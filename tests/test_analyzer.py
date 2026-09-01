"""Regression tests for two TrafficAnalyzer bugs found by manually smoke-testing
POST /analyze/upload:

1. Every analysis returned 200 but silently failed to persist. AnomalyDetection.timestamp
   is a datetime, and `.model_dump()` (without mode="json") left it as a raw datetime
   object, which SQLAlchemy's JSON column can't serialize
   (TypeError: Object of type datetime is not JSON serializable).
2. A distributed-DDoS anomaly (source_ip=None by design — there's no single source) produced
   the literal recommendation string "Заблокировать IP None в firewall".
"""
from datetime import datetime

from analyzer import TrafficAnalyzer
from database import AnalysisRecord, SessionLocal, init_db
from models import AnalysisResult, AnomalyDetection, AnomalyType, TrafficStats


def _make_result(analysis_id, anomalies):
    return AnalysisResult(
        analysis_id=analysis_id,
        timestamp=datetime.now(),
        duration_seconds=0.01,
        stats=TrafficStats(total_packets=10, total_bytes=1000, unique_ips=5),
        anomalies=anomalies,
        risk_score=0.5,
        is_under_attack=False,
        recommendations=[],
    )


def test_save_to_database_persists_anomaly_with_datetime_timestamp():
    init_db()
    analyzer = TrafficAnalyzer()

    anomaly = AnomalyDetection(
        type=AnomalyType.DDOS_ATTACK,
        severity=0.8,
        description="test anomaly",
        timestamp=datetime.now(),
        source_ip="1.2.3.4",
    )
    result = _make_result("test-persists-datetime", [anomaly])

    analyzer._save_to_database(result)

    db = SessionLocal()
    try:
        record = db.query(AnalysisRecord).filter_by(analysis_id="test-persists-datetime").first()
        assert record is not None
        assert record.anomalies_json[0]["source_ip"] == "1.2.3.4"
        assert record.anomalies_json[0]["timestamp"]
    finally:
        db.close()


def test_generate_recommendations_omits_none_source_ip():
    analyzer = TrafficAnalyzer()

    distributed = AnomalyDetection(
        type=AnomalyType.DDOS_ATTACK,
        severity=0.3,
        description="distributed attack, no single source",
        timestamp=datetime.now(),
        source_ip=None,
    )
    stats = TrafficStats(total_packets=10, unique_ips=5)

    recommendations = analyzer._generate_recommendations([distributed], stats, is_under_attack=False)

    assert not any("None" in r for r in recommendations)


def test_generate_recommendations_includes_source_ip_when_present():
    analyzer = TrafficAnalyzer()

    single_source = AnomalyDetection(
        type=AnomalyType.DDOS_ATTACK,
        severity=0.9,
        description="single source ddos",
        timestamp=datetime.now(),
        source_ip="9.9.9.9",
    )
    stats = TrafficStats(total_packets=10, unique_ips=5)

    recommendations = analyzer._generate_recommendations([single_source], stats, is_under_attack=False)

    assert any("9.9.9.9" in r for r in recommendations)
