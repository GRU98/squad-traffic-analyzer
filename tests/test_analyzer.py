from datetime import datetime

import pytest
from packets import SERVER_IP, game_session, udp

from analyzer import TrafficAnalyzer
from config import settings
from database import AnalysisRecord, SessionLocal
from models import AnomalyDetection, AnomalyType, TrafficStats


def anomaly(type_, severity, ip=None, description=""):
    return AnomalyDetection(
        type=type_, severity=severity, description=description, timestamp=datetime.now(), source_ip=ip
    )


def test_risk_score_is_zero_without_anomalies():
    assert TrafficAnalyzer()._calculate_risk_score([], TrafficStats()) == 0.0


def test_risk_score_formula_and_cap():
    analyzer = TrafficAnalyzer()
    single = analyzer._calculate_risk_score([anomaly(AnomalyType.HIGH_PPS, 0.6)], TrafficStats())
    assert single == pytest.approx(0.6 * 0.5 + 0.6 * 0.3 + 0.1 * 0.2)

    many = [anomaly(AnomalyType.DDOS_ATTACK, 1.0) for _ in range(20)]
    assert analyzer._calculate_risk_score(many, TrafficStats()) == 1.0


def test_recommendations_are_deduplicated_and_ordered():
    analyzer = TrafficAnalyzer()
    anomalies = [
        anomaly(AnomalyType.DDOS_ATTACK, 0.9, ip="1.1.1.1"),
        anomaly(AnomalyType.DDOS_ATTACK, 0.8, ip="1.1.1.1"),
        anomaly(AnomalyType.PORT_SCAN, 0.5, ip="2.2.2.2"),
        anomaly(AnomalyType.SUSPICIOUS_PATTERN, 0.5, ip="3.3.3.3", description="Возможная SYN flood атака"),
    ]

    recs = analyzer._generate_recommendations(anomalies, TrafficStats(unique_ips=300), is_under_attack=True)

    assert recs[0].startswith("⚠️ КРИТИЧНО")
    assert len(recs) == len(set(recs))
    assert recs.index("Заблокировать IP 1.1.1.1 в firewall") < recs.index(
        "Добавить 2.2.2.2 в blacklist (сканирование портов)"
    )
    assert "Настроить SYN cookies на уровне ОС" in recs
    assert recs[-1] == "Большое количество уникальных IP - возможна распределенная атака"


def test_recommendations_for_clean_traffic():
    recs = TrafficAnalyzer()._generate_recommendations([], TrafficStats(), is_under_attack=False)
    assert recs == ["✅ Трафик в норме, подозрительной активности не обнаружено"]


async def test_analyze_clean_pcap_persists_record(pcap_builder):
    path = pcap_builder(game_session(clients=5, seconds=5, pps_per_client=10))

    result = await TrafficAnalyzer().analyze_pcap(path, server_ip=SERVER_IP)

    assert result.risk_score == 0.0 and not result.is_under_attack and result.anomalies == []
    assert result.stats.game_port_packets == result.stats.total_packets
    with SessionLocal() as db:
        record = db.query(AnalysisRecord).filter_by(analysis_id=result.analysis_id).one()
    assert record.total_packets == result.stats.total_packets
    assert record.recommendations_json == result.recommendations
    assert record.is_under_attack is False


async def test_analyze_flood_pcap_flags_attack(pcap_builder):
    flood = [udp("9.9.9.9", size=30, t=i * 0.00005) for i in range(3000)]
    path = pcap_builder(flood + game_session(clients=3, seconds=1, pps_per_client=5))

    result = await TrafficAnalyzer().analyze_pcap(path, server_ip=SERVER_IP)

    assert result.is_under_attack
    assert any(a.type == AnomalyType.DDOS_ATTACK and a.source_ip == "9.9.9.9" for a in result.anomalies)
    assert any("9.9.9.9" in r for r in result.recommendations)


async def test_database_failure_does_not_break_analysis(pcap_builder, monkeypatch):
    import analyzer as analyzer_module

    class BrokenSession:
        def __init__(self):
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.closed = True

        def add(self, record):
            raise RuntimeError("db down")

        def commit(self):
            pass

        def close(self):
            self.closed = True

    sessions = []

    def factory():
        session = BrokenSession()
        sessions.append(session)
        return session

    monkeypatch.setattr(analyzer_module, "SessionLocal", factory)

    result = await TrafficAnalyzer().analyze_pcap(pcap_builder([udp("1.1.1.1")]))

    assert result.stats.total_packets == 1
    assert sessions and all(s.closed for s in sessions)


async def test_unreadable_pcap_raises(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a pcap")
    with pytest.raises((OSError, ValueError, Exception)):  # noqa: B017 — Scapy бросает Scapy_Exception/FileNotFoundError
        await TrafficAnalyzer().analyze_pcap(str(bad))


async def test_analyze_query_flood_pcap_end_to_end(pcap_builder, monkeypatch):
    from packets import A2S_INFO_REQUEST, QUERY_PORT

    monkeypatch.setattr(settings, "ANOMALY_THRESHOLD_QUERY_PPS", 100)
    # 6000 spoofed A2S_INFO requests in 10s (600 req/s) from 6000 sources, each answered with ~350 bytes
    packets = []
    for i in range(6000):
        src = f"{(i >> 16) % 256 or 1}.{(i >> 8) % 256}.{i % 256}.7"
        t = i / 600
        packets.append(udp(src, dport=QUERY_PORT, payload=A2S_INFO_REQUEST, t=t))
        packets.append(udp(SERVER_IP, dst=src, sport=QUERY_PORT, dport=50000, size=350, t=t + 0.0005))
    packets.extend(game_session(clients=3, seconds=10, pps_per_client=5))
    packets.sort(key=lambda p: p.time)

    result = await TrafficAnalyzer().analyze_pcap(pcap_builder(packets), server_ip=SERVER_IP)

    flood = [a for a in result.anomalies if a.type == AnomalyType.QUERY_FLOOD]
    assert len(flood) == 1 and flood[0].severity == 1.0
    assert result.stats.query_requests == 6000 and result.stats.query_request_sources == 6000
    assert any("A2S" in r for r in result.recommendations)
