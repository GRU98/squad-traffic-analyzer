from datetime import datetime

import pytest

from anomaly_detector import AnomalyDetector
from config import settings
from models import AnomalyType, PacketInfo, TrafficStats


def pkt(src, dst="10.0.0.1", sport=50000, dport=7787, protocol="UDP", length=120, t=0.0, flags=None):
    return PacketInfo(
        timestamp=t,
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        protocol=protocol,
        length=length,
        flags=flags,
    )


def normal_traffic(clients=10, seconds=10, pps=30):
    packets = []
    for c in range(clients):
        ip = f"192.168.1.{c + 10}"
        for i in range(seconds * pps):
            t = i / pps
            packets.append(pkt(ip, sport=40000 + c, length=100, t=t))
            packets.append(pkt("10.0.0.1", dst=ip, sport=7787, dport=40000 + c, length=300, t=t + 0.001))
    packets.sort(key=lambda p: p.timestamp)
    return packets


def types(anomalies):
    return {a.type for a in anomalies}


def test_normal_traffic_produces_no_anomalies():
    packets = normal_traffic()
    stats = TrafficStats(total_packets=len(packets), unique_ips=11, packets_per_second=600)

    anomalies = AnomalyDetector().detect_anomalies(packets, stats, server_ip="10.0.0.1")

    assert anomalies == []


def test_server_replies_are_not_reported_as_port_scan_or_ddos():
    """Сервер отвечает 30 клиентам на 30 разных портов и шлёт больше всех — это не атака."""
    packets = normal_traffic(clients=30, seconds=2, pps=20)
    stats = TrafficStats(total_packets=len(packets), unique_ips=31, packets_per_second=1200)

    with_server = AnomalyDetector().detect_anomalies(packets, stats, server_ip="10.0.0.1")
    without_server = AnomalyDetector().detect_anomalies(packets, stats)

    assert with_server == []
    assert {a.source_ip for a in without_server} == {"10.0.0.1"}


def test_empty_capture_produces_no_anomalies():
    assert AnomalyDetector().detect_anomalies([], TrafficStats()) == []


def test_high_pps_and_bps_use_configured_thresholds():
    stats = TrafficStats(
        packets_per_second=settings.ANOMALY_THRESHOLD_PPS * 2, bytes_per_second=settings.ANOMALY_THRESHOLD_BPS + 1
    )

    anomalies = AnomalyDetector().detect_anomalies([], stats)

    by_type = {a.type: a for a in anomalies}
    assert by_type[AnomalyType.HIGH_PPS].severity == pytest.approx(1.0)
    assert by_type[AnomalyType.HIGH_BPS].severity == pytest.approx(0.5, abs=1e-6)
    assert anomalies[0].severity >= anomalies[-1].severity


def test_port_scan_threshold_comes_from_settings(monkeypatch):
    monkeypatch.setattr(settings, "ANOMALY_THRESHOLD_PORT_SCAN", 5)
    packets = [pkt("6.6.6.6", dport=1000 + i, protocol="TCP", flags="S") for i in range(6)]

    anomalies = AnomalyDetector().detect_anomalies(packets, TrafficStats())

    scan = [a for a in anomalies if a.type == AnomalyType.PORT_SCAN]
    assert len(scan) == 1 and scan[0].source_ip == "6.6.6.6" and scan[0].details["ports_count"] == 6

    monkeypatch.setattr(settings, "ANOMALY_THRESHOLD_PORT_SCAN", 50)
    assert AnomalyType.PORT_SCAN not in types(AnomalyDetector().detect_anomalies(packets, TrafficStats()))


def test_syn_flood_detected_only_for_syn_without_ack():
    syn = [pkt("7.7.7.7", protocol="TCP", flags="S", t=i * 0.001) for i in range(150)]
    syn_ack = [pkt("8.8.8.8", protocol="TCP", flags="SA", t=i * 0.001) for i in range(150)]

    anomalies = AnomalyDetector().detect_anomalies(syn + syn_ack, TrafficStats())

    flood = [a for a in anomalies if a.type == AnomalyType.SUSPICIOUS_PATTERN and "SYN" in a.description]
    assert [a.source_ip for a in flood] == ["7.7.7.7"]


def test_single_source_ddos_detected():
    attacker = [pkt("9.9.9.9", length=60, t=i * 0.0001) for i in range(2000)]
    others = [pkt(f"192.168.1.{i % 50}", t=i * 0.001) for i in range(500)]

    anomalies = AnomalyDetector().detect_anomalies(
        attacker + others, TrafficStats(unique_ips=51, packets_per_second=100)
    )

    ddos = [a for a in anomalies if a.type == AnomalyType.DDOS_ATTACK]
    assert ddos and ddos[0].source_ip == "9.9.9.9" and ddos[0].severity == 1.0


def test_distributed_ddos_requires_many_ips_and_high_pps(monkeypatch):
    monkeypatch.setattr(settings, "ANOMALY_THRESHOLD_CONNECTIONS", 100)
    stats = TrafficStats(unique_ips=500, packets_per_second=5000)

    anomalies = AnomalyDetector().detect_anomalies([], stats)

    assert AnomalyType.DDOS_ATTACK in types(anomalies)
    assert AnomalyType.DDOS_ATTACK not in types(
        AnomalyDetector().detect_anomalies([], TrafficStats(unique_ips=500, packets_per_second=10))
    )


def test_malformed_packets_on_game_port():
    packets = [pkt("5.5.5.5", length=10, dport=settings.SQUAD_GAME_PORT) for _ in range(60)]

    anomalies = AnomalyDetector().detect_anomalies(packets, TrafficStats())

    malformed = [a for a in anomalies if a.type == AnomalyType.MALFORMED_PACKET]
    assert len(malformed) == 1 and malformed[0].source_ip == "5.5.5.5" and malformed[0].details["malformed_count"] == 60


def test_malformed_ignores_other_ports():
    packets = [pkt("5.5.5.5", length=10, dport=9999) for _ in range(60)]
    assert AnomalyType.MALFORMED_PACKET not in types(AnomalyDetector().detect_anomalies(packets, TrafficStats()))


def test_ml_burst_window_is_attributed_to_the_bursting_source():
    """Пакеты из аномального окна должны атрибутироваться по времени, а не по индексу окна."""
    packets = normal_traffic(clients=5, seconds=30, pps=10)
    burst_start = 20.0
    burst = [pkt("66.66.66.66", length=1400, t=burst_start + i * 0.0005) for i in range(1500)]
    packets = sorted(packets + burst, key=lambda p: p.timestamp)

    anomalies = AnomalyDetector()._detect_ml_anomalies(packets)

    assert len(anomalies) == 1
    ml = anomalies[0]
    assert ml.type == AnomalyType.ML_DETECTED
    assert ml.source_ip == "66.66.66.66"
    assert ml.details["anomaly_count"] >= 1500
    assert ml.details["windows"] == [20]


def test_ml_skips_small_captures_and_respects_ml_enabled(monkeypatch):
    detector = AnomalyDetector()
    assert detector._detect_ml_anomalies([pkt("1.1.1.1") for _ in range(50)]) == []

    monkeypatch.setattr(settings, "ML_ENABLED", False)
    packets = normal_traffic(clients=5, seconds=30, pps=10) + [
        pkt("66.66.66.66", length=1400, t=20 + i * 0.0005) for i in range(1500)
    ]
    assert detector._detect_ml_anomalies(sorted(packets, key=lambda p: p.timestamp)) == []


def test_anomalies_carry_timestamps():
    stats = TrafficStats(packets_per_second=settings.ANOMALY_THRESHOLD_PPS + 1)
    anomaly = AnomalyDetector().detect_anomalies([], stats)[0]
    assert isinstance(anomaly.timestamp, datetime)


def query_stats(requests, seconds, sources, request_bytes=None, response_bytes=None):
    return TrafficStats(
        total_packets=requests,
        packets_per_second=requests / seconds if seconds else 0,
        query_requests=requests,
        query_request_sources=sources,
        query_request_bytes=request_bytes if request_bytes is not None else requests * 67,
        query_responses=requests,
        query_response_bytes=response_bytes if response_bytes is not None else requests * 350,
    )


def test_query_flood_detected_from_request_rate(monkeypatch):
    monkeypatch.setattr(settings, "ANOMALY_THRESHOLD_QUERY_PPS", 100)
    stats = query_stats(requests=30000, seconds=60, sources=25000)

    anomalies = AnomalyDetector().detect_anomalies([], stats, server_ip="10.0.0.1")

    flood = [a for a in anomalies if a.type == AnomalyType.QUERY_FLOOD]
    assert len(flood) == 1
    assert flood[0].severity == 1.0
    assert flood[0].details["requests_per_second"] == pytest.approx(500)
    assert flood[0].details["unique_sources"] == 25000
    assert flood[0].details["amplification_ratio"] == pytest.approx(350 / 67, rel=1e-3)


def test_query_flood_severity_scales_with_rate(monkeypatch):
    monkeypatch.setattr(settings, "ANOMALY_THRESHOLD_QUERY_PPS", 100)
    stats = query_stats(requests=12000, seconds=60, sources=10)  # 200 req/s = 2x threshold

    flood = [a for a in AnomalyDetector().detect_anomalies([], stats) if a.type == AnomalyType.QUERY_FLOOD]

    assert len(flood) == 1 and flood[0].severity == pytest.approx(0.4)


def test_normal_query_rate_is_not_a_flood(monkeypatch):
    monkeypatch.setattr(settings, "ANOMALY_THRESHOLD_QUERY_PPS", 100)
    stats = query_stats(requests=300, seconds=60, sources=40)  # 5 req/s: браузер серверов + Steam master

    assert AnomalyType.QUERY_FLOOD not in types(AnomalyDetector().detect_anomalies([], stats))


def test_query_flood_needs_a_measurable_rate():
    stats = query_stats(requests=5000, seconds=0, sources=5000)  # один timestamp → PPS = 0
    assert AnomalyType.QUERY_FLOOD not in types(AnomalyDetector().detect_anomalies([], stats))


async def test_concurrent_ml_detection_is_safe():
    """Один AnomalyDetector, параллельные вызовы из потоков — как в TrafficAnalyzer под нагрузкой."""
    import asyncio

    detector = AnomalyDetector()
    packets = normal_traffic(clients=5, seconds=30, pps=10) + [
        pkt("66.66.66.66", length=1400, t=20 + i * 0.0005) for i in range(1500)
    ]
    packets.sort(key=lambda p: p.timestamp)

    results = await asyncio.gather(*(asyncio.to_thread(detector._detect_ml_anomalies, packets) for _ in range(8)))

    assert all(len(r) == 1 and r[0].source_ip == "66.66.66.66" for r in results)


def test_malformed_detection_honours_custom_ports():
    packets = [pkt("5.5.5.5", length=10, dport=9787) for _ in range(60)]

    default_ports = AnomalyDetector().detect_anomalies(packets, TrafficStats())
    custom_ports = AnomalyDetector().detect_anomalies(packets, TrafficStats(), game_port=9787, query_port=29165)

    assert AnomalyType.MALFORMED_PACKET not in types(default_ports)
    assert AnomalyType.MALFORMED_PACKET in types(custom_ports)


def test_query_flood_description_uses_analysis_port(monkeypatch):
    monkeypatch.setattr(settings, "ANOMALY_THRESHOLD_QUERY_PPS", 100)
    stats = query_stats(requests=30000, seconds=60, sources=25000)

    flood = [
        a for a in AnomalyDetector().detect_anomalies([], stats, query_port=29165) if a.type == AnomalyType.QUERY_FLOOD
    ]

    assert "29165" in flood[0].description


def test_ml_ignores_server_reply_burst_when_server_ip_known():
    """Всплеск исходящих ответов сервера не должен становиться ML-аномалией с source_ip сервера."""
    packets = normal_traffic(clients=5, seconds=30, pps=10)
    packets += [
        pkt("10.0.0.1", dst=f"192.168.9.{i % 200}", sport=7787, dport=40000 + i, length=1400, t=20 + i * 0.0005)
        for i in range(1500)
    ]
    packets.sort(key=lambda p: p.timestamp)
    stats = TrafficStats(total_packets=len(packets), unique_ips=206, packets_per_second=len(packets) / 30)

    with_server = AnomalyDetector().detect_anomalies(packets, stats, server_ip="10.0.0.1")
    without_server = AnomalyDetector().detect_anomalies(packets, stats)

    assert AnomalyType.ML_DETECTED not in types(with_server)
    ml = [a for a in without_server if a.type == AnomalyType.ML_DETECTED]
    assert ml and ml[0].source_ip == "10.0.0.1"
