from datetime import datetime

import pytest
from aiohttp import web

from config import settings
from models import AnalysisResult, AnomalyDetection, AnomalyType, TrafficStats
from notifications import NotificationService


def result(risk, attack, anomalies=1):
    return AnalysisResult(
        analysis_id="abc",
        timestamp=datetime(2026, 1, 1),
        duration_seconds=1.0,
        stats=TrafficStats(total_packets=10, unique_ips=2, packets_per_second=5),
        anomalies=[
            AnomalyDetection(
                type=AnomalyType.HIGH_PPS,
                severity=0.9,
                description=f"a{i}",
                timestamp=datetime(2026, 1, 1),
                source_ip="1.1.1.1",
            )
            for i in range(anomalies)
        ],
        risk_score=risk,
        is_under_attack=attack,
        recommendations=["r1", "r2", "r3", "r4"],
    )


def test_message_contains_summary_top_anomalies_and_top_recommendations():
    msg = NotificationService()._build_message(result(0.95, True, anomalies=7))

    assert msg.startswith("🚨 АТАКА")
    assert "Risk Score: 0.95" in msg
    assert msg.count("• [0.90]") == 5
    assert "→ r3" in msg and "→ r4" not in msg


async def test_low_risk_result_sends_nothing(monkeypatch):
    calls = []
    service = NotificationService()
    monkeypatch.setattr(settings, "WEBHOOK_ENABLED", True)
    monkeypatch.setattr(settings, "WEBHOOK_URL", "http://127.0.0.1:1/hook")

    async def fake(*a, **k):
        calls.append(1)

    monkeypatch.setattr(service, "_send_webhook", fake)

    await service.send_alert(result(0.2, False))
    assert calls == []

    await service.send_alert(result(0.6, False))
    assert calls == [1]


async def test_webhook_posts_structured_payload(monkeypatch, aiohttp_unused_port=None):
    received = {}

    async def hook(request):
        received.update(await request.json())
        return web.Response(status=204)

    app = web.Application()
    app.router.add_post("/hook", hook)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        monkeypatch.setattr(settings, "WEBHOOK_ENABLED", True)
        monkeypatch.setattr(settings, "WEBHOOK_URL", f"http://127.0.0.1:{port}/hook")
        await NotificationService().send_alert(result(0.8, True))
    finally:
        await runner.cleanup()

    assert received["event"] == "anomaly_detected"
    assert received["analysis_id"] == "abc" and received["is_under_attack"] is True
    assert received["anomalies"] == [{"type": "high_pps", "severity": 0.9, "source_ip": "1.1.1.1"}]


async def test_failing_channel_does_not_break_others(monkeypatch):
    service = NotificationService()
    monkeypatch.setattr(settings, "WEBHOOK_ENABLED", True)
    monkeypatch.setattr(settings, "WEBHOOK_URL", "http://127.0.0.1:1/hook")
    monkeypatch.setattr(settings, "TELEGRAM_ENABLED", True)
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "t")
    sent = []

    async def ok(*a, **k):
        sent.append("email")

    async def boom(*a, **k):
        raise RuntimeError("telegram down")

    monkeypatch.setattr(service, "_send_telegram", boom)
    monkeypatch.setattr(service, "_send_webhook", ok)

    await service.send_alert(result(0.9, True))
    assert sent == ["email"]


@pytest.mark.parametrize("attack,risk,expected", [(True, 0.1, True), (False, 0.5, True), (False, 0.49, False)])
async def test_alert_gating(monkeypatch, attack, risk, expected):
    service = NotificationService()
    monkeypatch.setattr(settings, "WEBHOOK_ENABLED", True)
    monkeypatch.setattr(settings, "WEBHOOK_URL", "http://127.0.0.1:1/hook")
    calls = []

    async def fake(*a, **k):
        calls.append(1)

    monkeypatch.setattr(service, "_send_webhook", fake)
    await service.send_alert(result(risk, attack))
    assert bool(calls) is expected
