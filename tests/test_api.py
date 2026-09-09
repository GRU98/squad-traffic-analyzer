import os

import pytest
from fastapi.testclient import TestClient
from packets import game_session, udp

import main
from config import settings


@pytest.fixture
def client():
    with TestClient(main.app) as c:
        yield c


def test_root_and_health(client):
    assert client.get("/").json()["status"] == "running"
    health = client.get("/health").json()
    assert health["status"] == "healthy" and health["redis"] == "unavailable"


def test_docs_hidden_only_in_production(client):
    assert client.get("/docs").status_code == 200


def test_upload_rejects_non_pcap(client):
    resp = client.post("/analyze/upload", files={"file": ("notes.txt", b"hello")})
    assert resp.status_code == 400


def test_upload_analyzes_pcap_and_cleans_temp_file(client, pcap_builder, monkeypatch):
    created = []
    real_tempfile = main.tempfile.NamedTemporaryFile

    def tracking(*args, **kwargs):
        tmp = real_tempfile(*args, **kwargs)
        created.append(tmp.name)
        return tmp

    monkeypatch.setattr(main.tempfile, "NamedTemporaryFile", tracking)
    path = pcap_builder(game_session(clients=2, seconds=2, pps_per_client=5))

    with open(path, "rb") as fh:
        resp = client.post(
            "/analyze/upload?server_ip=10.0.0.1", files={"file": ("capture.pcap", fh, "application/octet-stream")}
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stats"]["total_packets"] == 40 and body["risk_score"] == 0.0
    assert created and not any(os.path.exists(p) for p in created)

    detail = client.get(f"/analysis/{body['analysis_id']}")
    assert detail.status_code == 200 and detail.json()["stats"]["total_packets"] == 40


def test_upload_corrupt_pcap_returns_500_and_cleans_temp(client, monkeypatch):
    created = []
    real_tempfile = main.tempfile.NamedTemporaryFile

    def tracking(*args, **kwargs):
        tmp = real_tempfile(*args, **kwargs)
        created.append(tmp.name)
        return tmp

    monkeypatch.setattr(main.tempfile, "NamedTemporaryFile", tracking)

    resp = client.post("/analyze/upload", files={"file": ("bad.pcap", b"garbage")})

    assert resp.status_code == 500
    assert created and not any(os.path.exists(p) for p in created)


def test_analyze_path_only_inside_pcap_dir(client, pcap_builder, tmp_path, monkeypatch):
    pcap_dir = tmp_path / "captures"
    pcap_dir.mkdir()
    monkeypatch.setattr(settings, "PCAP_DIR", str(pcap_dir))
    inside = pcap_builder([udp("1.1.1.1")], name="captures/ok.pcap")
    outside = pcap_builder([udp("1.1.1.1")], name="outside.pcap")

    assert client.post("/analyze/path", params={"pcap_path": inside}).status_code == 200
    assert client.post("/analyze/path", params={"pcap_path": outside}).status_code == 403
    assert client.post("/analyze/path", params={"pcap_path": str(pcap_dir / "../outside.pcap")}).status_code == 403
    assert client.post("/analyze/path", params={"pcap_path": str(pcap_dir / "missing.pcap")}).status_code == 404


def test_analyze_latest_picks_newest_capture(client, pcap_builder, tmp_path, monkeypatch):
    pcap_dir = tmp_path / "captures"
    pcap_dir.mkdir()
    monkeypatch.setattr(settings, "PCAP_DIR", str(pcap_dir))
    assert client.post("/capture/analyze-latest").status_code == 404

    old = pcap_builder([udp("1.1.1.1")], name="captures/old.pcap")
    new = pcap_builder([udp("1.1.1.1"), udp("2.2.2.2")], name="captures/new.pcap")
    os.utime(old, (1, 1))
    os.utime(new, (2, 2))

    resp = client.post("/capture/analyze-latest")
    assert resp.status_code == 200 and resp.json()["stats"]["total_packets"] == 2


def test_history_and_summary(client, pcap_builder):
    with open(pcap_builder([udp("1.1.1.1")]), "rb") as fh:
        client.post("/analyze/upload", files={"file": ("a.pcap", fh)})

    history = client.get("/history", params={"limit": 5}).json()
    assert len(history) == 1 and history[0]["total_packets"] == 1

    summary = client.get("/stats/summary").json()
    assert summary["total_analyses"] == 1 and summary["attacks_detected"] == 0

    assert client.get("/history", params={"limit": 0}).status_code == 422
    assert client.get("/history", params={"limit": 5000}).status_code == 422
    assert client.get("/analysis/does-not-exist").status_code == 404


def test_realtime_stats_without_redis(client):
    assert client.get("/stats/realtime").json() == {"recent_stats": [], "recent_anomalies": []}


def test_mode_reports_settings(client):
    assert client.get("/mode").json()["analysis_mode"] == settings.ANALYSIS_MODE


def test_cleanup_removes_old_pcaps(client, pcap_builder, tmp_path, monkeypatch):
    pcap_dir = tmp_path / "captures"
    pcap_dir.mkdir()
    monkeypatch.setattr(settings, "PCAP_DIR", str(pcap_dir))
    monkeypatch.setattr(settings, "PCAP_RETENTION_DAYS", 1)
    old = pcap_builder([udp("1.1.1.1")], name="captures/old.pcap")
    fresh = pcap_builder([udp("1.1.1.1")], name="captures/fresh.pcap")
    os.utime(old, (1, 1))

    resp = client.delete("/cleanup")

    assert resp.status_code == 200 and resp.json()["deleted_pcaps"] == 1
    assert not os.path.exists(old) and os.path.exists(fresh)


def test_capture_start_validates_input(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PCAP_DIR", str(tmp_path / "captures"))
    assert client.post("/capture/start", params={"duration": 0}).status_code == 422
    assert client.post("/capture/start", params={"interface": "eth0; rm -rf /"}).status_code == 422


def test_capture_start_launches_tcpdump(client, tmp_path, monkeypatch):
    pcap_dir = tmp_path / "captures"
    monkeypatch.setattr(settings, "PCAP_DIR", str(pcap_dir))
    launched = {}

    class FakeProc:
        pid = 4242
        returncode = None

        async def wait(self):
            return 0

    async def fake_exec(*cmd, **kwargs):
        launched["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(main.asyncio, "create_subprocess_exec", fake_exec)

    resp = client.post("/capture/start", params={"duration": 5, "interface": "en0"})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["pid"] == 4242 and body["pcap_file"].startswith(str(pcap_dir))
    assert launched["cmd"][0] == "tcpdump" and "en0" in launched["cmd"] and "5" in launched["cmd"]
    assert launched["cmd"][-1] == f"udp port {settings.SQUAD_GAME_PORT} or udp port {settings.SQUAD_QUERY_PORT}"
    assert pcap_dir.is_dir()

    monkeypatch.setattr(settings, "CAPTURE_FILTER", "udp portrange 7787-7788")
    assert client.post("/capture/start", params={"duration": 5}).status_code == 200
    assert launched["cmd"][-1] == "udp portrange 7787-7788"


class TestApiKey:
    @pytest.fixture(autouse=True)
    def _enable(self, monkeypatch):
        monkeypatch.setattr(settings, "API_KEY_ENABLED", True)
        monkeypatch.setattr(settings, "API_KEY", "s3cret")

    def test_missing_or_wrong_key_is_rejected(self, client):
        assert client.get("/mode").status_code == 403
        assert client.get("/mode", headers={"X-API-Key": "nope"}).status_code == 403

    def test_correct_key_is_accepted(self, client):
        assert client.get("/mode", headers={"X-API-Key": "s3cret"}).status_code == 200
        assert client.get("/mode", params={"api_key": "s3cret"}).status_code == 200

    def test_health_stays_open(self, client):
        assert client.get("/health").status_code == 200

    def test_unset_key_denies_everything(self, client, monkeypatch):
        monkeypatch.setattr(settings, "API_KEY", None)
        assert client.get("/mode").status_code == 503
        monkeypatch.setattr(settings, "API_KEY", "")
        assert client.get("/mode", headers={"X-API-Key": ""}).status_code == 503


def test_upload_with_custom_ports_drives_counters_and_malformed_detection(client, pcap_builder):
    from packets import A2S_INFO_REQUEST

    packets = []
    for i in range(80):
        packets.append(udp(f"7.7.7.{i % 50}", dport=9787, size=1500, t=i * 0.01))  # >1500 байт на кастомном game-порту
    packets.append(udp("8.8.8.8", dport=29165, payload=A2S_INFO_REQUEST, t=0.5))
    packets.append(udp("10.0.0.1", dst="8.8.8.8", sport=29165, dport=50000, size=300, t=0.6))
    packets.extend(game_session(clients=2, seconds=1, pps_per_client=5))
    packets.sort(key=lambda p: p.time)

    with open(pcap_builder(packets), "rb") as fh:
        resp = client.post(
            "/analyze/upload",
            params={"server_ip": "10.0.0.1", "game_port": 9787, "query_port": 29165},
            files={"file": ("custom.pcap", fh)},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stats"]["game_port_packets"] == 80
    assert body["stats"]["query_port_packets"] == 2
    assert body["stats"]["query_requests"] == 1 and body["stats"]["query_responses"] == 1
    malformed = [a for a in body["anomalies"] if a["type"] == "malformed_packet"]
    assert len(malformed) == 1 and malformed[0]["details"]["malformed_count"] == 80
