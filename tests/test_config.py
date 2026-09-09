from config import Settings


def test_settings_read_environment(monkeypatch):
    monkeypatch.setenv("PCAP_DIR", "/srv/pcaps")
    monkeypatch.setenv("ANOMALY_THRESHOLD_PORT_SCAN", "7")

    s = Settings(_env_file=None)

    assert s.PCAP_DIR == "/srv/pcaps" and s.ANOMALY_THRESHOLD_PORT_SCAN == 7


def test_settings_defaults():
    s = Settings(_env_file=None)
    assert s.PCAP_DIR == "/app/pcap_captures" and s.SQUAD_GAME_PORT == 7787
