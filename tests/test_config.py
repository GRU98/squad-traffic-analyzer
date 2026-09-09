from config import Settings


def test_settings_read_environment(monkeypatch):
    monkeypatch.setenv("PCAP_DIR", "/srv/pcaps")
    monkeypatch.setenv("ANOMALY_THRESHOLD_PORT_SCAN", "7")

    s = Settings(_env_file=None)

    assert s.PCAP_DIR == "/srv/pcaps" and s.ANOMALY_THRESHOLD_PORT_SCAN == 7


def test_settings_defaults():
    s = Settings(_env_file=None)
    assert s.PCAP_DIR == "/app/pcap_captures" and s.SQUAD_GAME_PORT == 7787


def test_capture_filter_defaults_to_server_ports(monkeypatch):
    monkeypatch.delenv("CAPTURE_FILTER", raising=False)
    s = Settings(_env_file=None, SQUAD_GAME_PORT=7787, SQUAD_QUERY_PORT=27165)
    assert s.capture_filter() == "udp port 7787 or udp port 27165"


def test_capture_filter_override(monkeypatch):
    monkeypatch.setenv("CAPTURE_FILTER", "udp portrange 7787-7788 or udp portrange 27165-27166 or udp port 15000")
    assert (
        Settings(_env_file=None).capture_filter()
        == "udp portrange 7787-7788 or udp portrange 27165-27166 or udp port 15000"
    )
    assert Settings(_env_file=None, CAPTURE_FILTER="   ").capture_filter() == "udp port 7787 or udp port 27165"
