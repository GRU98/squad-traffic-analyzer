"""Общие фикстуры: изолированная SQLite-БД, недоступный Redis и генератор синтетических PCAP."""

import os
import sys
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parents[1] / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

# Настройки читаются один раз при импорте config, поэтому окружение задаётся до любых импортов app/.
_TEST_DB = Path(os.environ.get("PYTEST_TMP_DB", "/tmp/squad_traffic_analyzer_test.db"))
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TEST_DB}")
os.environ.setdefault("REDIS_HOST", "127.0.0.1")
os.environ.setdefault("REDIS_PORT", "1")  # порт 1 закрыт — соединение отклоняется мгновенно
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("API_KEY_ENABLED", "false")
os.environ.setdefault("TELEGRAM_ENABLED", "false")
os.environ.setdefault("EMAIL_ENABLED", "false")
os.environ.setdefault("WEBHOOK_ENABLED", "false")
os.environ.setdefault("AUTO_CAPTURE_ENABLED", "false")


@pytest.fixture(autouse=True)
def _fresh_database():
    """Каждый тест начинает с пустой таблицы analyses."""
    from database import Base, engine

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def pcap_builder(tmp_path):
    """Фабрика PCAP-файлов из описания пакетов Scapy."""
    from scapy.all import wrpcap

    def build(packets, name="capture.pcap"):
        path = tmp_path / name
        wrpcap(str(path), packets)
        return str(path)

    return build
