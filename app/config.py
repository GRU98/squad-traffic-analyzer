"""Конфигурация приложения. Значения читаются из переменных окружения и файла .env."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Настройки приложения, сгруппированные по назначению (см. .env.example)."""

    # Application
    APP_NAME: str = "Squad Traffic Analyzer"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 1
    RELOAD: bool = False

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str | None = None
    REDIS_MAX_CONNECTIONS: int = 50

    # Database
    DATABASE_URL: str = "sqlite:///./data/traffic_analyzer.db"

    # Squad Server
    SQUAD_GAME_PORT: int = 7787
    SQUAD_QUERY_PORT: int = 27165
    SQUAD_SERVER_IP: str | None = None

    # Anomaly Detection
    ANOMALY_THRESHOLD_PPS: int = 10000
    ANOMALY_THRESHOLD_BPS: int = 100_000_000
    ANOMALY_THRESHOLD_CONNECTIONS: int = 100
    ANOMALY_THRESHOLD_PORT_SCAN: int = 20
    # Входящих A2S-запросов в секунду на query-порт, выше которых считаем query flood.
    ANOMALY_THRESHOLD_QUERY_PPS: int = 100

    # ML Model
    ML_MODEL_CONTAMINATION: float = 0.1
    ML_ENABLED: bool = True

    # Data Retention
    STATS_RETENTION_HOURS: int = 168
    PCAP_RETENTION_DAYS: int = 7
    DB_CLEANUP_ENABLED: bool = True

    # Единственная директория, из которой API читает и в которую пишет PCAP-файлы.
    # /analyze/path принимает только пути внутри неё (защита от чтения произвольных файлов).
    PCAP_DIR: str = "/app/pcap_captures"

    # Security
    API_KEY_ENABLED: bool = False
    API_KEY: str | None = None
    CORS_ORIGINS: str = "*"
    RATE_LIMIT_ENABLED: bool = False
    RATE_LIMIT_PER_MINUTE: int = 60

    # Monitoring
    SENTRY_DSN: str | None = None
    PROMETHEUS_ENABLED: bool = False
    METRICS_PORT: int = 9090

    # Analysis Modes
    ANALYSIS_MODE: str = "manual"  # continuous, scheduled, manual
    CONTINUOUS_INTERVAL_SECONDS: int = 300
    SCHEDULED_CRON: str = "0 */6 * * *"

    # Capture Settings
    AUTO_CAPTURE_ENABLED: bool = False
    CAPTURE_DURATION_SECONDS: int = 60
    CAPTURE_INTERFACE: str = "eth0"

    # Notifications
    TELEGRAM_ENABLED: bool = False
    TELEGRAM_BOT_TOKEN: str | None = None
    TELEGRAM_CHAT_ID: str | None = None

    EMAIL_ENABLED: bool = False
    EMAIL_SMTP_HOST: str = "smtp.gmail.com"
    EMAIL_SMTP_PORT: int = 587
    EMAIL_FROM: str | None = None
    EMAIL_TO: str | None = None
    EMAIL_PASSWORD: str | None = None

    WEBHOOK_ENABLED: bool = False
    WEBHOOK_URL: str | None = None

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")


settings = Settings()
