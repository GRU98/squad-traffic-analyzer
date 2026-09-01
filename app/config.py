"""Конфигурация приложения. Значения читаются из переменных окружения и файла .env."""

from pydantic_settings import BaseSettings
from typing import Optional


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
    REDIS_PASSWORD: Optional[str] = None
    REDIS_MAX_CONNECTIONS: int = 50
    
    # Database
    DATABASE_URL: str = "sqlite:///./data/traffic_analyzer.db"
    
    # Squad Server
    SQUAD_GAME_PORT: int = 7787
    SQUAD_QUERY_PORT: int = 27165
    SQUAD_SERVER_IP: Optional[str] = None
    
    # Anomaly Detection
    ANOMALY_THRESHOLD_PPS: int = 10000
    ANOMALY_THRESHOLD_BPS: int = 100_000_000
    ANOMALY_THRESHOLD_CONNECTIONS: int = 100
    ANOMALY_THRESHOLD_PORT_SCAN: int = 20
    
    # ML Model
    ML_MODEL_CONTAMINATION: float = 0.1
    ML_ENABLED: bool = True
    
    # Data Retention
    STATS_RETENTION_HOURS: int = 168
    PCAP_RETENTION_DAYS: int = 7
    DB_CLEANUP_ENABLED: bool = True
    
    # Security
    API_KEY_ENABLED: bool = False
    API_KEY: Optional[str] = None
    CORS_ORIGINS: str = "*"
    RATE_LIMIT_ENABLED: bool = False
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # Monitoring
    SENTRY_DSN: Optional[str] = None
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
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None
    
    EMAIL_ENABLED: bool = False
    EMAIL_SMTP_HOST: str = "smtp.gmail.com"
    EMAIL_SMTP_PORT: int = 587
    EMAIL_FROM: Optional[str] = None
    EMAIL_TO: Optional[str] = None
    EMAIL_PASSWORD: Optional[str] = None
    
    WEBHOOK_ENABLED: bool = False
    WEBHOOK_URL: Optional[str] = None
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"  # .env also carries docker-compose-only vars (e.g. DB_PASSWORD)


settings = Settings()
