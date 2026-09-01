"""SQLAlchemy ORM-модели и сессия для персистентного хранения истории анализов."""

import os

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from config import settings

Base = declarative_base()


class AnalysisRecord(Base):
    """Одна запись истории: результат TrafficAnalyzer.analyze_pcap, сохранённый в БД."""

    __tablename__ = "analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String, unique=True, index=True)
    timestamp = Column(DateTime, default=datetime.now)
    duration_seconds = Column(Float)
    
    total_packets = Column(Integer)
    total_bytes = Column(Integer)
    unique_ips = Column(Integer)
    packets_per_second = Column(Float)
    bytes_per_second = Column(Float)
    
    anomaly_count = Column(Integer)
    risk_score = Column(Float)
    is_under_attack = Column(Boolean, default=False)
    
    stats_json = Column(JSON)
    anomalies_json = Column(JSON)
    recommendations_json = Column(JSON)


class BaselinePattern(Base):
    """Схема для хранения baseline-паттернов трафика. Таблица создаётся, но
    ничто в приложении пока не записывает и не читает из неё."""

    __tablename__ = "baseline_patterns"
    
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.now)
    
    avg_pps = Column(Float)
    avg_bps = Column(Float)
    avg_unique_ips = Column(Float)
    
    protocol_distribution = Column(JSON)
    packet_size_distribution = Column(JSON)
    
    is_active = Column(Boolean, default=True)


_connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

if settings.DATABASE_URL.startswith("sqlite:///"):
    _db_path = settings.DATABASE_URL.removeprefix("sqlite:///")
    _db_dir = os.path.dirname(_db_path)
    if _db_dir:
        os.makedirs(_db_dir, exist_ok=True)

engine = create_engine(settings.DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Создать таблицы, если они ещё не существуют. Вызывается при старте приложения."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI-зависимость: выдаёт сессию БД и закрывает её после запроса."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
