"""Pydantic-модели: пакеты, статистика трафика, аномалии и результат анализа."""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class AnomalyType(str, Enum):
    """Категории аномалий, которые умеет распознавать AnomalyDetector."""

    HIGH_PPS = "high_pps"
    HIGH_BPS = "high_bps"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    PORT_SCAN = "port_scan"
    MALFORMED_PACKET = "malformed_packet"
    UNUSUAL_PROTOCOL = "unusual_protocol"
    DDOS_ATTACK = "ddos_attack"
    ML_DETECTED = "ml_detected"


class AnomalyDetection(BaseModel):
    """Одна обнаруженная аномалия с её степенью серьёзности и источником."""

    type: AnomalyType
    severity: float = Field(..., ge=0.0, le=1.0)
    description: str
    timestamp: datetime
    source_ip: Optional[str] = None
    details: Dict = Field(default_factory=dict)


class TrafficStats(BaseModel):
    """Агрегированная статистика по одному разобранному PCAP-файлу."""

    total_packets: int = 0
    total_bytes: int = 0
    unique_ips: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    
    udp_packets: int = 0
    tcp_packets: int = 0
    icmp_packets: int = 0
    other_packets: int = 0
    
    game_port_packets: int = 0
    query_port_packets: int = 0
    
    top_talkers: List[Dict[str, Any]] = Field(default_factory=list)
    protocol_distribution: Dict[str, int] = Field(default_factory=dict)
    packet_size_distribution: Dict[str, int] = Field(default_factory=dict)


class AnalysisResult(BaseModel):
    """Итог одного запуска TrafficAnalyzer.analyze_pcap — ответ API."""

    analysis_id: str
    timestamp: datetime
    duration_seconds: float
    
    stats: TrafficStats
    anomalies: List[AnomalyDetection]
    
    risk_score: float = Field(..., ge=0.0, le=1.0)
    is_under_attack: bool = False
    
    recommendations: List[str] = Field(default_factory=list)


class PacketInfo(BaseModel):
    """Нормализованные поля одного пакета, извлечённые PcapParser."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    length: int
    flags: Optional[str] = None
