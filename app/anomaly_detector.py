"""Детекция аномалий в трафике: эвристические правила + Isolation Forest (ML)."""

from typing import List
from collections import defaultdict, Counter
from datetime import datetime
import numpy as np
from sklearn.ensemble import IsolationForest
import logging

from models import PacketInfo, AnomalyDetection, AnomalyType, TrafficStats
from config import settings

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Прогоняет пакеты и статистику через набор эвристик и ML-модель.

    ML-модель (IsolationForest) переобучается заново на каждый вызов
    detect_anomalies — baseline между анализами не сохраняется.
    """

    def __init__(self):
        self.ml_model = IsolationForest(
            contamination=settings.ML_MODEL_CONTAMINATION,
            random_state=42
        )
        self.baseline_trained = False

    def detect_anomalies(
        self,
        packets: List[PacketInfo],
        stats: TrafficStats
    ) -> List[AnomalyDetection]:
        """Запустить все детекторы и вернуть найденные аномалии по убыванию severity.

        Args:
            packets: пакеты одного PCAP-файла (из PcapParser.parse_pcap).
            stats: агрегированная статистика того же файла.

        Returns:
            Список AnomalyDetection, отсортированный по severity (убывание).
        """
        anomalies = []
        
        anomalies.extend(self._detect_high_traffic(stats))
        anomalies.extend(self._detect_port_scan(packets))
        anomalies.extend(self._detect_suspicious_patterns(packets))
        anomalies.extend(self._detect_ddos_patterns(packets, stats))
        anomalies.extend(self._detect_malformed_packets(packets))
        
        ml_anomalies = self._detect_ml_anomalies(packets)
        anomalies.extend(ml_anomalies)
        
        anomalies.sort(key=lambda x: x.severity, reverse=True)
        
        return anomalies
    
    def _detect_high_traffic(self, stats: TrafficStats) -> List[AnomalyDetection]:
        """Сравнить PPS/BPS с порогами из настроек (HIGH_PPS / HIGH_BPS)."""
        anomalies = []
        
        if stats.packets_per_second > settings.ANOMALY_THRESHOLD_PPS:
            severity = min(1.0, stats.packets_per_second / (settings.ANOMALY_THRESHOLD_PPS * 2))
            anomalies.append(AnomalyDetection(
                type=AnomalyType.HIGH_PPS,
                severity=severity,
                description=f"Высокий PPS: {stats.packets_per_second:.2f} пакетов/сек",
                timestamp=datetime.now(),
                details={"pps": stats.packets_per_second, "threshold": settings.ANOMALY_THRESHOLD_PPS}
            ))
        
        if stats.bytes_per_second > settings.ANOMALY_THRESHOLD_BPS:
            severity = min(1.0, stats.bytes_per_second / (settings.ANOMALY_THRESHOLD_BPS * 2))
            anomalies.append(AnomalyDetection(
                type=AnomalyType.HIGH_BPS,
                severity=severity,
                description=f"Высокий BPS: {stats.bytes_per_second / 1_000_000:.2f} Мбит/сек",
                timestamp=datetime.now(),
                details={"bps": stats.bytes_per_second, "threshold": settings.ANOMALY_THRESHOLD_BPS}
            ))
        
        return anomalies
    
    def _detect_port_scan(self, packets: List[PacketInfo]) -> List[AnomalyDetection]:
        """Флагнуть IP, обратившиеся более чем к 20 уникальным dst-портам.

        Порог захардкожен здесь и не связан с settings.ANOMALY_THRESHOLD_PORT_SCAN.
        """
        anomalies = []

        ip_ports = defaultdict(set)
        
        for pkt in packets:
            if pkt.dst_port:
                ip_ports[pkt.src_ip].add(pkt.dst_port)
        
        for ip, ports in ip_ports.items():
            if len(ports) > 20:
                severity = min(1.0, len(ports) / 100)
                anomalies.append(AnomalyDetection(
                    type=AnomalyType.PORT_SCAN,
                    severity=severity,
                    description=f"Сканирование портов с {ip}: {len(ports)} портов",
                    timestamp=datetime.now(),
                    source_ip=ip,
                    details={"ports_count": len(ports), "ports": list(ports)[:50]}
                ))
        
        return anomalies
    
    def _detect_suspicious_patterns(self, packets: List[PacketInfo]) -> List[AnomalyDetection]:
        """Обнаружить SYN-флуд (SYN без ACK) и потоки мелких (<64 байт) пакетов.

        Оба случая репортятся как AnomalyType.SUSPICIOUS_PATTERN — отдельного
        типа для SYN flood в модели нет, разница видна только в description.
        """
        anomalies = []

        syn_flood_ips = defaultdict(int)
        
        for pkt in packets:
            if pkt.protocol == "TCP" and pkt.flags and "S" in pkt.flags and "A" not in pkt.flags:
                syn_flood_ips[pkt.src_ip] += 1
        
        for ip, syn_count in syn_flood_ips.items():
            if syn_count > 100:
                severity = min(1.0, syn_count / 1000)
                anomalies.append(AnomalyDetection(
                    type=AnomalyType.SUSPICIOUS_PATTERN,
                    severity=severity,
                    description=f"Возможная SYN flood атака с {ip}: {syn_count} SYN пакетов",
                    timestamp=datetime.now(),
                    source_ip=ip,
                    details={"syn_count": syn_count}
                ))
        
        small_packet_ips = defaultdict(int)
        for pkt in packets:
            if pkt.length < 64:
                small_packet_ips[pkt.src_ip] += 1
        
        for ip, count in small_packet_ips.items():
            if count > 500:
                severity = min(1.0, count / 5000)
                anomalies.append(AnomalyDetection(
                    type=AnomalyType.SUSPICIOUS_PATTERN,
                    severity=severity,
                    description=f"Подозрительно много маленьких пакетов с {ip}: {count}",
                    timestamp=datetime.now(),
                    source_ip=ip,
                    details={"small_packets": count}
                ))
        
        return anomalies
    
    def _detect_ddos_patterns(self, packets: List[PacketInfo], stats: TrafficStats) -> List[AnomalyDetection]:
        """Найти DDoS-паттерны: один IP с >30% трафика, либо много IP при высоком PPS.

        Проверяет только 10 самых активных отправителей (Counter.most_common(10)).
        """
        anomalies = []

        ip_packet_count = Counter(pkt.src_ip for pkt in packets)
        
        total_packets = len(packets)
        for ip, count in ip_packet_count.most_common(10):
            percentage = (count / total_packets) * 100
            
            if percentage > 30 and count > 1000:
                severity = min(1.0, percentage / 50)
                anomalies.append(AnomalyDetection(
                    type=AnomalyType.DDOS_ATTACK,
                    severity=severity,
                    description=f"Возможная DDoS атака с {ip}: {percentage:.1f}% трафика ({count} пакетов)",
                    timestamp=datetime.now(),
                    source_ip=ip,
                    details={"packets": count, "percentage": percentage}
                ))
        
        if stats.unique_ips > settings.ANOMALY_THRESHOLD_CONNECTIONS:
            if stats.packets_per_second > 1000:
                severity = min(1.0, stats.unique_ips / (settings.ANOMALY_THRESHOLD_CONNECTIONS * 5))
                anomalies.append(AnomalyDetection(
                    type=AnomalyType.DDOS_ATTACK,
                    severity=severity,
                    description=f"Распределенная атака: {stats.unique_ips} уникальных IP",
                    timestamp=datetime.now(),
                    details={"unique_ips": stats.unique_ips, "pps": stats.packets_per_second}
                ))
        
        return anomalies
    
    def _detect_malformed_packets(self, packets: List[PacketInfo]) -> List[AnomalyDetection]:
        """Посчитать UDP-пакеты на игровом/query-порту с длиной вне диапазона 20–1500 байт."""
        anomalies = []

        malformed_count = 0
        malformed_ips = Counter()
        
        for pkt in packets:
            if pkt.protocol == "UDP" and pkt.dst_port in [settings.SQUAD_GAME_PORT, settings.SQUAD_QUERY_PORT]:
                if pkt.length < 20 or pkt.length > 1500:
                    malformed_count += 1
                    malformed_ips[pkt.src_ip] += 1
        
        if malformed_count > 50:
            severity = min(1.0, malformed_count / 500)
            top_offender = malformed_ips.most_common(1)[0] if malformed_ips else ("unknown", 0)
            anomalies.append(AnomalyDetection(
                type=AnomalyType.MALFORMED_PACKET,
                severity=severity,
                description=f"Обнаружено {malformed_count} некорректных пакетов",
                timestamp=datetime.now(),
                source_ip=top_offender[0],
                details={"malformed_count": malformed_count, "top_sources": dict(malformed_ips.most_common(5))}
            ))
        
        return anomalies
    
    def _detect_ml_anomalies(self, packets: List[PacketInfo]) -> List[AnomalyDetection]:
        """Обучить IsolationForest на признаках по 1-секундным окнам и найти выбросы.

        Пропускается, если пакетов меньше 100. Индексы аномальных строк из
        predictions (одна строка на окно) используются напрямую как индексы в
        packets (один элемент на пакет) — при >100 окнах это указывает на
        несвязанные пакеты, так что anomaly_percentage и top_sources в
        details можно доверять лишь приблизительно.
        """
        anomalies = []

        if len(packets) < 100:
            return anomalies
        
        try:
            features = self._extract_features(packets)
            
            predictions = self.ml_model.fit_predict(features)
            
            anomaly_indices = np.where(predictions == -1)[0]
            
            if len(anomaly_indices) > 0:
                anomaly_percentage = (len(anomaly_indices) / len(packets)) * 100
                
                if anomaly_percentage > 5:
                    severity = min(1.0, anomaly_percentage / 20)
                    
                    anomalous_ips = Counter([packets[i].src_ip for i in anomaly_indices])
                    top_ip = anomalous_ips.most_common(1)[0] if anomalous_ips else ("unknown", 0)
                    
                    anomalies.append(AnomalyDetection(
                        type=AnomalyType.ML_DETECTED,
                        severity=severity,
                        description=f"ML модель обнаружила аномалии: {anomaly_percentage:.1f}% пакетов",
                        timestamp=datetime.now(),
                        source_ip=top_ip[0],
                        details={
                            "anomaly_count": len(anomaly_indices),
                            "anomaly_percentage": anomaly_percentage,
                            "top_sources": dict(anomalous_ips.most_common(5))
                        }
                    ))
        except Exception as e:
            logger.error(f"ML anomaly detection failed: {e}")
        
        return anomalies
    
    def _extract_features(self, packets: List[PacketInfo]) -> np.ndarray:
        """Bucket пакеты в 1-секундные окна и вернуть по одной строке признаков на окно.

        Признаки на окно: [кол-во пакетов, суммарные байты, кол-во уникальных
        src IP, средний размер пакета]. Не бывает признаков "на IP" — вся
        группировка идёт по времени, а не по источнику.
        """
        time_windows = defaultdict(lambda: {"count": 0, "bytes": 0, "ips": set()})
        
        if not packets:
            return np.array([])
        
        start_time = packets[0].timestamp
        window_size = 1.0
        
        for pkt in packets:
            window_idx = int((pkt.timestamp - start_time) / window_size)
            time_windows[window_idx]["count"] += 1
            time_windows[window_idx]["bytes"] += pkt.length
            time_windows[window_idx]["ips"].add(pkt.src_ip)
        
        features = []
        for window_data in time_windows.values():
            features.append([
                window_data["count"],
                window_data["bytes"],
                len(window_data["ips"]),
                window_data["bytes"] / max(window_data["count"], 1)
            ])
        
        return np.array(features)
