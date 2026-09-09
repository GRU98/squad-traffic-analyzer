"""Детекция аномалий в трафике: эвристические правила + Isolation Forest (ML)."""

import logging
from collections import Counter, defaultdict
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest

from config import settings
from models import AnomalyDetection, AnomalyType, PacketInfo, TrafficStats

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Прогоняет пакеты и статистику через набор эвристик и ML-модель.

    ML-модель (IsolationForest) переобучается заново на каждый вызов
    detect_anomalies — baseline между анализами не сохраняется.
    """

    def __init__(self):
        self.ml_model = IsolationForest(contamination=settings.ML_MODEL_CONTAMINATION, random_state=42)
        self.baseline_trained = False

    def detect_anomalies(
        self,
        packets: list[PacketInfo],
        stats: TrafficStats,
        server_ip: str | None = None,
    ) -> list[AnomalyDetection]:
        """Запустить все детекторы и вернуть найденные аномалии по убыванию severity.

        Args:
            packets: пакеты одного PCAP-файла (из PcapParser.parse_pcap).
            stats: агрегированная статистика того же файла.
            server_ip: IP Squad-сервера. Если задан, исходящие пакеты сервера
                исключаются из детекторов "по источнику" (DDoS, сканирование
                портов, мелкие пакеты): сервер сам отвечает десяткам клиентских
                портов и генерирует большую долю трафика, что без фильтра
                выглядит как атака. Без server_ip анализируются все пакеты.

        Returns:
            Список AnomalyDetection, отсортированный по severity (убывание).
        """
        anomalies = []
        inbound = [pkt for pkt in packets if pkt.src_ip != server_ip] if server_ip else packets

        anomalies.extend(self._detect_high_traffic(stats))
        anomalies.extend(self._detect_port_scan(inbound))
        anomalies.extend(self._detect_suspicious_patterns(inbound))
        anomalies.extend(self._detect_ddos_patterns(inbound, stats))
        anomalies.extend(self._detect_malformed_packets(inbound))
        anomalies.extend(self._detect_query_flood(stats))

        ml_anomalies = self._detect_ml_anomalies(packets)
        anomalies.extend(ml_anomalies)

        anomalies.sort(key=lambda x: x.severity, reverse=True)

        return anomalies

    def _detect_high_traffic(self, stats: TrafficStats) -> list[AnomalyDetection]:
        """Сравнить PPS/BPS с порогами из настроек (HIGH_PPS / HIGH_BPS)."""
        anomalies = []

        if stats.packets_per_second > settings.ANOMALY_THRESHOLD_PPS:
            severity = min(1.0, stats.packets_per_second / (settings.ANOMALY_THRESHOLD_PPS * 2))
            anomalies.append(
                AnomalyDetection(
                    type=AnomalyType.HIGH_PPS,
                    severity=severity,
                    description=f"Высокий PPS: {stats.packets_per_second:.2f} пакетов/сек",
                    timestamp=datetime.now(),
                    details={"pps": stats.packets_per_second, "threshold": settings.ANOMALY_THRESHOLD_PPS},
                )
            )

        if stats.bytes_per_second > settings.ANOMALY_THRESHOLD_BPS:
            severity = min(1.0, stats.bytes_per_second / (settings.ANOMALY_THRESHOLD_BPS * 2))
            anomalies.append(
                AnomalyDetection(
                    type=AnomalyType.HIGH_BPS,
                    severity=severity,
                    description=f"Высокий BPS: {stats.bytes_per_second / 1_000_000:.2f} Мбит/сек",
                    timestamp=datetime.now(),
                    details={"bps": stats.bytes_per_second, "threshold": settings.ANOMALY_THRESHOLD_BPS},
                )
            )

        return anomalies

    def _detect_port_scan(self, packets: list[PacketInfo]) -> list[AnomalyDetection]:
        """Флагнуть IP, обратившиеся более чем к ANOMALY_THRESHOLD_PORT_SCAN уникальным dst-портам."""
        anomalies = []
        threshold = settings.ANOMALY_THRESHOLD_PORT_SCAN

        ip_ports = defaultdict(set)

        for pkt in packets:
            if pkt.dst_port:
                ip_ports[pkt.src_ip].add(pkt.dst_port)

        for ip, ports in ip_ports.items():
            if len(ports) > threshold:
                severity = min(1.0, len(ports) / (threshold * 5))
                anomalies.append(
                    AnomalyDetection(
                        type=AnomalyType.PORT_SCAN,
                        severity=severity,
                        description=f"Сканирование портов с {ip}: {len(ports)} портов",
                        timestamp=datetime.now(),
                        source_ip=ip,
                        details={"ports_count": len(ports), "ports": sorted(ports)[:50], "threshold": threshold},
                    )
                )

        return anomalies

    def _detect_suspicious_patterns(self, packets: list[PacketInfo]) -> list[AnomalyDetection]:
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
                anomalies.append(
                    AnomalyDetection(
                        type=AnomalyType.SUSPICIOUS_PATTERN,
                        severity=severity,
                        description=f"Возможная SYN flood атака с {ip}: {syn_count} SYN пакетов",
                        timestamp=datetime.now(),
                        source_ip=ip,
                        details={"syn_count": syn_count},
                    )
                )

        small_packet_ips = defaultdict(int)
        for pkt in packets:
            if pkt.length < 64:
                small_packet_ips[pkt.src_ip] += 1

        for ip, count in small_packet_ips.items():
            if count > 500:
                severity = min(1.0, count / 5000)
                anomalies.append(
                    AnomalyDetection(
                        type=AnomalyType.SUSPICIOUS_PATTERN,
                        severity=severity,
                        description=f"Подозрительно много маленьких пакетов с {ip}: {count}",
                        timestamp=datetime.now(),
                        source_ip=ip,
                        details={"small_packets": count},
                    )
                )

        return anomalies

    def _detect_ddos_patterns(self, packets: list[PacketInfo], stats: TrafficStats) -> list[AnomalyDetection]:
        """Найти DDoS-паттерны: один IP с >30% входящего трафика, либо много IP при высоком PPS.

        Проверяет только 10 самых активных отправителей (Counter.most_common(10)).
        """
        anomalies = []

        ip_packet_count = Counter(pkt.src_ip for pkt in packets)

        total_packets = len(packets)
        for ip, count in ip_packet_count.most_common(10):
            percentage = (count / total_packets) * 100

            if percentage > 30 and count > 1000:
                severity = min(1.0, percentage / 50)
                anomalies.append(
                    AnomalyDetection(
                        type=AnomalyType.DDOS_ATTACK,
                        severity=severity,
                        description=f"Возможная DDoS атака с {ip}: {percentage:.1f}% трафика ({count} пакетов)",
                        timestamp=datetime.now(),
                        source_ip=ip,
                        details={"packets": count, "percentage": percentage},
                    )
                )

        if stats.unique_ips > settings.ANOMALY_THRESHOLD_CONNECTIONS and stats.packets_per_second > 1000:
            severity = min(1.0, stats.unique_ips / (settings.ANOMALY_THRESHOLD_CONNECTIONS * 5))
            anomalies.append(
                AnomalyDetection(
                    type=AnomalyType.DDOS_ATTACK,
                    severity=severity,
                    description=f"Распределенная атака: {stats.unique_ips} уникальных IP",
                    timestamp=datetime.now(),
                    details={"unique_ips": stats.unique_ips, "pps": stats.packets_per_second},
                )
            )

        return anomalies

    def _detect_malformed_packets(self, packets: list[PacketInfo]) -> list[AnomalyDetection]:
        """Посчитать UDP-пакеты на игровом/query-порту с длиной вне диапазона 20–1500 байт."""
        anomalies = []

        malformed_count = 0
        malformed_ips = Counter()

        for pkt in packets:
            on_squad_port = pkt.protocol == "UDP" and pkt.dst_port in (
                settings.SQUAD_GAME_PORT,
                settings.SQUAD_QUERY_PORT,
            )
            if on_squad_port and (pkt.length < 20 or pkt.length > 1500):
                malformed_count += 1
                malformed_ips[pkt.src_ip] += 1

        if malformed_count > 50:
            severity = min(1.0, malformed_count / 500)
            top_offender = malformed_ips.most_common(1)[0] if malformed_ips else ("unknown", 0)
            anomalies.append(
                AnomalyDetection(
                    type=AnomalyType.MALFORMED_PACKET,
                    severity=severity,
                    description=f"Обнаружено {malformed_count} некорректных пакетов",
                    timestamp=datetime.now(),
                    source_ip=top_offender[0],
                    details={"malformed_count": malformed_count, "top_sources": dict(malformed_ips.most_common(5))},
                )
            )

        return anomalies

    def _detect_query_flood(self, stats: TrafficStats) -> list[AnomalyDetection]:
        """Обнаружить A2S query flood / amplification на query-порту.

        Steam-запрос A2S_INFO — это ~25 байт payload, ответ сервера — сотни байт,
        поэтому query-порт используют и для отражённых (spoofed) атак, и для
        прямого флуда. Правило: входящих запросов в секунду больше
        ANOMALY_THRESHOLD_QUERY_PPS. Работает только если парсер знал server_ip
        (иначе счётчики запросов нулевые). Ставка PPS считается по длительности
        захвата (total_packets / packets_per_second).
        """
        anomalies: list[AnomalyDetection] = []

        if stats.query_requests == 0 or stats.packets_per_second <= 0 or stats.total_packets == 0:
            return anomalies

        duration = stats.total_packets / stats.packets_per_second
        requests_per_second = stats.query_requests / duration
        threshold = settings.ANOMALY_THRESHOLD_QUERY_PPS

        if requests_per_second > threshold:
            severity = min(1.0, requests_per_second / (threshold * 5))
            amplification = stats.query_response_bytes / stats.query_request_bytes if stats.query_request_bytes else 0.0
            anomalies.append(
                AnomalyDetection(
                    type=AnomalyType.QUERY_FLOOD,
                    severity=severity,
                    description=(
                        f"Query flood на порту {settings.SQUAD_QUERY_PORT}: {requests_per_second:.0f} запросов/сек "
                        f"с {stats.query_request_sources} IP (amplification x{amplification:.1f})"
                    ),
                    timestamp=datetime.now(),
                    details={
                        "requests_per_second": requests_per_second,
                        "threshold": threshold,
                        "unique_sources": stats.query_request_sources,
                        "requests": stats.query_requests,
                        "responses": stats.query_responses,
                        "amplification_ratio": amplification,
                    },
                )
            )

        return anomalies

    def _detect_ml_anomalies(self, packets: list[PacketInfo]) -> list[AnomalyDetection]:
        """Обучить IsolationForest на признаках по 1-секундным окнам и найти всплески.

        Пропускается, если ML_ENABLED выключен или пакетов меньше 100.

        IsolationForest с фиксированным contamination всегда помечает долю окон
        как выбросы, даже на идеально ровном трафике. Поэтому окно считается
        аномальным только если модель его пометила И его объём (пакеты или
        байты) превышает медиану по всем окнам минимум вдвое. Пакеты-источники
        атрибутируются по принадлежности к аномальным окнам, а не по индексу.
        """
        anomalies = []

        if not settings.ML_ENABLED or len(packets) < 100:
            return anomalies

        try:
            features, window_packets = self._extract_features(packets)
            if len(features) < 2:
                return anomalies

            predictions = self.ml_model.fit_predict(features)

            median_count = float(np.median(features[:, 0]))
            median_bytes = float(np.median(features[:, 1]))
            flagged_windows = [
                window_idx
                for window_idx, (prediction, row) in enumerate(zip(predictions, features, strict=True))
                if prediction == -1 and (row[0] >= median_count * 2 or row[1] >= median_bytes * 2)
            ]

            if not flagged_windows:
                return anomalies

            anomalous_packets = [packets[i] for w in flagged_windows for i in window_packets[w][1]]
            anomaly_percentage = (len(anomalous_packets) / len(packets)) * 100

            if anomaly_percentage > 5:
                severity = min(1.0, anomaly_percentage / 20)

                anomalous_ips = Counter(pkt.src_ip for pkt in anomalous_packets)
                top_ip = anomalous_ips.most_common(1)[0]

                anomalies.append(
                    AnomalyDetection(
                        type=AnomalyType.ML_DETECTED,
                        severity=severity,
                        description=f"ML модель обнаружила аномалии: {anomaly_percentage:.1f}% пакетов",
                        timestamp=datetime.now(),
                        source_ip=top_ip[0],
                        details={
                            "anomaly_count": len(anomalous_packets),
                            "anomaly_percentage": anomaly_percentage,
                            "windows": sorted(window_packets[w][0] for w in flagged_windows),
                            "top_sources": dict(anomalous_ips.most_common(5)),
                        },
                    )
                )
        except Exception as e:
            logger.error(f"ML anomaly detection failed: {e}")

        return anomalies

    def _extract_features(self, packets: list[PacketInfo]) -> tuple[np.ndarray, list[tuple[int, list[int]]]]:
        """Bucket пакеты в 1-секундные окна и вернуть по одной строке признаков на окно.

        Признаки на окно: [кол-во пакетов, суммарные байты, кол-во уникальных
        src IP, средний размер пакета]. Вторым элементом возвращается список
        (секунда окна, индексы пакетов) в том же порядке, что и строки
        признаков — по нему аномальные окна сопоставляются с пакетами.
        """
        time_windows: dict[int, dict] = defaultdict(lambda: {"count": 0, "bytes": 0, "ips": set(), "packets": []})

        if not packets:
            return np.empty((0, 4)), []

        start_time = packets[0].timestamp
        window_size = 1.0

        for index, pkt in enumerate(packets):
            window_idx = int((pkt.timestamp - start_time) / window_size)
            time_windows[window_idx]["count"] += 1
            time_windows[window_idx]["bytes"] += pkt.length
            time_windows[window_idx]["ips"].add(pkt.src_ip)
            time_windows[window_idx]["packets"].append(index)

        features = []
        window_packets = []
        for window_idx in sorted(time_windows):
            window_data = time_windows[window_idx]
            features.append(
                [
                    window_data["count"],
                    window_data["bytes"],
                    len(window_data["ips"]),
                    window_data["bytes"] / max(window_data["count"], 1),
                ]
            )
            window_packets.append((window_idx, window_data["packets"]))

        return np.array(features, dtype=float), window_packets
