"""Оркестрация полного пайплайна анализа: парсинг → детекция → скоринг → сохранение."""

import asyncio
import logging
import uuid
from datetime import datetime

from anomaly_detector import AnomalyDetector
from config import settings
from database import AnalysisRecord, SessionLocal
from models import AnalysisResult, AnomalyDetection, TrafficStats
from pcap_parser import PcapParser
from redis_client import RedisClient

logger = logging.getLogger(__name__)


class TrafficAnalyzer:
    """Связывает PcapParser, AnomalyDetector и хранилища (Redis, БД) в один анализ."""

    def __init__(self):
        self.parser = None
        self.detector = AnomalyDetector()
        self.redis_client = RedisClient()

    async def analyze_pcap(
        self, pcap_path: str, server_ip: str | None = None, game_port: int = 7787, query_port: int = 27165
    ) -> AnalysisResult:
        """Разобрать PCAP-файл, найти аномалии и сохранить/оповестить о результате.

        Args:
            pcap_path: путь к .pcap/.pcapng файлу на диске.
            server_ip: IP Squad-сервера — нужен, чтобы отделить game/query-порт
                трафик; без него счётчики game_port_packets/query_port_packets
                остаются нулевыми.
            game_port: игровой UDP-порт сервера.
            query_port: query (Steam) UDP-порт сервера.

        Returns:
            AnalysisResult с статистикой, аномалиями, risk_score и рекомендациями.
            Результат также сохраняется в Redis и БД, и рассылается уведомлением,
            если риск достаточно высок — ошибки этих побочных шагов только
            логируются и не прерывают анализ.

        Raises:
            Exception: если PCAP-файл не удалось прочитать (см. PcapParser.parse_pcap).

        Разбор и детекция — CPU-bound и выполняются в отдельном потоке, чтобы
        не блокировать event loop FastAPI на время обработки больших файлов.
        """
        start_time = datetime.now()
        analysis_id = str(uuid.uuid4())

        logger.info(f"Starting analysis {analysis_id} for {pcap_path}")

        self.parser = PcapParser(server_ip, game_port, query_port)

        packets, stats = await asyncio.to_thread(self.parser.parse_pcap, pcap_path)

        anomalies = await asyncio.to_thread(
            self.detector.detect_anomalies, packets, stats, server_ip, game_port, query_port
        )

        risk_score = self._calculate_risk_score(anomalies, stats)
        is_under_attack = risk_score > 0.7

        recommendations = self._generate_recommendations(anomalies, stats, is_under_attack)

        duration = (datetime.now() - start_time).total_seconds()

        result = AnalysisResult(
            analysis_id=analysis_id,
            timestamp=start_time,
            duration_seconds=duration,
            stats=stats,
            anomalies=anomalies,
            risk_score=risk_score,
            is_under_attack=is_under_attack,
            recommendations=recommendations,
        )

        self._save_to_redis(result)
        self._save_to_database(result)

        logger.info(f"Analysis {analysis_id} completed in {duration:.2f}s, risk: {risk_score:.2f}")

        # Send notifications
        try:
            from notifications import notifier

            await notifier.send_alert(result)
        except Exception as e:
            logger.error(f"Notification error: {e}")

        return result

    def _calculate_risk_score(self, anomalies: list[AnomalyDetection], stats: TrafficStats) -> float:
        """Свести аномалии в единый риск 0.0-1.0: max_severity*0.5 + avg_severity*0.3 + count_factor*0.2."""
        if not anomalies:
            return 0.0

        max_severity = max(a.severity for a in anomalies)
        avg_severity = sum(a.severity for a in anomalies) / len(anomalies)
        anomaly_count_factor = min(1.0, len(anomalies) / 10)

        risk_score = (max_severity * 0.5) + (avg_severity * 0.3) + (anomaly_count_factor * 0.2)

        return min(1.0, risk_score)

    def _generate_recommendations(
        self, anomalies: list[AnomalyDetection], stats: TrafficStats, is_under_attack: bool
    ) -> list[str]:
        """Собрать удобочитаемые (RU) рекомендации по типам найденных аномалий.

        Порядок сохраняется (критичное предупреждение первым, далее по аномалиям
        в порядке убывания severity), точные дубликаты убираются.
        """
        recommendations = []

        if is_under_attack:
            recommendations.append("⚠️ КРИТИЧНО: Сервер под атакой! Рекомендуется немедленная проверка.")

        for anomaly in anomalies:
            if anomaly.type.value == "ddos_attack":
                recommendations.append(f"Заблокировать IP {anomaly.source_ip} в firewall")
                recommendations.append("Включить rate limiting на уровне сети")

            elif anomaly.type.value == "port_scan":
                recommendations.append(f"Добавить {anomaly.source_ip} в blacklist (сканирование портов)")

            elif anomaly.type.value == "high_pps":
                recommendations.append("Проверить настройки DDoS защиты")
                recommendations.append("Рассмотреть использование CloudFlare/Qrator")

            elif anomaly.type.value == "query_flood":
                recommendations.append(
                    f"Ограничить rate A2S-запросов на UDP {settings.SQUAD_QUERY_PORT} (iptables hashlimit / провайдер)"
                )
                recommendations.append(
                    "Проверить, не используется ли сервер для reflection-атаки (ответы на spoofed IP)"
                )

            elif anomaly.type.value == "suspicious_pattern":
                if "SYN flood" in anomaly.description:
                    recommendations.append("Настроить SYN cookies на уровне ОС")
                    recommendations.append(f"Заблокировать {anomaly.source_ip}")

        if stats.unique_ips > 200:
            recommendations.append("Большое количество уникальных IP - возможна распределенная атака")

        if not recommendations:
            recommendations.append("✅ Трафик в норме, подозрительной активности не обнаружено")

        return list(dict.fromkeys(recommendations))

    def _save_to_redis(self, result: AnalysisResult):
        """Кэшировать статистику и алерты (severity > 0.5) в Redis. Ошибки только логируются."""
        try:
            stats_dict = result.stats.model_dump()
            self.redis_client.store_realtime_stats(stats_dict)

            for anomaly in result.anomalies:
                if anomaly.severity > 0.5:
                    self.redis_client.store_anomaly_alert(anomaly.model_dump())
        except Exception as e:
            logger.error(f"Failed to save to Redis: {e}")

    def _save_to_database(self, result: AnalysisResult):
        """Записать результат анализа в таблицу analyses. Ошибки только логируются."""
        try:
            with SessionLocal() as db:
                record = AnalysisRecord(
                    analysis_id=result.analysis_id,
                    timestamp=result.timestamp,
                    duration_seconds=result.duration_seconds,
                    total_packets=result.stats.total_packets,
                    total_bytes=result.stats.total_bytes,
                    unique_ips=result.stats.unique_ips,
                    packets_per_second=result.stats.packets_per_second,
                    bytes_per_second=result.stats.bytes_per_second,
                    anomaly_count=len(result.anomalies),
                    risk_score=result.risk_score,
                    is_under_attack=result.is_under_attack,
                    stats_json=result.stats.model_dump(),
                    anomalies_json=[a.model_dump() for a in result.anomalies],
                    recommendations_json=result.recommendations,
                )
                db.add(record)
                db.commit()

            logger.info(f"Saved analysis {result.analysis_id} to database")
        except Exception as e:
            logger.error(f"Failed to save to database: {e}")
