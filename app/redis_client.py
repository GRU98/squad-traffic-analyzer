"""Тонкая обёртка над redis-py: real-time статистика, алерты, счётчики, очистка."""

import json
import logging
from datetime import datetime, timedelta

import redis
from redis.backoff import ExponentialBackoff
from redis.retry import Retry

from config import settings

logger = logging.getLogger(__name__)


class RedisClient:
    """Все методы глотают исключения redis и только логируют их — сбой Redis не роняет анализ."""

    def __init__(self):
        self.client = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=5,
            # redis-py >= 8 по умолчанию делает 10 повторов с backoff — недоступный Redis
            # блокировал бы каждый анализ на ~30 с. Один быстрый повтор достаточно.
            retry=Retry(ExponentialBackoff(cap=0.5, base=0.1), 1),
        )

    def store_realtime_stats(self, stats: dict, ttl: int = 3600):
        """Сохранить снимок статистики под ключом stats:<timestamp с микросекундами>, истекает через ttl секунд."""
        try:
            key = f"stats:{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
            self.client.setex(key, ttl, json.dumps(stats))
            logger.info(f"Stored stats in Redis: {key}")
        except Exception as e:
            logger.error(f"Failed to store stats in Redis: {e}")

    def get_recent_stats(self, hours: int = 1) -> list:
        """Вернуть все снимки статистики, ещё не истёкшие в Redis (ключи stats:*).

        Параметр hours не используется для фильтрации — фактическое окно
        определяется только TTL, заданным в store_realtime_stats.
        """
        try:
            stats_list = []
            for key in self.client.scan_iter("stats:*"):
                data = self.client.get(key)
                if data:
                    stats_list.append(json.loads(data))

            return stats_list
        except Exception as e:
            logger.error(f"Failed to get stats from Redis: {e}")
            return []

    def increment_counter(self, counter_name: str, amount: int = 1):
        """Атомарно увеличить именованный счётчик Redis на amount (INCRBY)."""
        try:
            self.client.incr(counter_name, amount)
        except Exception as e:
            logger.error(f"Failed to increment counter: {e}")

    def get_counter(self, counter_name: str) -> int:
        """Прочитать значение счётчика; 0, если ключ не найден или Redis недоступен."""
        try:
            value = self.client.get(counter_name)
            return int(value) if value else 0
        except Exception as e:
            logger.error(f"Failed to get counter: {e}")
            return 0

    def store_anomaly_alert(self, anomaly: dict):
        """Сохранить аномалию под ключом anomaly:<timestamp> (TTL 24ч) и в списке recent_anomalies (последние 100)."""
        try:
            key = f"anomaly:{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
            self.client.setex(key, 86400, json.dumps(anomaly))

            self.client.lpush("recent_anomalies", json.dumps(anomaly))
            self.client.ltrim("recent_anomalies", 0, 99)

            logger.info(f"Stored anomaly alert: {key}")
        except Exception as e:
            logger.error(f"Failed to store anomaly: {e}")

    def get_recent_anomalies(self, limit: int = 10) -> list:
        """Вернуть до limit последних аномалий из списка recent_anomalies (новые первыми)."""
        try:
            anomalies = self.client.lrange("recent_anomalies", 0, limit - 1)
            return [json.loads(a) for a in anomalies]
        except Exception as e:
            logger.error(f"Failed to get anomalies: {e}")
            return []

    def cleanup_old_data(self):
        """Удалить stats:* ключи старше settings.STATS_RETENTION_HOURS.

        anomaly:* ключи сюда не входят — они самостоятельно истекают по TTL
        (24ч), заданному в store_anomaly_alert.
        """
        try:
            cutoff = datetime.now() - timedelta(hours=settings.STATS_RETENTION_HOURS)
            cutoff_str = cutoff.strftime("%Y%m%d%H%M%S%f")

            deleted = 0
            for key in list(self.client.scan_iter("stats:*")):
                timestamp_str = key.split(":")[1]
                if timestamp_str < cutoff_str:
                    self.client.delete(key)
                    deleted += 1

            logger.info(f"Cleaned up {deleted} old stats entries")
        except Exception as e:
            logger.error(f"Failed to cleanup old data: {e}")
