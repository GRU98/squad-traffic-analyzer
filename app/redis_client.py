import redis
import json
from typing import Optional, Dict
from datetime import datetime, timedelta
import logging

from config import settings

logger = logging.getLogger(__name__)


class RedisClient:
    def __init__(self):
        self.client = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD,
            decode_responses=True
        )
        
    def store_realtime_stats(self, stats: Dict, ttl: int = 3600):
        try:
            key = f"stats:{datetime.now().strftime('%Y%m%d%H%M%S')}"
            self.client.setex(key, ttl, json.dumps(stats))
            logger.info(f"Stored stats in Redis: {key}")
        except Exception as e:
            logger.error(f"Failed to store stats in Redis: {e}")
    
    def get_recent_stats(self, hours: int = 1) -> list:
        try:
            pattern = "stats:*"
            keys = self.client.keys(pattern)
            
            stats_list = []
            for key in keys:
                data = self.client.get(key)
                if data:
                    stats_list.append(json.loads(data))
            
            return stats_list
        except Exception as e:
            logger.error(f"Failed to get stats from Redis: {e}")
            return []
    
    def increment_counter(self, counter_name: str, amount: int = 1):
        try:
            self.client.incr(counter_name, amount)
        except Exception as e:
            logger.error(f"Failed to increment counter: {e}")
    
    def get_counter(self, counter_name: str) -> int:
        try:
            value = self.client.get(counter_name)
            return int(value) if value else 0
        except Exception as e:
            logger.error(f"Failed to get counter: {e}")
            return 0
    
    def store_anomaly_alert(self, anomaly: Dict):
        try:
            key = f"anomaly:{datetime.now().strftime('%Y%m%d%H%M%S')}"
            self.client.setex(key, 86400, json.dumps(anomaly))
            
            self.client.lpush("recent_anomalies", json.dumps(anomaly))
            self.client.ltrim("recent_anomalies", 0, 99)
            
            logger.info(f"Stored anomaly alert: {key}")
        except Exception as e:
            logger.error(f"Failed to store anomaly: {e}")
    
    def get_recent_anomalies(self, limit: int = 10) -> list:
        try:
            anomalies = self.client.lrange("recent_anomalies", 0, limit - 1)
            return [json.loads(a) for a in anomalies]
        except Exception as e:
            logger.error(f"Failed to get anomalies: {e}")
            return []
    
    def cleanup_old_data(self):
        try:
            cutoff = datetime.now() - timedelta(hours=settings.STATS_RETENTION_HOURS)
            cutoff_str = cutoff.strftime('%Y%m%d%H%M%S')
            
            pattern = "stats:*"
            keys = self.client.keys(pattern)
            
            deleted = 0
            for key in keys:
                timestamp_str = key.split(':')[1]
                if timestamp_str < cutoff_str:
                    self.client.delete(key)
                    deleted += 1
            
            logger.info(f"Cleaned up {deleted} old stats entries")
        except Exception as e:
            logger.error(f"Failed to cleanup old data: {e}")
