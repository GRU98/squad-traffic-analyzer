from redis_client import RedisClient


def test_unavailable_redis_is_swallowed():
    client = RedisClient()

    client.store_realtime_stats({"total_packets": 1})
    client.store_anomaly_alert({"type": "high_pps"})
    client.increment_counter("x")
    client.cleanup_old_data()

    assert client.get_recent_stats() == []
    assert client.get_recent_anomalies() == []
    assert client.get_counter("x") == 0
