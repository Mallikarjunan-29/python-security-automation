import redis
import os
import json

class RedisCache:
    def __init__(self):
        host = os.getenv("REDIS_HOST", "localhost")

        self.redis_ti = redis.Redis(
            host=host,
            port=6379,
            db=0,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30
        )

        self.redis_ai = redis.Redis(
            host=host,
            port=6379,
            db=1,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30
        )

        self.DEFAULT_TTL = 14400  # 4 hours

    def get_ti(self, key):
        value = self.redis_ti.get(key)
        return json.loads(value) if value else None

    def get_ai(self, key):
        value = self.redis_ai.get(key)
        return json.loads(value) if value else None

    def set_ti(self, key, value, ttl=None):
        return self.redis_ti.set(
            key,
            json.dumps(value),
            ex=ttl or self.DEFAULT_TTL
        )

    def set_ai(self, key, value, ttl=None):
        return self.redis_ai.set(
            key,
            json.dumps(value),
            ex=ttl or self.DEFAULT_TTL
        )