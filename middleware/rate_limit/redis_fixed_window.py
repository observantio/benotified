"""
Redis-based fixed window rate limiter for Be Observant middleware.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import logging
import time
from importlib import import_module
from urllib.parse import urlparse, urlunparse

from .models import RateLimitHitResult

logger = logging.getLogger(__name__)


def _sanitize_redis_url(url: str) -> str:
    try:
        p = urlparse(url)
        host = f"{p.hostname}:{p.port}" if p.port else (p.hostname or "")
        return urlunparse(p._replace(netloc=host))
    except (AttributeError, ValueError):
        return "<redis-url>"


class RedisFixedWindowRateLimiter:
    def __init__(
        self,
        redis_url: str,
        *,
        key_prefix: str = "beobs:rl",
        socket_timeout: float = 1.0,
        max_connections: int = 50,
    ) -> None:
        try:
            redis = import_module("redis")
        except ImportError as exc:
            raise RuntimeError("redis package is not installed") from exc

        self._key_prefix = key_prefix

        client = redis.from_url(
            redis_url,
            socket_timeout=socket_timeout,
            socket_connect_timeout=socket_timeout,
            max_connections=max_connections,
            decode_responses=True,
        )

        try:
            if not client.ping():
                raise RuntimeError("redis ping returned falsy response")
        except (ConnectionError, OSError, RuntimeError, TimeoutError) as exc:
            raise RuntimeError(
                f"unable to connect to Redis at {_sanitize_redis_url(redis_url)}: {exc}"
            ) from exc

        self._client = client
        logger.info("Connected to Redis for rate limiting: %s", _sanitize_redis_url(redis_url))

    def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitHitResult:
        if limit <= 0:
            return RateLimitHitResult(True, 0, 0, "redis")

        window_seconds = int(window_seconds)
        if window_seconds <= 0:
            return RateLimitHitResult(True, 0, 0, "redis")

        now = int(time.time())
        window_id = now // window_seconds
        bucket_key = f"{self._key_prefix}:{key}:{window_id}"
        retry_after = max(1, window_seconds - (now % window_seconds))
        pipe = self._client.pipeline(transaction=False)
        pipe.incr(bucket_key)
        pipe.expire(bucket_key, window_seconds + 1)
        current, _ = pipe.execute()

        count = int(current)
        return RateLimitHitResult(count <= limit, max(0, limit - count), retry_after, "redis")
