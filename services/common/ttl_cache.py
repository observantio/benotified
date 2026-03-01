"""
Redis-based TTL cache utilities for storing and retrieving temporary data with expiration, including functions to set and get cached values with optional encryption based on a configured encryption key. This module provides a simple interface for caching data in Redis with a specified time-to-live (TTL) and handles encryption and decryption of cached values when an encryption key is configured, ensuring that sensitive data can be stored securely in the cache while still benefiting from Redis's performance and scalability features.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""
import asyncio
import json
import time
import os
import logging
from typing import Any, Awaitable, Callable, Dict, Optional

_redis_asyncio = None
try:
    import redis
    _redis_asyncio = getattr(redis, "asyncio", None)
except Exception:
    _redis_asyncio = None

logger = logging.getLogger(__name__)


class TTLCache:

    def __init__(self) -> None:
        self._data: Dict[str, tuple[Any, float]] = {}
        self._lock = asyncio.Lock()

        self._redis_client = None
        self._redis_connected = False
        self._redis_url = (os.getenv("TTL_CACHE_REDIS_URL") or os.getenv("RATE_LIMIT_REDIS_URL") or "").strip()
        self._key_prefix = (os.getenv("TTL_CACHE_KEY_PREFIX") or "beobs:ttl").strip()

        if _redis_asyncio is not None and self._redis_url:
            try:
                self._redis_client = _redis_asyncio.from_url(self._redis_url, decode_responses=False)
            except Exception as exc:
                logger.warning("Failed to initialize Redis client for TTLCache; using in-memory fallback: %s", exc)
                self._redis_client = None

    async def _ensure_redis(self) -> bool:
        if not self._redis_client:
            return False
        if self._redis_connected:
            return True
        try:
            ok = await self._redis_client.ping()
            if ok:
                self._redis_connected = True
                logger.info("Connected to Redis for TTL cache: %s", self._redis_url)
                return True
        except Exception as exc:
            logger.warning("Redis TTL cache unreachable; falling back to in-memory cache: %s", exc)
            self._redis_client = None
            return False
        return False

    def _redis_key(self, key: str) -> str:
        return f"{self._key_prefix}:{key}"

    def _serialize_value(self, value: Any) -> bytes:
        try:
            return b"j:" + json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except Exception as exc:
            raise ValueError("TTL cache only supports JSON-serializable values") from exc

    def _deserialize_value(self, raw: bytes) -> Optional[Any]:
        if raw is None:
            return None
        if raw.startswith(b"j:"):
            try:
                return json.loads(raw[2:].decode("utf-8"))
            except Exception:
                logger.warning("TTL cache JSON payload is invalid; dropping cache value")
                return None
        # Strict mode: no pickle or arbitrary bytes deserialization.
        logger.warning("TTL cache encountered non-JSON legacy payload; dropping cache value")
        return None

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            if await self._ensure_redis():
                if self._redis_client is None:
                    return None
                try:
                    raw = await self._redis_client.get(self._redis_key(key))
                    return self._deserialize_value(raw)
                except Exception as exc:
                    logger.warning("Redis TTL cache GET failed; falling back to memory: %s", exc)
                    self._redis_client = None

            entry = self._data.get(key)
            if not entry:
                return None
            value, expires = entry
            if time.monotonic() > expires:
                self._data.pop(key, None)
                return None
            return value

    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        async with self._lock:
            if await self._ensure_redis():
                if self._redis_client is None:
                    return
                try:
                    raw = self._serialize_value(value)
                    await self._redis_client.set(self._redis_key(key), raw, ex=max(0, int(ttl_seconds)))
                    return
                except Exception as exc:
                    logger.warning("Redis TTL cache SET failed; using in-memory fallback: %s", exc)
                    self._redis_client = None

            self._data[key] = (value, time.monotonic() + max(0, int(ttl_seconds)))

    async def get_or_set(self, key: str, factory: Callable[[], Awaitable[Any]], ttl_seconds: int) -> Optional[Any]:
        async with self._lock:
            # Try Redis first
            if await self._ensure_redis():
                if self._redis_client is None:
                    return None
                try:
                    raw = await self._redis_client.get(self._redis_key(key))
                    if raw is not None:
                        return self._deserialize_value(raw)
                except Exception as exc:
                    logger.warning("Redis TTL cache GET failed; falling back to memory: %s", exc)
                    self._redis_client = None

            entry = self._data.get(key)
            if entry and time.monotonic() <= entry[1]:
                return entry[0]

            value = None
            try:
                value = await factory()
            except Exception:
                raise
            if value is None:
                return None

            if await self._ensure_redis():
                if self._redis_client is None:
                    return value
                try:
                    raw = self._serialize_value(value)
                    await self._redis_client.set(self._redis_key(key), raw, ex=max(0, int(ttl_seconds)))
                    return value
                except Exception as exc:
                    logger.warning("Redis TTL cache SET failed; storing in-memory: %s", exc)
                    self._redis_client = None

            self._data[key] = (value, time.monotonic() + max(0, int(ttl_seconds)))
            return value

    async def clear(self) -> None:
        async with self._lock:
            if await self._ensure_redis():
                if self._redis_client is None:
                    self._data.clear()
                    return
                try:
                    pattern = f"{self._key_prefix}:*"
                    keys = await self._redis_client.keys(pattern)
                    if keys:
                        await self._redis_client.delete(*keys)
                    return
                except Exception as exc:
                    logger.warning("Redis TTL cache CLEAR failed; clearing in-memory cache: %s", exc)
                    self._redis_client = None

            self._data.clear()
