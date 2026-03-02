"""
These middlewares enforce limits on request size 
and concurrency to protect the server from overload.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Dict, Optional
from urllib.parse import urlparse, urlunparse
from fastapi import HTTPException, Request, status
from config import config

try:
    import redis
except Exception:
    redis = None

logger = logging.getLogger(__name__)

_fallback_lock = threading.Lock()
_rate_limit_fallback_total = 0
_rate_limit_fallback_by_mode: Dict[str, int] = {"memory": 0, "deny": 0, "allow": 0}


def _sanitize_redis_url(url: str) -> str:
    try:
        p = urlparse(url)
        host = f"{p.hostname}:{p.port}" if p.port else (p.hostname or "")
        return urlunparse(p._replace(netloc=host))
    except Exception:
        return "<redis-url>"


def _valid_ip(value: str) -> Optional[str]:
    candidate = (value or "").strip()
    if not candidate:
        return None
    try:
        ip_address(candidate)
        return candidate
    except ValueError:
        return None


@dataclass
class RateLimitState:
    window_start: float
    count: int


@dataclass(frozen=True)
class RateLimitHitResult:
    allowed: bool
    remaining: int
    retry_after_seconds: int
    backend: str
    fallback_used: bool = False


class InMemoryRateLimiter:
    def __init__(
        self,
        *,
        gc_every: int = 1024,
        stale_after_seconds: int = 3600,
        max_states: int = 200_000,
    ) -> None:
        self._lock = threading.Lock()
        self._states: Dict[str, RateLimitState] = {}
        self._gc_every = max(100, int(gc_every))
        self._stale_after_seconds = max(60, int(stale_after_seconds))
        self._max_states = max(10_000, int(max_states))
        self._ops = 0

    def _cleanup(self, now: float, window_seconds: int) -> None:
        self._ops += 1
        if self._ops % self._gc_every != 0:
            return
        threshold = now - max(window_seconds * 2, self._stale_after_seconds)
        stale = [k for k, st in self._states.items() if st.window_start < threshold]
        for k in stale:
            self._states.pop(k, None)

    def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitHitResult:
        if limit <= 0:
            return RateLimitHitResult(True, 0, 0, "memory")

        window_seconds = int(window_seconds)
        if window_seconds <= 0:
            return RateLimitHitResult(True, 0, 0, "memory")

        now = time.time()

        with self._lock:
            self._cleanup(now, window_seconds)

            if key not in self._states and len(self._states) >= self._max_states:
                oldest = min(self._states, key=lambda k: self._states[k].window_start)
                self._states.pop(oldest, None)

            st = self._states.get(key)
            if st is None or (now - st.window_start) >= window_seconds:
                st = RateLimitState(window_start=now, count=0)
                self._states[key] = st

            st.count += 1
            allowed = st.count <= limit
            remaining = max(0, limit - st.count)
            retry_after = max(0, int(window_seconds - (now - st.window_start)))
            return RateLimitHitResult(allowed, remaining, retry_after, "memory")


class RedisFixedWindowRateLimiter:
    def __init__(
        self,
        redis_url: str,
        *,
        key_prefix: str = "beobs:rl",
        socket_timeout: float = 1.0,
        max_connections: int = 50,
    ) -> None:
        if redis is None:
            raise RuntimeError("redis package is not installed")
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
        except Exception as exc:
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


class HybridRateLimiter:
    def __init__(
        self,
        redis_limiter: Optional[RedisFixedWindowRateLimiter],
        fallback_limiter: InMemoryRateLimiter,
    ) -> None:
        self._redis_limiter = redis_limiter
        self._fallback_limiter = fallback_limiter
        self._last_warning = 0.0

    def hit(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        fallback_mode: str = "memory",
    ) -> RateLimitHitResult:
        mode = (fallback_mode or "memory").strip().lower()
        if mode not in {"memory", "deny", "allow"}:
            mode = "memory"

        if self._redis_limiter is not None:
            try:
                return self._redis_limiter.hit(key, limit=limit, window_seconds=window_seconds)
            except HTTPException:
                raise
            except Exception as exc:
                now = time.monotonic()
                if now - self._last_warning > 30:
                    logger.warning("Redis rate limiter unavailable, falling back: %s", type(exc).__name__)
                    self._last_warning = now
                _record_fallback_event(mode, type(exc).__name__)
                if mode == "deny":
                    return RateLimitHitResult(False, 0, int(window_seconds), "redis-fallback-deny", True)
                if mode == "allow":
                    return RateLimitHitResult(True, max(0, int(limit)), 0, "redis-fallback-allow", True)

        return self._fallback_limiter.hit(key, limit=limit, window_seconds=window_seconds)


def _record_fallback_event(mode: str, reason: str) -> None:
    global _rate_limit_fallback_total
    with _fallback_lock:
        _rate_limit_fallback_total += 1
        _rate_limit_fallback_by_mode[mode] = _rate_limit_fallback_by_mode.get(mode, 0) + 1
    logger.warning(
        "rate_limit_fallback_event total=%s mode=%s reason=%s",
        _rate_limit_fallback_total,
        mode,
        reason,
    )


def _build_rate_limiter() -> HybridRateLimiter:
    backend = (os.getenv("RATE_LIMIT_BACKEND", "auto") or "auto").strip().lower()
    redis_url = (os.getenv("RATE_LIMIT_REDIS_URL", "") or "").strip()

    fallback = InMemoryRateLimiter(
        gc_every=config.RATE_LIMIT_GC_EVERY,
        stale_after_seconds=config.RATE_LIMIT_STALE_AFTER_SECONDS,
        max_states=config.RATE_LIMIT_MAX_STATES,
    )

    if backend in {"memory", "in-memory", "inmemory"}:
        return HybridRateLimiter(None, fallback)

    if not redis_url:
        if backend == "redis":
            logger.warning("RATE_LIMIT_BACKEND=redis but RATE_LIMIT_REDIS_URL is not set; using in-memory limiter")
        if config.IS_PRODUCTION:
            logger.warning("Using in-memory rate limiter in production. Configure Redis for multi-instance safety.")
        return HybridRateLimiter(None, fallback)

    try:
        redis_limiter = RedisFixedWindowRateLimiter(
            redis_url,
            socket_timeout=float(os.getenv("RATE_LIMIT_REDIS_TIMEOUT", "1.0")),
            max_connections=int(os.getenv("RATE_LIMIT_REDIS_MAX_CONNECTIONS", "50")),
        )
        logger.info("Using Redis-backed rate limiter")
        return HybridRateLimiter(redis_limiter, fallback)
    except Exception as exc:
        logger.warning("Failed to initialize Redis rate limiter, using in-memory fallback: %s", exc)
        if config.IS_PRODUCTION:
            logger.warning("Redis rate limiting failed in production; rate limiting is process-local only")
        return HybridRateLimiter(None, fallback)


rate_limiter = _build_rate_limiter()


def client_ip(request: Request) -> str:
    def _trusted_proxy_peer() -> bool:
        if not config.TRUST_PROXY_HEADERS:
            return False
        trusted_cidrs = getattr(config, "TRUSTED_PROXY_CIDRS", []) or []
        if not trusted_cidrs:
            return True

        direct = (request.client.host if request.client else "").strip()
        validated = _valid_ip(direct)
        if not validated:
            return False

        try:
            peer_ip = ip_address(validated)
            for cidr in trusted_cidrs:
                try:
                    if peer_ip in ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    continue
        except ValueError:
            return False
        return False

    if _trusted_proxy_peer():
        forwarded_for = (request.headers.get("x-forwarded-for") or "").strip()
        if forwarded_for:
            first = forwarded_for.split(",", 1)[0].strip()
            valid_first = _valid_ip(first)
            if valid_first:
                return valid_first

        real_ip = (request.headers.get("x-real-ip") or "").strip()
        valid_real_ip = _valid_ip(real_ip)
        if valid_real_ip:
            return valid_real_ip

    direct = (request.client.host if request.client else "unknown").strip()
    return _valid_ip(direct) or "unknown"


def enforce_rate_limit(
    *,
    key: str,
    limit: int,
    window_seconds: int,
    fallback_mode: Optional[str] = None,
) -> None:
    result = rate_limiter.hit(
        key,
        limit=limit,
        window_seconds=window_seconds,
        fallback_mode=fallback_mode or config.RATE_LIMIT_FALLBACK_MODE,
    )
    if result.allowed:
        return
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many requests",
        headers={"Retry-After": str(result.retry_after_seconds)},
    )


def enforce_ip_rate_limit(
    request: Request,
    *,
    scope: str,
    limit: int,
    window_seconds: int,
    fallback_mode: Optional[str] = None,
) -> None:
    ip = client_ip(request)
    if ip == "unknown":
        fingerprint_source = "|".join([
            request.headers.get("user-agent", ""),
            request.headers.get("x-forwarded-for", ""),
            request.headers.get("x-real-ip", ""),
            request.headers.get("host", ""),
            scope,
        ])
        fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()[:24]
        ip = f"unknown-{fingerprint}"
        logger.warning("Client IP could not be resolved for scope=%s; applying strict unknown-IP bucket", scope)

    enforce_rate_limit(
        key=f"ip:{ip}:{scope}",
        limit=limit,
        window_seconds=window_seconds,
        fallback_mode=fallback_mode,
    )
