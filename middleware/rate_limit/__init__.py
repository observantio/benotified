"""
Rate limiting primitives and helpers.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Optional

from fastapi import HTTPException, Request, status

from config import config

from .hybrid import HybridRateLimiter
from .in_memory import InMemoryRateLimiter
from .ip import client_ip
from .models import RateLimitHitResult, RateLimitState
from .redis_fixed_window import RedisFixedWindowRateLimiter

logger = logging.getLogger(__name__)


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
    except (ConnectionError, ImportError, OSError, RuntimeError, TimeoutError, ValueError) as exc:
        logger.warning("Failed to initialize Redis rate limiter, using in-memory fallback: %s", exc)
        if config.IS_PRODUCTION:
            logger.warning("Redis rate limiting failed in production; rate limiting is process-local only")
        return HybridRateLimiter(None, fallback)


rate_limiter = _build_rate_limiter()


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
        fingerprint_source = "|".join(
            [
                request.headers.get("user-agent", ""),
                request.headers.get("x-forwarded-for", ""),
                request.headers.get("x-real-ip", ""),
                request.headers.get("host", ""),
                scope,
            ]
        )
        fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()[:24]
        ip = f"unknown-{fingerprint}"
        logger.warning("Client IP could not be resolved for scope=%s; applying strict unknown-IP bucket", scope)

    enforce_rate_limit(
        key=f"ip:{ip}:{scope}",
        limit=limit,
        window_seconds=window_seconds,
        fallback_mode=fallback_mode,
    )


__all__ = [
    "RateLimitState",
    "RateLimitHitResult",
    "InMemoryRateLimiter",
    "RedisFixedWindowRateLimiter",
    "HybridRateLimiter",
    "client_ip",
    "enforce_rate_limit",
    "enforce_ip_rate_limit",
    "rate_limiter",
]
