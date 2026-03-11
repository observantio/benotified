"""
Hybrid rate limiter that uses Redis for distributed rate limiting and falls back to an in-memory limiter if Redis is unavailable.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from fastapi import HTTPException

from .in_memory import InMemoryRateLimiter
from .models import RateLimitHitResult
from .observability import record_fallback_event
from .redis_fixed_window import RedisFixedWindowRateLimiter

logger = logging.getLogger(__name__)


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
            except (ConnectionError, OSError, RuntimeError, TimeoutError, ValueError) as exc:
                now = time.monotonic()
                if now - self._last_warning > 30:
                    logger.warning("Redis rate limiter unavailable, falling back: %s", type(exc).__name__)
                    self._last_warning = now
                record_fallback_event(mode, type(exc).__name__)
                if mode == "deny":
                    return RateLimitHitResult(False, 0, int(window_seconds), "redis-fallback-deny", True)
                if mode == "allow":
                    return RateLimitHitResult(True, max(0, int(limit)), 0, "redis-fallback-allow", True)

        return self._fallback_limiter.hit(key, limit=limit, window_seconds=window_seconds)
