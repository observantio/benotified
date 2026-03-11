"""
Concurrency limiting middleware.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import PlainTextResponse

logger = logging.getLogger(__name__)

_concurrency_busy_total = 0


def _inc_concurrency_busy() -> int:
    global _concurrency_busy_total
    _concurrency_busy_total += 1
    return _concurrency_busy_total


class ConcurrencyLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        max_concurrent: int = 200,
        acquire_timeout: float = 1.0,
    ) -> None:
        self.app = app
        self._max_concurrent = int(max_concurrent)
        self._timeout = float(acquire_timeout)
        self._sem: Optional[asyncio.Semaphore] = None

    def _get_semaphore(self) -> asyncio.Semaphore:
        if self._sem is None:
            self._sem = asyncio.Semaphore(self._max_concurrent)
        return self._sem

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        try:
            await asyncio.wait_for(self._get_semaphore().acquire(), timeout=self._timeout)
        except asyncio.TimeoutError:
            total = _inc_concurrency_busy()
            logger.warning("concurrency_limit_busy total=%s timeout=%s", total, self._timeout)
            resp = PlainTextResponse("Server busy, please retry", status_code=503)
            await resp(scope, receive, send)
            return

        try:
            await self.app(scope, receive, send)
        finally:
            self._get_semaphore().release()
