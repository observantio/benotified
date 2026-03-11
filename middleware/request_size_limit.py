"""
Request size limiting middleware.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import logging

from starlette.types import ASGIApp, Message, Receive, Scope, Send
from starlette.responses import PlainTextResponse

logger = logging.getLogger(__name__)

_request_size_rejections_total = 0


def _inc_request_size_rejections() -> int:
    global _request_size_rejections_total
    _request_size_rejections_total += 1
    return _request_size_rejections_total


class _TooLarge(Exception):
    def __init__(self, max_bytes: int) -> None:
        super().__init__(f"Request body exceeds {max_bytes} bytes")
        self.max_bytes = max_bytes


class RequestSizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int = 1_048_576) -> None:
        self.app = app
        self.max_bytes = int(max_bytes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }
        content_length = headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    total = _inc_request_size_rejections()
                    logger.warning(
                        "request_size_rejected total=%s content_length=%s max_bytes=%s",
                        total,
                        content_length,
                        self.max_bytes,
                    )
                    resp = PlainTextResponse("Request body too large", status_code=413)
                    await resp(scope, receive, send)
                    return
            except ValueError:
                logger.warning("Invalid content-length header value: %r", content_length)

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body") or b""
                received += len(body)
                if received > self.max_bytes:
                    raise _TooLarge(self.max_bytes)
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _TooLarge:
            total = _inc_request_size_rejections()
            logger.warning("request_size_rejected total=%s max_bytes=%s", total, self.max_bytes)
            if not response_started:
                resp = PlainTextResponse("Request body too large", status_code=413)
                await resp(scope, receive, send)
