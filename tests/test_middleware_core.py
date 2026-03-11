"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from tests._env import ensure_test_env

ensure_test_env()

from middleware.concurrency_limit import ConcurrencyLimitMiddleware
from middleware.error_handlers import general_exception_handler, handle_route_errors, validation_exception_handler
from middleware.headers import _is_https_request, security_headers_middleware
from middleware.request_size_limit import RequestSizeLimitMiddleware


def _request(path: str = "/", headers: list[tuple[bytes, bytes]] | None = None, scheme: str = "http") -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": path,
            "headers": headers or [],
            "client": ("127.0.0.1", 1234),
            "scheme": scheme,
            "query_string": b"",
        }
    )


@pytest.mark.asyncio
async def test_handle_route_errors_variants():
    @handle_route_errors(bad_request_detail="bad")
    async def bad_request() -> str:
        raise ValueError("ignored")

    @handle_route_errors(bad_gateway_detail="upstream")
    async def bad_gateway() -> str:
        raise httpx.ReadError("boom")

    @handle_route_errors(internal_detail=None)
    async def raw_internal() -> str:
        raise RuntimeError("raw")

    @handle_route_errors()
    async def passthrough() -> str:
        raise HTTPException(status_code=409, detail="conflict")

    with pytest.raises(HTTPException) as bad_req_exc:
        await bad_request()
    assert bad_req_exc.value.status_code == 400
    assert bad_req_exc.value.detail == "bad"

    with pytest.raises(HTTPException) as bad_gateway_exc:
        await bad_gateway()
    assert bad_gateway_exc.value.status_code == 502
    assert bad_gateway_exc.value.detail == "upstream"

    with pytest.raises(RuntimeError):
        await raw_internal()

    with pytest.raises(HTTPException) as passthrough_exc:
        await passthrough()
    assert passthrough_exc.value.status_code == 409


@pytest.mark.asyncio
async def test_error_handlers_and_security_headers():
    validation_response = validation_exception_handler(
        _request("/invalid"),
        type("Exc", (), {"errors": lambda self=None: [{"msg": "invalid"}]})(),
    )
    assert validation_response.status_code == 422
    assert json.loads(validation_response.body.decode("utf-8"))["detail"][0]["msg"] == "invalid"

    general_response = general_exception_handler(_request("/boom"), RuntimeError("boom"))
    assert general_response.status_code == 500
    assert json.loads(general_response.body.decode("utf-8"))["detail"] == "Internal server error"

    async def call_next(_request: Request) -> Response:
        return PlainTextResponse("ok")

    http_request = _request("/headers")
    https_request = _request("/headers", headers=[(b"x-forwarded-proto", b"https")])

    assert _is_https_request(http_request) is False
    assert _is_https_request(https_request) is True

    http_response = await security_headers_middleware(http_request, call_next)
    https_response = await security_headers_middleware(https_request, call_next)

    assert http_response.headers["X-Frame-Options"] == "DENY"
    assert "Strict-Transport-Security" not in http_response.headers
    assert https_response.headers["Strict-Transport-Security"].startswith("max-age=")


@pytest.mark.asyncio
async def test_request_size_limit_middleware_paths():
    sent_messages = []

    async def app(scope, receive, send):
        while True:
            message = await receive()
            if not message.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    middleware = RequestSizeLimitMiddleware(app, max_bytes=4)

    async def receive_small():
        return {"type": "http.request", "body": b"ok", "more_body": False}

    async def send(message):
        sent_messages.append(message)

    await middleware({"type": "http", "headers": []}, receive_small, send)
    assert sent_messages[0]["type"] == "http.response.start"

    sent_messages.clear()
    await middleware(
        {"type": "http", "headers": [(b"content-length", b"10")]},
        receive_small,
        send,
    )
    assert sent_messages[0]["status"] == 413

    sent_messages.clear()
    await middleware(
        {"type": "http", "headers": [(b"content-length", b"bad")]},
        receive_small,
        send,
    )
    assert sent_messages[0]["type"] == "http.response.start"

    sent_messages.clear()
    chunks = iter(
        [
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.request", "body": b"de", "more_body": False},
        ]
    )

    async def receive_large_stream():
        return next(chunks)

    await middleware({"type": "http", "headers": []}, receive_large_stream, send)
    assert sent_messages[0]["status"] == 413


@pytest.mark.asyncio
async def test_concurrency_limit_middleware_paths(monkeypatch):
    sent_messages = []

    async def send(message):
        sent_messages.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    middleware = ConcurrencyLimitMiddleware(app, max_concurrent=1, acquire_timeout=0.01)
    await middleware({"type": "http", "headers": []}, receive, send)
    assert middleware._sem is not None
    assert sent_messages[0]["status"] == 200

    sent_messages.clear()

    async def timeout_wait_for(awaitable, timeout):
        awaitable.close()
        raise asyncio.TimeoutError()

    monkeypatch.setattr(asyncio, "wait_for", timeout_wait_for)
    await middleware({"type": "http", "headers": []}, receive, send)
    assert sent_messages[0]["status"] == 503

    sent_messages.clear()
    await middleware({"type": "lifespan"}, receive, send)
    assert sent_messages[0]["status"] == 200