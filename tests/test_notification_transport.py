"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env
ensure_test_env()

import asyncio
import httpx
import aiosmtplib

from services.notification import transport


def test_is_transient_http_exception():
    assert transport.is_transient_http_exception(httpx.RequestError("x")) is True
    assert transport.is_transient_http_exception(httpx.HTTPStatusError("err", request=None, response=httpx.Response(500))) is True
    assert transport.is_transient_http_exception(httpx.HTTPStatusError("err", request=None, response=httpx.Response(404))) is False
    assert transport.is_transient_http_exception(Exception("nope")) is False


def test_post_with_retry_success():
    class DummyClient:
        async def post(self, url, json=None, headers=None, params=None, **kwargs):
            
            return httpx.Response(200, request=httpx.Request("POST", url))

    client = DummyClient()
    resp = asyncio.run(transport.post_with_retry(client, "https://example.com", json={"a": 1}))
    assert isinstance(resp, httpx.Response)
    assert resp.status_code == 200


def test_post_with_retry_retries_on_transient_error():
    class FlakyClient:
        def __init__(self):
            self.calls = 0

        async def post(self, url, json=None, headers=None, params=None, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise httpx.RequestError("transient")
            return httpx.Response(200, request=httpx.Request("POST", url))

    client = FlakyClient()
    resp = asyncio.run(transport.post_with_retry(client, "https://example.com", json={}))
    assert isinstance(resp, httpx.Response)
    assert resp.status_code == 200


def test_send_smtp_with_retry_calls_aiosmtplib(monkeypatch):
    called = {}

    async def fake_send(*args, **kwargs):
        called['args'] = args
        called['kwargs'] = kwargs
        return "ok"

    monkeypatch.setattr(aiosmtplib, "send", fake_send)

    result = asyncio.run(transport.send_smtp_with_retry(message="m", hostname="h", port=25, username=None, password=None, start_tls=False, use_tls=False, timeout=5))
    assert result == "ok"
    assert called['kwargs']['hostname'] == "h"
