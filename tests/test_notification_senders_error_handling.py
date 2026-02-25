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

from services.notification import senders, transport
from models.alerting.alerts import Alert, AlertStatus


def _make_alert():
    return Alert(labels={"alertname": "A", "severity": "critical"}, annotations={}, startsAt="2023-01-01T00:00:00Z", status=AlertStatus(state="active"), fingerprint="fp")


def test_send_webhook_handles_http_status_error(monkeypatch):
    async def fake_post(client, url, json=None, headers=None, params=None):
        req = httpx.Request("POST", url)
        resp = httpx.Response(405, request=req)
        raise httpx.HTTPStatusError("Client error", request=req, response=resp)

    monkeypatch.setattr(transport, "post_with_retry", fake_post)
    client = httpx.AsyncClient()
    channel = {"url": "https://google.com"}
    res = asyncio.run(senders.send_webhook(client, channel, _make_alert(), "firing"))
    assert res is False


def test_send_webhook_handles_request_error(monkeypatch):
    async def fake_post(client, url, json=None, headers=None, params=None):
        raise httpx.RequestError("network down")

    monkeypatch.setattr(transport, "post_with_retry", fake_post)
    client = httpx.AsyncClient()
    channel = {"url": "https://example.com"}
    res = asyncio.run(senders.send_webhook(client, channel, _make_alert(), "firing"))
    assert res is False
