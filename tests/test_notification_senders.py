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


def test_send_slack_calls_transport(monkeypatch):
    called = {}

    async def fake_post(client, url, json=None, headers=None, params=None):
        called['url'] = url
        called['json'] = json
        return httpx.Response(200)

    monkeypatch.setattr(transport, "post_with_retry", fake_post)
    client = httpx.AsyncClient()
    channel = {"webhook_url": "https://hooks.slack.com/services/test"}
    res = asyncio.run(senders.send_slack(client, channel, _make_alert(), "firing"))
    assert res is True
    assert called['url'] == channel['webhook_url']


def test_send_slack_invalid_url_returns_false():
    client = httpx.AsyncClient()
    channel = {"webhook_url": "ftp://bad.example.com"}
    res = asyncio.run(senders.send_slack(client, channel, _make_alert(), "firing"))
    assert res is False


def test_send_webhook_and_pagerduty(monkeypatch):
    calls = []

    async def fake_post(client, url, json=None, headers=None, params=None):
        calls.append((url, json, headers))
        return httpx.Response(200)

    monkeypatch.setattr(transport, "post_with_retry", fake_post)
    client = httpx.AsyncClient()
    channel = {"url": "https://example.com/h"}
    assert asyncio.run(senders.send_webhook(client, channel, _make_alert(), "firing")) is True
    assert calls[-1][0] == "https://example.com/h"
    channel2 = {"routing_key": "rk"}
    assert asyncio.run(senders.send_pagerduty(client, channel2, _make_alert(), "resolved")) is True
    assert calls[-1][0] == "https://events.pagerduty.com/v2/enqueue"
    assert asyncio.run(senders.send_pagerduty(client, {}, _make_alert(), "firing")) is False
