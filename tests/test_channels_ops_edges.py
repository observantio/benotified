"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from services.alerting import channels_ops


class FakeResponse:
    def __init__(self, payload=None, status_code=200):
        self._payload = payload or {}
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "bad status",
                request=httpx.Request("GET", "https://example.test"),
                response=httpx.Response(self.status_code, request=httpx.Request("GET", "https://example.test")),
            )


@pytest.mark.asyncio
async def test_notify_for_alerts_covers_skip_suppressed_and_dispatch_paths(monkeypatch):
    sent = []
    service = SimpleNamespace(logger=SimpleNamespace(info=lambda *_args, **_kwargs: None, debug=lambda *_args, **_kwargs: None))
    storage_service = SimpleNamespace()
    notification_service = SimpleNamespace()

    matched_rule = SimpleNamespace(
        id="rule-1",
        group="infra",
        created_by="owner",
        name="CPUHigh",
        annotations={"createdByUsername": "alice", "productName": "payments"},
    )

    channels = [SimpleNamespace(name="email"), SimpleNamespace(name="slack")]
    storage_service.get_notification_channels_for_rule_name = lambda *_args, **_kwargs: channels
    storage_service.get_alert_rule_by_name_for_delivery = lambda *_args, **_kwargs: matched_rule

    async def fake_send_notification(channel, alert_model, action):
        sent.append((channel.name, alert_model, action))
        return True

    notification_service.send_notification = fake_send_notification
    monkeypatch.setattr(channels_ops, "is_suppressed_status", lambda raw_status: raw_status == {"state": "suppressed"})

    alerts = [
        {},
        {"labels": {"alertname": "CPUHigh"}, "status": {"state": "suppressed"}},
        {
            "labels": {"alertname": "CPUHigh", "org_id": "org-1"},
            "annotations": {"summary": "CPU > 90"},
            "status": {"state": "active", "silencedBy": ["s1"], "inhibitedBy": ["i1"]},
            "startsAt": "2024-01-01T00:00:00Z",
            "endsAt": "2024-01-01T01:00:00Z",
            "generatorURL": "https://grafana",
            "fingerprint": "fp-1",
        },
        {
            "labels": {"alertname": "CPUHigh"},
            "annotations": {},
            "status": "resolved",
            "generatorURL": "https://grafana",
        },
    ]

    await channels_ops.notify_for_alerts(service, "tenant", alerts, storage_service, notification_service)
    assert len(sent) == 4
    assert sent[0][2] == "firing"
    assert sent[0][1].annotations["beobservantCorrelationId"] == "infra"
    assert sent[0][1].annotations["beobservantCreatedByUsername"] == "alice"
    assert sent[0][1].annotations["beobservantProductName"] == "payments"
    assert sent[2][2] == "resolved"

    storage_service.get_notification_channels_for_rule_name = lambda *_args, **_kwargs: []
    await channels_ops.notify_for_alerts(service, "tenant", alerts, storage_service, notification_service)


@pytest.mark.asyncio
async def test_channels_status_and_receivers_helpers(monkeypatch):
    service = SimpleNamespace(_client=SimpleNamespace(), alertmanager_url="https://alertmanager")

    async def fake_get_status(*_args, **_kwargs):
        return FakeResponse(
            payload={
                "cluster": {"name": "am"},
                "config": {"receivers": [{"name": "default"}, {"name": "ops"}, {"name": None}, "bad"]},
                    "version": "1.0.0",
                "versionInfo": {},
                    "configHash": "hash-1",
                "uptime": "1h",
            }
        )

    monkeypatch.setattr(service._client, "get", fake_get_status, raising=False)
    status = await channels_ops.get_status(service)
    assert status is not None
    assert await channels_ops.get_receivers(service) == ["default", "ops"]

    async def raise_http_error(*_args, **_kwargs):
        raise httpx.RequestError("boom", request=httpx.Request("GET", "https://example.test"))

    monkeypatch.setattr(service._client, "get", raise_http_error, raising=False)
    assert await channels_ops.get_status(service) is None
    assert await channels_ops.get_receivers(service) == []


def test_channels_small_helpers_cover_string_normalization(monkeypatch):
    monkeypatch.setattr(channels_ops, "is_suppressed_status", lambda raw_status: raw_status == {"state": "suppressed"})
    assert channels_ops._is_suppressed({"state": "suppressed"}) is True
    assert channels_ops._string_dict({"a": 1, "b": None}) == {"a": "1"}
    assert channels_ops._string_dict([]) == {}
    assert channels_ops._string_list([1, "", "x"]) == ["1", "x"]
    assert channels_ops._string_list("bad") == []
    assert channels_ops._optional_string("  x ") == "x"
    assert channels_ops._optional_string(None) is None