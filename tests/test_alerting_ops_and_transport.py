"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from email.message import EmailMessage
from types import SimpleNamespace

import httpx
import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.access.auth_models import Role, TokenData
from models.alerting.alerts import Alert
from models.alerting.rules import AlertRule
from services.alerting import alerts_ops, rules_ops
from services.notification import transport as transport_mod


class FakeResponse:
    def __init__(self, *, status_code=200, payload=None, text="", request=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text
        self.request = request or httpx.Request("GET", "https://example.test")

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("bad status", request=self.request, response=self)


def _current_user(**kwargs) -> TokenData:
    payload = {
        "user_id": "u1",
        "username": "user",
        "tenant_id": "tenant",
        "org_id": "org-1",
        "role": Role.ADMIN,
        "permissions": ["read:rules"],
    }
    payload.update(kwargs)
    return TokenData(**payload)


@pytest.mark.asyncio
async def test_alerts_ops_cover_success_and_failure_branches(monkeypatch):
    service = SimpleNamespace(
        _mimir_client=SimpleNamespace(),
        _client=SimpleNamespace(),
        alertmanager_url="https://alertmanager",
        logger=SimpleNamespace(error=lambda *_args, **_kwargs: None, warning=lambda *_args, **_kwargs: None),
    )

    async def fake_mimir_get(*_args, **_kwargs):
        return FakeResponse(payload={"status": "success", "data": ["up", "http_requests_total"]})

    monkeypatch.setattr(service._mimir_client, "get", fake_mimir_get, raising=False)
    assert await alerts_ops.list_metric_names(service, "org-1") == ["up", "http_requests_total"]

    async def fake_mimir_get_bad(*_args, **_kwargs):
        return FakeResponse(payload={"status": "error"})

    monkeypatch.setattr(service._mimir_client, "get", fake_mimir_get_bad, raising=False)
    with pytest.raises(httpx.HTTPStatusError):
        await alerts_ops.list_metric_names(service, "org-1")

    async def fake_alert_get(*_args, **_kwargs):
        return FakeResponse(payload=[{"labels": {"alertname": "CPUHigh"}, "annotations": {}, "status": {"state": "active"}, "startsAt": "2024-01-01T00:00:00Z", "endsAt": "2024-01-01T01:00:00Z", "generatorURL": "https://grafana"}])

    monkeypatch.setattr(service._client, "get", fake_alert_get, raising=False)
    alerts = await alerts_ops.get_alerts(service, {"service": "api"}, active=True, silenced=False, inhibited=False)
    assert alerts[0].labels["alertname"] == "CPUHigh"

    async def fake_group_get(*_args, **_kwargs):
        return FakeResponse(payload=[{"labels": {"service": "api"}, "receiver": "default", "alerts": []}])

    monkeypatch.setattr(service._client, "get", fake_group_get, raising=False)
    groups = await alerts_ops.get_alert_groups(service, {"service": "api"})
    assert groups[0].labels["service"] == "api"

    async def fake_post(*_args, **_kwargs):
        return FakeResponse(status_code=200)

    monkeypatch.setattr(service._client, "post", fake_post, raising=False)
    assert await alerts_ops.post_alerts(
        service,
        [Alert(labels={"alertname": "CPUHigh"}, annotations={}, status={"state": "active"}, startsAt="2024-01-01T00:00:00Z", endsAt="2024-01-01T01:00:00Z", generatorURL="https://grafana")],
    ) is True

    async def raise_http_error(*_args, **_kwargs):
        raise httpx.RequestError("boom", request=httpx.Request("GET", "https://example.test"))

    monkeypatch.setattr(service._client, "get", raise_http_error, raising=False)
    monkeypatch.setattr(service._client, "post", raise_http_error, raising=False)
    assert await alerts_ops.get_alerts(service) == []
    assert await alerts_ops.get_alert_groups(service) == []
    assert await alerts_ops.post_alerts(service, []) is False

    async def fake_create_silence(_silence):
        return "sil-1"

    async def fake_create_silence_none(_silence):
        return None

    assert await alerts_ops.delete_alerts(service, None) is False
    service.create_silence = fake_create_silence
    assert await alerts_ops.delete_alerts(service, {"service": "api"}) is True
    service.create_silence = fake_create_silence_none
    assert await alerts_ops.delete_alerts(service, {"service": "api"}) is False


@pytest.mark.asyncio
async def test_rules_ops_cover_org_resolution_and_sync(monkeypatch):
    service = SimpleNamespace(
        _mimir_client=SimpleNamespace(),
        MIMIR_RULES_NAMESPACE="tenant/rules",
        MIMIR_RULER_CONFIG_BASEPATH="/ruler/v1/rules",
        _group_enabled_rules=lambda rules: {"infra": rules[:1], "apps": rules[1:]},
        _extract_mimir_group_names=lambda text: ["infra", "stale"],
        _build_ruler_group_yaml=lambda name, rules: f"group: {name} count={len(rules)}",
    )

    assert rules_ops.resolve_rule_org_id("rule-org", _current_user()) == "rule-org"
    assert rules_ops.resolve_rule_org_id(None, _current_user(org_id="user-org")) == "user-org"

    rules = [
        AlertRule.model_validate({"name": "CPUHigh", "expression": "up == 0", "severity": "critical", "groupName": "infra"}),
        AlertRule.model_validate({"name": "Latency", "expression": "latency > 1", "severity": "warning", "groupName": "apps"}),
    ]

    calls = []

    async def fake_get(*_args, **_kwargs):
        return FakeResponse(status_code=200, text="groups")

    async def fake_delete(url, **_kwargs):
        calls.append(("delete", url))
        return FakeResponse(status_code=204)

    async def fake_post(url, **kwargs):
        calls.append(("post", url, kwargs["content"]))
        return FakeResponse(status_code=202)

    monkeypatch.setattr(service._mimir_client, "get", fake_get, raising=False)
    monkeypatch.setattr(service._mimir_client, "delete", fake_delete, raising=False)
    monkeypatch.setattr(service._mimir_client, "post", fake_post, raising=False)
    await rules_ops.sync_mimir_rules_for_org(service, "org-1", rules)
    assert calls[0][0] == "delete"
    assert calls[1][0] == "post"

    async def fake_get_404(*_args, **_kwargs):
        return FakeResponse(status_code=404)

    monkeypatch.setattr(service._mimir_client, "get", fake_get_404, raising=False)
    await rules_ops.sync_mimir_rules_for_org(service, "org-1", rules)

    async def fake_get_error(*_args, **_kwargs):
        raise httpx.RequestError("boom", request=httpx.Request("GET", "https://example.test"))

    monkeypatch.setattr(service._mimir_client, "get", fake_get_error, raising=False)
    await rules_ops.sync_mimir_rules_for_org(service, "org-1", rules)

    async def bad_delete(*_args, **_kwargs):
        return FakeResponse(status_code=500)

    monkeypatch.setattr(service._mimir_client, "get", fake_get, raising=False)
    monkeypatch.setattr(service._mimir_client, "delete", bad_delete, raising=False)
    with pytest.raises(httpx.HTTPStatusError):
        await rules_ops.sync_mimir_rules_for_org(service, "org-1", rules)

    async def bad_post(*_args, **_kwargs):
        return FakeResponse(status_code=500)

    monkeypatch.setattr(service._mimir_client, "delete", fake_delete, raising=False)
    monkeypatch.setattr(service._mimir_client, "post", bad_post, raising=False)
    with pytest.raises(httpx.HTTPStatusError):
        await rules_ops.sync_mimir_rules_for_org(service, "org-1", rules)


@pytest.mark.asyncio
async def test_transport_helpers_cover_transient_checks_and_send_paths(monkeypatch):
    req = httpx.Request("POST", "https://example.test")
    res_500 = httpx.Response(500, request=req)
    res_400 = httpx.Response(400, request=req)
    assert transport_mod._is_transient_http(httpx.RequestError("boom", request=req), transport_mod.DEFAULT_RETRY_ON_STATUS) is True
    assert transport_mod._is_transient_http(httpx.HTTPStatusError("bad", request=req, response=res_500), transport_mod.DEFAULT_RETRY_ON_STATUS) is True
    assert transport_mod._is_transient_http(httpx.HTTPStatusError("bad", request=req, response=res_400), transport_mod.DEFAULT_RETRY_ON_STATUS) is False

    class FakeSMTPError(transport_mod.aiosmtplib.errors.SMTPException):
        def __init__(self, code):
            super().__init__("smtp")
            self.code = code

    assert transport_mod._is_transient_smtp(FakeSMTPError(450)) is True
    assert transport_mod._is_transient_smtp(FakeSMTPError(550)) is False

    monkeypatch.setattr(transport_mod.config, "MAX_RETRIES", 1)
    monkeypatch.setattr(transport_mod.config, "RETRY_BACKOFF", 0)
    monkeypatch.setattr(transport_mod.config, "DEFAULT_TIMEOUT", 1)

    class FakeClient:
        def __init__(self, response):
            self.response = response

        async def post(self, *_args, **_kwargs):
            return self.response

    response = FakeResponse(status_code=200)
    assert await transport_mod.post_with_retry(FakeClient(response), "https://example.test", json={"ok": True}) is response

    with pytest.raises(httpx.HTTPStatusError):
        await transport_mod.post_with_retry(FakeClient(FakeResponse(status_code=500)), "https://example.test")

    sent = []

    async def fake_send(**kwargs):
        sent.append(kwargs)
        return {"accepted": ["user@example.com"]}

    monkeypatch.setattr(transport_mod.aiosmtplib, "send", fake_send)
    message = EmailMessage()
    message["To"] = "user@example.com"
    assert (await transport_mod.send_smtp_with_retry(message, "smtp.example.com", 587))["accepted"] == ["user@example.com"]
    assert sent[0]["hostname"] == "smtp.example.com"