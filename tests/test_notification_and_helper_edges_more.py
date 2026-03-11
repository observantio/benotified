"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.access.auth_models import Role, TokenData
from models.alerting.alerts import Alert, AlertState, AlertStatus
from models.alerting.incidents import AlertIncident, IncidentStatus
from services.alerting import rule_import_service, silence_metadata, suppression
from services.common import encryption, meta, url_utils
from services.jira import helpers as jira_helpers
from services.jira_service import JiraError
from services.notification import email_providers, payloads
from services.notification import senders, transport, validators


def _token_data() -> TokenData:
    return TokenData(
        user_id="user-1",
        username="alice",
        tenant_id="tenant-a",
        org_id="org-a",
        role=Role.ADMIN,
        permissions=["read:alerts"],
    )


def _alert() -> Alert:
    return Alert(
        labels={"alertname": "HighLatency"},
        annotations={"summary": "Latency increased"},
        startsAt="2026-01-01T00:00:00Z",
        endsAt=None,
        generatorURL="https://grafana.example.com/alert/1",
        status=AlertStatus(state=AlertState.ACTIVE, silencedBy=[], inhibitedBy=[]),
        receivers=["default"],
        fingerprint="fp-1",
    )


def _incident(jira_integration_id: str | None = None) -> AlertIncident:
    now = datetime.now(timezone.utc)
    return AlertIncident(
        id="inc-1",
        fingerprint="fp-1",
        alertName="HighLatency",
        severity="high",
        status=IncidentStatus.OPEN,
        labels={"service": "api"},
        annotations={},
        jiraIntegrationId=jira_integration_id,
        lastSeenAt=now,
        createdAt=now,
        updatedAt=now,
    )


def test_suppression_metadata_meta_and_url_helpers():
    assert suppression.is_suppressed_status({"state": "suppressed"}) is True
    assert suppression.is_suppressed_status({"silencedBy": ["id"]}) is True
    assert suppression.is_suppressed_status({"inhibitedBy": ["id"]}) is True
    assert suppression.is_suppressed_status({"state": "active"}) is False
    assert suppression.is_suppressed_status("suppressed") is True
    assert suppression.is_suppressed_status(None) is False

    encoded = silence_metadata.encode_silence_comment("hello", "group", ["g1", "g2"])
    decoded = silence_metadata.decode_silence_comment(encoded)
    assert decoded == {"comment": "hello", "visibility": "group", "shared_group_ids": ["g1", "g2"]}
    assert silence_metadata.normalize_visibility(None) == "private"
    invalid = f"{silence_metadata.SILENCE_META_PREFIX}{{bad-json}}"
    assert silence_metadata.decode_silence_comment(invalid)["visibility"] == "tenant"
    malformed = silence_metadata.encode_silence_comment("note", "tenant", ["x"]).replace('["x"]', '"x"')
    assert silence_metadata.decode_silence_comment(malformed)["shared_group_ids"] == []

    assert meta.parse_meta(None) == {}
    assert meta.parse_meta({meta.INCIDENT_META_KEY: {"shared_group_ids": ["g1"]}}) == {"shared_group_ids": ["g1"]}
    assert meta.parse_meta({meta.INCIDENT_META_KEY: '{"shared_group_ids": ["g1", ""]}'}) == {"shared_group_ids": ["g1", ""]}
    assert meta.parse_meta({meta.INCIDENT_META_KEY: "{"}) == {}
    assert meta._safe_group_ids({"shared_group_ids": ["g1", "", 1]}) == ["g1"]

    assert url_utils.is_safe_http_url("https://example.com/path") is True
    assert url_utils.is_safe_http_url("http://10.0.0.1") is False
    assert url_utils.is_safe_http_url("http://localhost") is False
    assert url_utils.is_safe_http_url("ftp://example.com") is False


def test_encryption_roundtrip_and_error_paths(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(encryption.app_config, "DATA_ENCRYPTION_KEY", key)
    encryption._get_fernet.cache_clear()

    encrypted = encryption.encrypt_config({"apiKey": "secret"})
    assert encryption.decrypt_config(encrypted) == {"apiKey": "secret"}
    assert encryption.decrypt_config({"plain": True}) == {"plain": True}

    class _FakeFernet:
        def decrypt(self, _payload):
            raise InvalidToken()

    monkeypatch.setattr(encryption, "_get_fernet", lambda: _FakeFernet())
    with pytest.raises(ValueError, match="wrong key"):
        encryption.decrypt_config({"__encrypted__": "abc"})

    class _ListFernet:
        def decrypt(self, _payload):
            return b"[]"

    monkeypatch.setattr(encryption, "_get_fernet", lambda: _ListFernet())
    with pytest.raises(ValueError, match="Failed to decrypt"):
        encryption.decrypt_config({"__encrypted__": "abc"})


@pytest.mark.asyncio
async def test_jira_helper_paths(monkeypatch):
    integration = {"id": "jira-1", "enabled": True}
    credentials = {"base_url": "https://tenant.atlassian.net", "auth_mode": "api_token"}
    monkeypatch.setattr(jira_helpers, "load_tenant_jira_integrations", lambda tenant_id: [integration])
    assert jira_helpers._find_integration("tenant-a", "jira-1") == integration
    assert jira_helpers._find_integration("tenant-a", "missing") is None

    monkeypatch.setattr(jira_helpers, "resolve_jira_integration", lambda *args, **kwargs: integration)
    monkeypatch.setattr(jira_helpers, "jira_integration_credentials", lambda item: credentials)
    monkeypatch.setattr(jira_helpers, "integration_is_usable", lambda item: True)
    monkeypatch.setattr(jira_helpers.jira_service, "list_projects", lambda **kwargs: _resolved([{"key": "OPS"}]))
    result = await jira_helpers.jira_projects_via_integration("tenant-a", "jira-1", _token_data())
    assert result == {"enabled": True, "projects": [{"key": "OPS"}]}

    monkeypatch.setattr(jira_helpers, "jira_integration_credentials", lambda item: {"base_url": "https://tenant.atlassian.net", "auth_mode": "bearer"})
    with pytest.raises(HTTPException) as cloud_exc:
        await jira_helpers.jira_projects_via_integration("tenant-a", "jira-1", _token_data())
    assert cloud_exc.value.status_code == 400

    def missing_integration(*args, **kwargs):
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(jira_helpers, "resolve_jira_integration", missing_integration)
    with pytest.raises(HTTPException) as not_found_exc:
        await jira_helpers.jira_projects_via_integration("tenant-a", "missing", _token_data())
    assert not_found_exc.value.status_code == 404

    monkeypatch.setattr(jira_helpers, "resolve_jira_integration", lambda *args, **kwargs: integration)
    monkeypatch.setattr(jira_helpers, "jira_integration_credentials", lambda item: credentials)
    monkeypatch.setattr(jira_helpers, "integration_is_usable", lambda item: False)
    assert await jira_helpers.jira_issue_types_via_integration("tenant-a", "jira-1", "OPS", _token_data()) == {
        "enabled": False,
        "issueTypes": [],
    }

    monkeypatch.setattr(jira_helpers, "integration_is_usable", lambda item: True)
    monkeypatch.setattr(
        jira_helpers.jira_service,
        "list_issue_types",
        lambda **kwargs: _raise(JiraError("jira down")),
    )
    with pytest.raises(HTTPException) as issue_type_exc:
        await jira_helpers.jira_issue_types_via_integration("tenant-a", "jira-1", "OPS", _token_data())
    assert issue_type_exc.value.status_code == 502

    monkeypatch.setattr(jira_helpers, "resolve_jira_integration", lambda *args, **kwargs: integration)
    monkeypatch.setattr(jira_helpers, "integration_is_usable", lambda item: True)
    monkeypatch.setattr(jira_helpers, "jira_integration_credentials", lambda item: {"base_url": "https://jira.example.com", "user": "u"})
    assert jira_helpers.resolve_incident_jira_credentials(_incident("jira-1"), "tenant-a", _token_data()) == {
        "base_url": "https://jira.example.com",
        "user": "u",
    }

    monkeypatch.setattr(jira_helpers, "jira_is_enabled_for_tenant", lambda tenant_id: True)
    monkeypatch.setattr(jira_helpers, "get_effective_jira_credentials", lambda tenant_id: {"base_url": "https://jira.example.com"})
    assert jira_helpers.resolve_incident_jira_credentials(_incident(None), "tenant-a", _token_data()) == {
        "base_url": "https://jira.example.com"
    }


def test_rule_import_and_validation_helpers():
    assert rule_import_service._as_str_map({"a": 1, "b": None}) == {"a": "1"}
    assert rule_import_service._as_str_map("bad") == {}

    parsed = rule_import_service.parse_rules_yaml(
        """
spec:
  groups:
    - name: api
      rules:
        - alert: HighLatency
          expr: up == 0
          labels:
            severity: invalid
          annotations:
            description: bad
          beobservant:
            visibility: public
            channels: [slack]
            sharedGroupIds: [g1, ""]
        - name: DiskFull
          expr: disk > 90
""",
        defaults={"enabled": False, "duration": "10m", "orgId": "org-1"},
    )
    assert parsed[0].severity == "warning"
    assert parsed[0].visibility == "public"
    assert parsed[0].notification_channels == ["slack"]
    assert parsed[0].shared_group_ids == ["g1"]
    assert parsed[0].org_id == "org-1"
    assert parsed[1].name == "DiskFull"

    with pytest.raises(rule_import_service.RuleImportError, match="YAML content is required"):
        rule_import_service.parse_rules_yaml("")
    with pytest.raises(rule_import_service.RuleImportError, match="YAML content is empty"):
        rule_import_service.parse_rules_yaml("null")
    with pytest.raises(rule_import_service.RuleImportError, match="Expected 'groups'"):
        rule_import_service.parse_rules_yaml("name: nope")
    with pytest.raises(rule_import_service.RuleImportError, match="No valid alert rules"):
        rule_import_service.parse_rules_yaml("groups:\n  - name: api\n    rules: []")


@pytest.mark.asyncio
async def test_email_providers_and_payload_helpers(monkeypatch):
    assert email_providers._is_valid_email("ops@example.com") is True
    assert email_providers._is_valid_email("invalid") is False
    with pytest.raises(ValueError, match="No valid recipient"):
        email_providers._sanitize_recipients(["bad", " "])

    msg = email_providers.build_smtp_message("Subject", "Body", "from@example.com", [" ops@example.com "])
    assert msg["To"] == "ops@example.com"

    request = httpx.Request("POST", "https://example.com")
    response = httpx.Response(400, request=request)

    async def raise_http_status(*args, **kwargs):
        raise httpx.HTTPStatusError("bad", request=request, response=response)

    async def raise_http_error(*args, **kwargs):
        raise httpx.RequestError("boom", request=request)

    async def raise_unexpected(*args, **kwargs):
        raise RuntimeError("oops")

    monkeypatch.setattr(email_providers.transport, "post_with_retry", raise_http_status)
    assert await email_providers.send_via_sendgrid(SimpleNamespace(), "key", "subj", "body", ["ops@example.com"], "from@example.com") is False
    monkeypatch.setattr(email_providers.transport, "post_with_retry", raise_http_error)
    assert await email_providers.send_via_resend(SimpleNamespace(), "key", "subj", "body", ["ops@example.com"], "from@example.com") is False
    monkeypatch.setattr(email_providers.transport, "send_smtp_with_retry", raise_unexpected)
    assert await email_providers.send_via_smtp(msg, "smtp.example.com", 587, None, None, False, False) is False
    with pytest.raises(ValueError, match="without TLS"):
        await email_providers.send_via_smtp(msg, "smtp.example.com", 25, "user", "pass", False, False)

    alert = _alert()
    assert payloads._status_text("test") == "TEST"
    assert payloads._status_text("resolved") == "RESOLVED"
    assert payloads._status_text("other") == "FIRING"
    assert payloads._fmt(None) == "unknown"
    assert payloads._alert_start_timestamp(alert) == 1767225600
    broken_alert = alert.model_copy(update={"starts_at": "not-a-date", "annotations": {"description": "Only description"}, "labels": {"alertname": "DiskFull", "severity": "info", "instance": "host-1"}})
    assert payloads._alert_start_timestamp(broken_alert) is None
    assert payloads.get_annotation(broken_alert, "missing") is None
    assert payloads.get_alert_text(broken_alert) == "Only description"
    assert payloads._context_value(alert, "missing") == ""
    assert payloads._human_context(alert) == []

    rich_alert = alert.model_copy(update={
        "labels": {
            "alertname": "CPUHigh",
            "severity": "warning",
            "instance": "host-1",
            "extra": "value",
            "group": "corr-1",
        },
        "annotations": {
            "summary": "CPU high",
            "description": "Investigate",
            "beobservantCreatedByUsername": "alice",
            "beobservantProductName": "api",
            "beobservantRuleName": "CPUHigh",
        },
    })
    assert payloads.get_alert_text(rich_alert) == "CPU high\nInvestigate"
    assert payloads._important_labels(rich_alert) == [("extra", "value"), ("instance", "host-1")]
    body = payloads.format_alert_body(rich_alert, "resolved")
    assert "Context:" in body
    assert "Labels:" in body

    slack_payload = payloads.build_slack_payload(broken_alert, "test")
    assert slack_payload["attachments"][0]["color"] == "warning"
    assert "ts" not in slack_payload["attachments"][0]
    teams_payload = payloads.build_teams_payload(rich_alert, "resolved")
    assert teams_payload["themeColor"] == "00FF00"
    pagerduty_payload = payloads.build_pagerduty_payload(rich_alert, "resolved", "routing")
    assert pagerduty_payload["event_action"] == "resolve"
    assert pagerduty_payload["payload"]["severity"] == "warning"


@pytest.mark.asyncio
async def test_notification_validators_senders_and_transport(monkeypatch):
    assert validators._as_bool(0) is False
    assert validators._as_bool(2) is True
    assert validators._as_text(123) == "123"
    assert validators._as_optional_url("  ") is None
    assert validators._as_int("22") == 22
    assert validators._as_int("nope") is None

    errors = validators.validate_channel_config("email", {"email_provider": "smtp", "smtp_port": "abc"})
    assert "recipient" in " ".join(errors)
    assert "smtp_port" in " ".join(errors)
    assert validators.validate_channel_config("email", {"to": "a@b.com", "email_provider": "unknown"}) == ["Unsupported email provider 'unknown'"]
    assert validators.validate_channel_config("slack", {"webhook_url": "http://localhost/hook"})
    assert validators.validate_channel_config("teams", {"webhook_url": "http://localhost/hook"})
    assert validators.validate_channel_config("webhook", {"url": "javascript:alert(1)"})
    assert validators.validate_channel_config("pagerduty", {}) == ["PagerDuty channel requires 'routing_key'"]

    assert senders._is_allowed_host("https://hooks.slack.com/services/x", allowed_hosts=senders.SLACK_ALLOWED_HOSTS) is True
    assert senders._is_allowed_host("https://tenant.webhook.office.com/x", allowed_suffixes=senders.TEAMS_ALLOWED_SUFFIXES) is True
    assert senders._is_allowed_host("bad-url", allowed_hosts=senders.SLACK_ALLOWED_HOSTS) is False
    assert senders._safe_headers({"Authorization": 1, "Bad": 2}) == {"Authorization": "1"}
    assert senders._string_value(1) == ""
    assert senders._serialize_alert(_alert())["generatorURL"] == "https://grafana.example.com/alert/1"
    generic = SimpleNamespace(labels={"a": "b"}, annotations={}, starts_at="start", ends_at=None, fingerprint="fp")
    assert senders._serialize_alert(generic)["fingerprint"] == "fp"

    class _Client:
        pass

    async def good_post(*args, **kwargs):
        return None

    async def status_post(*args, **kwargs):
        request = httpx.Request("POST", "https://example.com")
        response = httpx.Response(500, request=request)
        raise httpx.HTTPStatusError("bad", request=request, response=response)

    async def error_post(*args, **kwargs):
        raise httpx.RequestError("boom", request=httpx.Request("POST", "https://example.com"))

    monkeypatch.setattr(senders.transport, "post_with_retry", good_post)
    assert await senders._send_json(_Client(), "javascript:alert(1)", {"x": 1}) is False
    assert await senders._send_json(_Client(), "https://example.com/hook", {"x": 1}) is True
    monkeypatch.setattr(senders.transport, "post_with_retry", status_post)
    assert await senders._send_json(_Client(), "https://example.com/hook", {"x": 1}) is False
    monkeypatch.setattr(senders.transport, "post_with_retry", error_post)
    assert await senders._send_json(_Client(), "https://example.com/hook", {"x": 1}) is False

    monkeypatch.setattr(senders.payloads, "build_slack_payload", lambda alert, action: {"kind": "slack", "action": action})
    monkeypatch.setattr(senders.payloads, "build_teams_payload", lambda alert, action: {"kind": "teams", "action": action})
    monkeypatch.setattr(senders.payloads, "build_pagerduty_payload", lambda alert, action, routing_key: {"kind": "pd", "routing_key": routing_key})
    monkeypatch.setattr(senders.transport, "post_with_retry", good_post)
    assert await senders.send_slack(_Client(), {"webhook_url": "https://hooks.slack.com/services/x"}, _alert(), "fire") is True
    assert await senders.send_slack(_Client(), {"webhook_url": "https://example.com/hook"}, _alert(), "fire") is False
    assert await senders.send_teams(_Client(), {"webhook_url": "https://tenant.webhook.office.com/x"}, _alert(), "fire") is True
    assert await senders.send_webhook(_Client(), {"url": "https://example.com/hook", "headers": {"X-Custom-Header": 5, "Ignored": 2}}, _alert(), "fire") is True
    assert await senders.send_webhook(_Client(), {}, _alert(), "fire") is False
    assert await senders.send_pagerduty(_Client(), {}, _alert(), "fire") is False
    assert await senders.send_pagerduty(_Client(), {"routing_key": "rk"}, _alert(), "fire") is True

    request = httpx.Request("POST", "https://example.com")
    response = httpx.Response(503, request=request)
    assert transport._is_transient_http(httpx.RequestError("down", request=request), transport.DEFAULT_RETRY_ON_STATUS) is True
    assert transport._is_transient_http(httpx.HTTPStatusError("bad", request=request, response=response), transport.DEFAULT_RETRY_ON_STATUS) is True
    assert transport._is_transient_http(ValueError("x"), transport.DEFAULT_RETRY_ON_STATUS) is False

    class _SmtpTransient(Exception):
        code = 450

    class _SmtpPermanent(Exception):
        code = 550

    smtp_transient = transport.aiosmtplib.errors.SMTPException("temporary")
    smtp_transient.code = 450
    smtp_permanent = transport.aiosmtplib.errors.SMTPException("permanent")
    smtp_permanent.code = 550
    assert transport._is_transient_smtp(smtp_transient) is True
    assert transport._is_transient_smtp(smtp_permanent) is False

    async def fail_send(**kwargs):
        raise RuntimeError("smtp down")

    monkeypatch.setattr(transport.aiosmtplib, "send", fail_send)
    with pytest.raises(RuntimeError, match="smtp down"):
        await transport.send_smtp_with_retry(SimpleNamespace(), "smtp.example.com", 25)


async def _resolved(value):
    return value


async def _raise(exc: Exception):
    raise exc