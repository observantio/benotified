"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.alerting.alerts import Alert, AlertState, AlertStatus
from models.alerting.channels import ChannelType, NotificationChannel
from services.common import encryption as enc_mod
from services import notification_service as notif_mod


def _alert() -> Alert:
    return Alert(
        labels={"alertname": "CPUHigh"},
        annotations={"summary": "High CPU"},
        startsAt="2024-01-01T00:00:00Z",
        status=AlertStatus(state=AlertState.ACTIVE),
    )


def _channel(**kwargs) -> NotificationChannel:
    payload = {
        "name": "ops",
        "type": ChannelType.EMAIL,
        "enabled": True,
        "config": {"to": "ops@example.com", "smtp_host": "smtp.example.com", "smtp_port": 587},
    }
    payload.update(kwargs)
    return NotificationChannel.model_validate(payload)


def test_encryption_roundtrip_and_failures(monkeypatch):
    key = Fernet.generate_key()
    enc_mod._get_fernet.cache_clear()
    monkeypatch.setattr(enc_mod.app_config, "DATA_ENCRYPTION_KEY", None, raising=False)
    with pytest.raises(RuntimeError):
        enc_mod._get_fernet()

    enc_mod._get_fernet.cache_clear()
    monkeypatch.setattr(enc_mod.app_config, "DATA_ENCRYPTION_KEY", b"bad", raising=False)
    with pytest.raises(RuntimeError):
        enc_mod._get_fernet()

    enc_mod._get_fernet.cache_clear()
    monkeypatch.setattr(enc_mod.app_config, "DATA_ENCRYPTION_KEY", key, raising=False)
    encrypted = enc_mod.encrypt_config({"token": "secret"})
    assert enc_mod.decrypt_config(encrypted) == {"token": "secret"}
    assert enc_mod.decrypt_config({"plain": True}) == {"plain": True}

    fernet = Fernet(key)
    bad_payload = {"__encrypted__": fernet.encrypt(b"[]").decode()}
    with pytest.raises(ValueError):
        enc_mod.decrypt_config(bad_payload)

    with pytest.raises(ValueError):
        enc_mod.decrypt_config({"__encrypted__": "bad-token"})


@pytest.mark.asyncio
async def test_notification_service_paths(monkeypatch):
    service = notif_mod.NotificationService()
    service._client = object()

    monkeypatch.delattr(notif_mod.notification_validators, "_as_bool", raising=False)
    assert service._as_bool("yes") is True
    monkeypatch.setattr(notif_mod.notification_validators, "validate_channel_config", lambda channel_type, channel_config: [channel_type])
    assert service.validate_channel_config("email", {}) == ["email"]

    disabled = _channel(enabled=False)
    assert await service.send_notification(disabled, _alert()) is False

    called = []

    async def fake_slack(channel, alert, action):
        called.append((channel.type, action))
        return True

    service._send_slack = fake_slack
    assert await service.send_notification(_channel(type=ChannelType.SLACK), _alert(), "resolved") is True
    assert called == [(ChannelType.SLACK, "resolved")]
    unknown_channel = SimpleNamespace(name="ops", type="unknown", enabled=True, config={})
    assert await service.send_notification(unknown_channel, _alert()) is False

    secrets = {
        "INCIDENT_ASSIGNMENT_EMAIL_ENABLED": "true",
        "INCIDENT_ASSIGNMENT_SMTP_HOST": "smtp.example.com",
        "INCIDENT_ASSIGNMENT_SMTP_PORT": "bad",
        "INCIDENT_ASSIGNMENT_FROM": "alerts@example.com",
        "INCIDENT_ASSIGNMENT_SMTP_STARTTLS": "true",
        "INCIDENT_ASSIGNMENT_SMTP_USE_SSL": "false",
    }
    monkeypatch.setattr(notif_mod.config, "DEFAULT_ADMIN_EMAIL", "admin@example.com", raising=False)
    monkeypatch.setattr(notif_mod.config, "get_secret", lambda key: secrets.get(key))

    smtp_calls = []

    async def fake_send_smtp_with_retry(**kwargs):
        smtp_calls.append(kwargs)
        return True

    monkeypatch.setattr(service, "_send_smtp_with_retry", fake_send_smtp_with_retry)
    assert await service.send_incident_assignment_email("user@example.com", "CPUHigh", "open", "critical", "alice") is True
    assert smtp_calls[0]["port"] == 587

    secrets["INCIDENT_ASSIGNMENT_EMAIL_ENABLED"] = "false"
    assert await service.send_incident_assignment_email("user@example.com", "CPUHigh", "open", "critical", "alice") is False
    secrets["INCIDENT_ASSIGNMENT_EMAIL_ENABLED"] = "true"
    secrets["INCIDENT_ASSIGNMENT_SMTP_HOST"] = ""
    assert await service.send_incident_assignment_email("user@example.com", "CPUHigh", "open", "critical", "alice") is False
    secrets["INCIDENT_ASSIGNMENT_SMTP_HOST"] = "smtp.example.com"

    async def failing_send_smtp_with_retry(**kwargs):
        raise TimeoutError("timeout")

    monkeypatch.setattr(service, "_send_smtp_with_retry", failing_send_smtp_with_retry)
    assert await service.send_incident_assignment_email("user@example.com", "CPUHigh", "open", "critical", "alice") is False


@pytest.mark.asyncio
async def test_notification_email_provider_paths(monkeypatch):
    service = notif_mod.NotificationService()
    service._client = object()
    monkeypatch.setattr(notif_mod.notification_payloads, "format_alert_body", lambda alert, action: f"{action}:{alert.labels['alertname']}")
    monkeypatch.setattr(notif_mod.config, "DEFAULT_ADMIN_EMAIL", "admin@example.com", raising=False)
    monkeypatch.setattr(notif_mod.notification_email, "build_smtp_message", lambda subject, body, from_addr, recipients: {"subject": subject, "body": body, "from": from_addr, "to": recipients})

    sendgrid_calls = []
    resend_calls = []
    smtp_calls = []

    async def fake_sendgrid(client, api_key, subject, body, recipients, from_addr):
        sendgrid_calls.append((api_key, recipients, from_addr))
        return True

    async def fake_resend(client, api_key, subject, body, recipients, from_addr):
        resend_calls.append((api_key, recipients, from_addr))
        return False

    async def fake_smtp(message, host, port, user, password, starttls, use_ssl):
        smtp_calls.append((message, host, port, user, password, starttls, use_ssl))
        return True

    monkeypatch.setattr(notif_mod.notification_email, "send_via_sendgrid", fake_sendgrid)
    monkeypatch.setattr(notif_mod.notification_email, "send_via_resend", fake_resend)
    monkeypatch.setattr(notif_mod.notification_email, "send_via_smtp", fake_smtp)

    assert await service._send_email(_channel(config={}), _alert(), "firing") is False
    assert await service._send_email(_channel(config={"to": "ops@example.com", "email_provider": "sendgrid"}), _alert(), "firing") is False
    assert await service._send_email(_channel(config={"to": "ops@example.com", "email_provider": "sendgrid", "sendgrid_api_key": "sg"}), _alert(), "firing") is True
    assert sendgrid_calls == [("sg", ["ops@example.com"], "admin@example.com")]

    assert await service._send_email(_channel(config={"to": "ops@example.com", "email_provider": "resend", "resend_api_key": "rk"}), _alert(), "firing") is False
    assert resend_calls == [("rk", ["ops@example.com"], "admin@example.com")]

    assert await service._send_email(_channel(config={"to": "ops@example.com", "email_provider": "unknown"}), _alert(), "firing") is False
    assert await service._send_email(_channel(config={"to": "ops@example.com", "smtp_port": 25}), _alert(), "firing") is False

    smtp_channel = _channel(config={"to": "a@example.com;b@example.com", "smtp_host": "smtp.example.com", "smtp_port": 0, "smtp_auth_type": "api_key", "smtp_api_key": "api", "smtp_starttls": True})
    assert await service._send_email(smtp_channel, _alert(), "resolved") is True
    assert smtp_calls[0][1:4] == ("smtp.example.com", 587, "apikey")

    noauth_channel = _channel(config={"to": "ops@example.com", "smtp_host": "smtp.example.com", "smtp_port": 25, "smtp_auth_type": "none"})
    assert await service._send_email(noauth_channel, _alert(), "resolved") is True