"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from email.message import EmailMessage

import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from config import config
from services import notification_service as notification_mod
from services.notification_service import NotificationService


@pytest.mark.asyncio
async def test_notification_service_support_helpers(monkeypatch):
    svc = NotificationService()
    monkeypatch.setattr(notification_mod.notification_validators, "_as_bool", lambda value: str(value) == "ok")
    monkeypatch.setattr(notification_mod.notification_validators, "validate_channel_config", lambda *_args: ["err"])

    async def fake_send_smtp_with_retry(*args, **kwargs):
        return {"args": args, "kwargs": kwargs}

    monkeypatch.setattr(notification_mod.notification_transport, "send_smtp_with_retry", fake_send_smtp_with_retry)

    assert svc._as_bool("ok") is True
    assert svc._as_bool("other") is False
    assert svc.validate_channel_config("email", {}) == ["err"]

    msg = EmailMessage()
    result = await svc._send_smtp_with_retry(msg, "smtp.example.com", 25, username="user", password="pw", start_tls=True)
    assert result["kwargs"]["hostname"] == "smtp.example.com"


@pytest.mark.asyncio
async def test_incident_assignment_email_paths(monkeypatch):
    svc = NotificationService()
    monkeypatch.setattr(config, "DEFAULT_ADMIN_EMAIL", "admin@example.com")

    monkeypatch.setattr(notification_mod.config, "get_secret", lambda key: None)
    assert await svc.send_incident_assignment_email("u@example.com", "CPU", "open", "critical", "admin") is False

    monkeypatch.setattr(
        notification_mod.config,
        "get_secret",
        lambda key: {
            "INCIDENT_ASSIGNMENT_EMAIL_ENABLED": "true",
            "INCIDENT_ASSIGNMENT_SMTP_PORT": "bad-port",
        }.get(key),
    )
    assert await svc.send_incident_assignment_email("u@example.com", "CPU", "open", "critical", "admin") is False

    async def fake_send(*, message, hostname, port, username=None, password=None, start_tls=False, use_tls=False):
        assert hostname == "smtp.example.com"
        assert port == 587
        assert message["To"] == "u@example.com"

    monkeypatch.setattr(
        notification_mod.config,
        "get_secret",
        lambda key: {
            "INCIDENT_ASSIGNMENT_EMAIL_ENABLED": "true",
            "INCIDENT_ASSIGNMENT_SMTP_HOST": "smtp.example.com",
            "INCIDENT_ASSIGNMENT_SMTP_PORT": "bad-port",
            "INCIDENT_ASSIGNMENT_FROM": "alerts@example.com",
        }.get(key),
    )
    monkeypatch.setattr(svc, "_send_smtp_with_retry", fake_send)
    assert await svc.send_incident_assignment_email("u@example.com", "CPU", "open", "critical", "admin") is True

    async def fail_send(**_kwargs):
        raise OSError("smtp down")

    monkeypatch.setattr(svc, "_send_smtp_with_retry", fail_send)
    assert await svc.send_incident_assignment_email("u@example.com", "CPU", "open", "critical", "admin") is False