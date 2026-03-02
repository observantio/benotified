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

from config import config

from services.notification import senders as notification_senders
from services.notification import email_providers as notification_email
from services.notification import payloads as notification_payloads
from services.notification_service import NotificationService
from models.alerting.channels import NotificationChannel, ChannelType
from models.alerting.alerts import Alert, AlertStatus


def _make_alert():
    return Alert(labels={"alertname": "A", "severity": "critical"}, annotations={}, startsAt="2023-01-01T00:00:00Z", status=AlertStatus(state="active"), fingerprint="fp")




def test_send_slack_delegates_to_senders(monkeypatch):
    called = {}

    async def fake_send_slack(client, channel_config, alert, action):
        called['slack'] = (client, channel_config, alert, action)
        return True

    monkeypatch.setattr(notification_senders, "send_slack", fake_send_slack)

    svc = NotificationService()
    ch = NotificationChannel(name="c", type=ChannelType.SLACK, config={"webhook_url": "https://example.com/h"})
    res = asyncio.run(svc.send_notification(ch, _make_alert(), "firing"))
    assert res is True
    assert 'slack' in called


def test_send_email_delegates_to_email_providers(monkeypatch):
    called = {}

    async def fake_send_via_sendgrid(client, api_key, subject, body, recipients, smtp_from):
        called['sg'] = (api_key, recipients)
        return True

    async def fake_send_via_resend(client, api_key, subject, body, recipients, smtp_from):
        called['rs'] = (api_key, recipients)
        return True

    async def fake_send_via_smtp(message, hostname, port, username, password, start_tls, use_tls):
        called['smtp'] = (hostname, port)
        return True

    monkeypatch.setattr(notification_email, "send_via_sendgrid", fake_send_via_sendgrid)
    monkeypatch.setattr(notification_email, "send_via_resend", fake_send_via_resend)
    monkeypatch.setattr(notification_email, "send_via_smtp", fake_send_via_smtp)

    # ensure a default from address exists so service logic doesn't blow up
    config.DEFAULT_ADMIN_EMAIL = "admin@example.com"

    svc = NotificationService()
    ch1 = NotificationChannel(name="e1", type=ChannelType.EMAIL, config={"to": "a@b.com", "email_provider": "sendgrid", "sendgrid_api_key": "k"})
    assert asyncio.run(svc.send_notification(ch1, _make_alert(), "firing")) is True
    assert called['sg'][0] == 'k'

    ch2 = NotificationChannel(name="e2", type=ChannelType.EMAIL, config={"to": "a@b.com", "email_provider": "resend", "resend_api_key": "rk"})
    assert asyncio.run(svc.send_notification(ch2, _make_alert(), "firing")) is True
    assert called['rs'][0] == 'rk'

    ch3 = NotificationChannel(name="e3", type=ChannelType.EMAIL, config={"to": "a@b.com", "smtp_host": "h", "smtp_port": 25})
    assert asyncio.run(svc.send_notification(ch3, _make_alert(), "firing")) is True
    assert called['smtp'][0] == 'h'


def test_format_helpers_delegate_to_payloads(monkeypatch):
    # ensure the formatting helper is actually invoked during notification
    called = {}

    def fake_format(alert, action):
        called['format'] = (alert, action)
        return "FORMATTED"

    monkeypatch.setattr(notification_payloads, "format_alert_body", fake_format)

    # avoid real email transport so test stays fast
    async def fake_send_smtp(message, hostname, port, username=None, password=None, start_tls=False, use_tls=False):
        return True

    monkeypatch.setattr(notification_email, "send_via_smtp", fake_send_smtp)

    # provide a default from address for the service
    config.DEFAULT_ADMIN_EMAIL = "admin@example.com"

    svc = NotificationService()
    ch = NotificationChannel(name="e", type=ChannelType.EMAIL, config={"to": "a@b.com", "smtp_host": "h", "smtp_port": 25})
    asyncio.run(svc.send_notification(ch, _make_alert(), "firing"))
    assert 'format' in called


def test_send_email_uses_build_smtp_message(monkeypatch):
    captured = {}

    def fake_build(subject, body, smtp_from, recipients):
        captured['built'] = (subject, body, smtp_from, recipients)
        from email.message import EmailMessage
        m = EmailMessage()
        m['Subject'] = subject
        return m

    async def fake_send_smtp(message, hostname, port, username=None, password=None, start_tls=False, use_tls=False):
        captured['sent'] = (hostname, port)
        return True

    monkeypatch.setattr(notification_email, "build_smtp_message", fake_build)
    monkeypatch.setattr(notification_email, "send_via_smtp", fake_send_smtp)

    # ensure default from address available
    config.DEFAULT_ADMIN_EMAIL = "admin@example.com"

    svc = NotificationService()
    ch = NotificationChannel(name="e", type=ChannelType.EMAIL, config={"to": "a@b.com", "smtp_host": "h", "smtp_port": 25})
    assert asyncio.run(svc.send_notification(ch, _make_alert(), "firing")) is True
    assert captured['built'][0].startswith("[FIRING]")
    assert captured['sent'][0] == 'h'
