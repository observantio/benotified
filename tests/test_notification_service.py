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

import pytest

from services.notification import senders as notification_senders
from services.notification import transport as notification_transport
from services.notification import email_providers as notification_email
from services.notification import payloads as notification_payloads
from services.notification_service import NotificationService
from models.alerting.channels import NotificationChannel, ChannelType
from models.alerting.alerts import Alert, AlertStatus


def _make_alert():
    return Alert(labels={"alertname": "A", "severity": "critical"}, annotations={}, startsAt="2023-01-01T00:00:00Z", status=AlertStatus(state="active"), fingerprint="fp")


def test_post_and_smtp_delegate_to_transport(monkeypatch):
    called = {}

    async def fake_post(client, url, json=None, headers=None, params=None):
        called['post'] = (client, url, json, headers, params)
        return httpx.Response(200, request=httpx.Request("POST", url))

    async def fake_smtp(message, hostname, port, username=None, password=None, start_tls=False, use_tls=False, timeout=None):
        called['smtp'] = (hostname, port, timeout)
        return "ok"

    monkeypatch.setattr(notification_transport, "post_with_retry", fake_post)
    monkeypatch.setattr(notification_transport, "send_smtp_with_retry", fake_smtp)

    svc = NotificationService()
    resp = asyncio.run(svc._post_with_retry("https://example.com", json={"a": 1}))
    assert isinstance(resp, httpx.Response)
    assert called['post'][1] == "https://example.com"

    res = asyncio.run(svc._send_smtp_with_retry(message="m", hostname="h", port=25, username=None, password=None, start_tls=False, use_tls=False))
    assert res == "ok"
    assert called['smtp'][0] == "h"


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

    async def fake_send_via_smtp(message, hostname, port, username, password, start_tls, use_tls, timeout=None):
        called['smtp'] = (hostname, port)
        return True

    monkeypatch.setattr(notification_email, "send_via_sendgrid", fake_send_via_sendgrid)
    monkeypatch.setattr(notification_email, "send_via_resend", fake_send_via_resend)
    monkeypatch.setattr(notification_email, "send_via_smtp", fake_send_via_smtp)

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
    called = {}

    def fake_format(alert, action):
        called['format'] = (alert, action)
        return "FORMATTED"

    def fake_label(alert, key, default=""):
        called['label'] = (alert, key, default)
        return "LBL"

    def fake_annotation(alert, key):
        called['annotation'] = (alert, key)
        return "ANN"

    def fake_text(alert):
        called['text'] = alert
        return "T"

    monkeypatch.setattr(notification_payloads, "format_alert_body", fake_format)
    monkeypatch.setattr(notification_payloads, "get_label", fake_label)
    monkeypatch.setattr(notification_payloads, "get_annotation", fake_annotation)
    monkeypatch.setattr(notification_payloads, "get_alert_text", fake_text)

    svc = NotificationService()
    a = _make_alert()
    assert svc._format_alert_body(a, "firing") == "FORMATTED"
    assert svc._get_label(a, "alertname", "d") == "LBL"
    assert svc._get_annotation(a, "summary") == "ANN"
    assert svc._get_alert_text(a) == "T"


def test_send_email_uses_build_smtp_message(monkeypatch):
    captured = {}

    def fake_build(subject, body, smtp_from, recipients):
        captured['built'] = (subject, body, smtp_from, recipients)
        from email.message import EmailMessage
        m = EmailMessage()
        m['Subject'] = subject
        return m

    async def fake_send_smtp(message, hostname, port, username=None, password=None, start_tls=False, use_tls=False, timeout=None):
        captured['sent'] = (hostname, port)
        return True

    monkeypatch.setattr(notification_email, "build_smtp_message", fake_build)
    monkeypatch.setattr(notification_email, "send_via_smtp", fake_send_smtp)

    svc = NotificationService()
    ch = NotificationChannel(name="e", type=ChannelType.EMAIL, config={"to": "a@b.com", "smtp_host": "h", "smtp_port": 25})
    assert asyncio.run(svc.send_notification(ch, _make_alert(), "firing")) is True
    assert captured['built'][0].startswith("[FIRING]")
    assert captured['sent'][0] == 'h'
