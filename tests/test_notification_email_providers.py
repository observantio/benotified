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
from email.message import EmailMessage

from services.notification import email_providers, transport


def test_build_smtp_message():
    msg = email_providers.build_smtp_message("subj", "body", "from@example.com", ["a@b.com", "c@d.com"])
    assert isinstance(msg, EmailMessage)
    assert msg["Subject"] == "subj"
    assert "a@b.com" in msg["To"]


def test_send_via_sendgrid_and_resend_success_and_failure(monkeypatch):
    async def ok_post(client, url, json=None, headers=None, params=None, **kwargs):
        return httpx.Response(202)

    async def fail_post(client, url, json=None, headers=None, params=None, **kwargs):
        raise Exception("boom")

    monkeypatch.setattr(transport, "post_with_retry", ok_post)
    client = httpx.AsyncClient()
    assert asyncio.run(email_providers.send_via_sendgrid(client, "key", "s", "b", ["x@x"], "from@f")) is True
    assert asyncio.run(email_providers.send_via_resend(client, "key", "s", "b", ["x@x"], "from@f")) is True

    monkeypatch.setattr(transport, "post_with_retry", fail_post)
    assert asyncio.run(email_providers.send_via_sendgrid(client, "key", "s", "b", ["x@x"], "from@f")) is False
    assert asyncio.run(email_providers.send_via_resend(client, "key", "s", "b", ["x@x"], "from@f")) is False


def test_send_via_smtp_calls_transport(monkeypatch):
    async def fake_send(message, hostname, port, username=None, password=None, start_tls=False, use_tls=False, timeout=None):
        return True

    monkeypatch.setattr(transport, "send_smtp_with_retry", fake_send)
    assert asyncio.run(email_providers.send_via_smtp("m", "h", 25, None, None, False, False, timeout=3)) is True

    async def fake_send_err(*args, **kwargs):
        raise Exception("fail")

    monkeypatch.setattr(transport, "send_smtp_with_retry", fake_send_err)
    assert asyncio.run(email_providers.send_via_smtp("m", "h", 25, None, None, False, False, timeout=3)) is False
