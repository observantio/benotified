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
import aiosmtplib

from services.notification import transport


def test_send_smtp_with_retry_calls_aiosmtplib(monkeypatch):
    called = {}

    async def fake_send(*args, **kwargs):
        called['args'] = args
        called['kwargs'] = kwargs
        return "ok"

    monkeypatch.setattr(aiosmtplib, "send", fake_send)

    result = asyncio.run(transport.send_smtp_with_retry(message="m", hostname="h", port=25, username=None, password=None, start_tls=False, use_tls=False))
    assert result == "ok"
    assert called['kwargs']['hostname'] == "h"
