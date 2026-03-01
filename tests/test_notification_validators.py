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

import pytest

from services.notification import validators as notification_validators


def test_validate_channel_config_email_checks():
    errs = notification_validators.validate_channel_config("email", {})
    assert any("recipient" in e.lower() or "to'" in e for e in errs)

    errs = notification_validators.validate_channel_config("email", {"to": "a@b.com", "email_provider": "smtp"})
    assert any("smtp_host" in e or "smtp host" in e.replace(' ', '_') for e in errs)

    errs = notification_validators.validate_channel_config("email", {"to": "a@b.com", "email_provider": "sendgrid"})
    assert any("sendgrid" in e.lower() for e in errs)

    errs = notification_validators.validate_channel_config("email", {"to": "a@b.com", "email_provider": "resend"})
    assert any("resend" in e.lower() for e in errs)


def test_validate_channel_config_slack_and_webhook_and_pagerduty():
    errs = notification_validators.validate_channel_config("slack", {"webhook_url": "ftp://example.com"})
    assert any("webhook" in e.lower() for e in errs)

    errs = notification_validators.validate_channel_config("teams", {"webhookUrl": ""})
    assert any("webhook" in e.lower() for e in errs)

    errs = notification_validators.validate_channel_config("webhook", {"url": None})
    assert any("webhook" in e.lower() or "url" in e.lower() for e in errs)

    errs = notification_validators.validate_channel_config("pagerduty", {})
    assert any("routing_key" in e or "integrationkey" in e.lower() for e in errs)
