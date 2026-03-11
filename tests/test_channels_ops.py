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

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from services.alerting import channels_ops


@pytest.mark.asyncio
async def test_notify_for_alerts_skips_suppressed_alerts():
    storage_service = SimpleNamespace(
        get_notification_channels_for_rule_name=lambda *args, **kwargs: [SimpleNamespace(name="c1")],
        get_alert_rule_by_name_for_delivery=lambda *args, **kwargs: None,
    )
    notification_service = SimpleNamespace(send_notification=AsyncMock(return_value=True))

    await channels_ops.notify_for_alerts(
        service=SimpleNamespace(),
        tenant_id="t1",
        alerts_list=[
            {
                "labels": {"alertname": "DiskFull", "severity": "critical"},
                "annotations": {"summary": "Disk almost full"},
                "startsAt": "2026-01-01T00:00:00Z",
                "status": {"state": "suppressed", "silencedBy": ["sil-1"], "inhibitedBy": []},
                "fingerprint": "fp-1",
            }
        ],
        storage_service=storage_service,
        notification_service=notification_service,
    )

    notification_service.send_notification.assert_not_called()

