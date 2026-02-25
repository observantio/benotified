"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from services.alerting import alerts_ops


class AlertOpsTests(unittest.IsolatedAsyncioTestCase):
    async def test_get_alerts_returns_models(self):
        payload = [{
            'labels': {'alertname': 'DiskFull'},
            'annotations': {'summary': 'Disk almost full'},
            'startsAt': '2026-01-01T00:00:00Z',
            'status': {'state': 'active', 'silencedBy': [], 'inhibitedBy': []},
        }]
        response = SimpleNamespace(raise_for_status=lambda: None, json=lambda: payload)

        service = SimpleNamespace(
            _client=SimpleNamespace(get=AsyncMock(return_value=response)),
            alertmanager_url='http://am',
            logger=SimpleNamespace(error=lambda *_args, **_kwargs: None),
        )

        result = await alerts_ops.get_alerts(service)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].labels.get('alertname'), 'DiskFull')

    async def test_delete_alerts_requires_filter(self):
        service = SimpleNamespace(logger=SimpleNamespace(warning=lambda *_args, **_kwargs: None))
        deleted = await alerts_ops.delete_alerts(service, filter_labels=None)
        self.assertFalse(deleted)


if __name__ == '__main__':
    unittest.main()
