"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import unittest
from unittest.mock import patch

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from fastapi import HTTPException

from services.alerting.integration_security_service import (
    infer_tenant_id_from_alerts,
    is_jira_sso_available,
    jira_integration_has_access,
    normalize_jira_auth_mode,
    normalize_visibility,
    validate_jira_credentials,
)
from models.access.auth_models import TokenData


class IntegrationSecurityServiceTests(unittest.TestCase):
    class _FakeQuery:
        def __init__(self, rows):
            self._rows = rows

        def filter(self, *_args, **_kwargs):
            return self

        def all(self):
            return list(self._rows)

    class _FakeDB:
        def __init__(self, rows):
            self._rows = rows

        def query(self, *_args, **_kwargs):
            return IntegrationSecurityServiceTests._FakeQuery(self._rows)

    class _FakeCtx:
        def __init__(self, db):
            self._db = db

        def __enter__(self):
            return self._db

        def __exit__(self, exc_type, exc, tb):
            return False

    def test_normalize_visibility_maps_public_to_tenant(self):
        self.assertEqual(normalize_visibility('public'), 'tenant')
        self.assertEqual(normalize_visibility('group'), 'group')
        self.assertEqual(normalize_visibility('invalid'), 'private')

    def test_normalize_jira_auth_mode_rejects_unsupported(self):
        with self.assertRaises(HTTPException):
            normalize_jira_auth_mode('oauth')

    def test_normalize_jira_auth_mode_sso_requires_oidc(self):
        with patch('services.alerting.integration_security_service.is_jira_sso_available', return_value=False):
            with self.assertRaises(HTTPException):
                normalize_jira_auth_mode('sso')

    def test_validate_jira_credentials_api_token_mode(self):
        validate_jira_credentials(
            base_url='https://jira.example.com',
            auth_mode='api_token',
            email='user@example.com',
            api_token='token123',
            bearer_token=None,
        )

        with self.assertRaises(HTTPException):
            validate_jira_credentials(
                base_url='https://jira.example.com',
                auth_mode='api_token',
                email='',
                api_token='token123',
                bearer_token=None,
            )

    def test_is_jira_sso_available_missing_config_attrs_does_not_crash(self):
        with patch(
            "services.alerting.integration_security_service.config",
            object(),
        ):
            self.assertFalse(is_jira_sso_available())

    def test_jira_integration_write_access_is_owner_only(self):
        owner = TokenData(
            user_id="u-owner",
            username="owner",
            tenant_id="t1",
            org_id="o1",
            role="user",
            permissions=[],
            group_ids=["g1"],
            is_superuser=False,
        )
        non_owner = TokenData(
            user_id="u-other",
            username="other",
            tenant_id="t1",
            org_id="o1",
            role="user",
            permissions=[],
            group_ids=["g1"],
            is_superuser=False,
        )
        item = {
            "id": "int-1",
            "createdBy": "u-owner",
            "visibility": "group",
            "sharedGroupIds": ["g1"],
        }
        self.assertTrue(jira_integration_has_access(item, owner, write=True))
        self.assertFalse(jira_integration_has_access(item, non_owner, write=True))
        self.assertTrue(jira_integration_has_access(item, non_owner, write=False))

    def test_infer_tenant_id_from_alerts_uses_explicit_scope(self):
        with patch(
            "services.alerting.integration_security_service.tenant_id_from_scope_header",
            return_value="t-explicit",
        ):
            inferred = infer_tenant_id_from_alerts("t-explicit", [{"labels": {"alertname": "CPU boom"}}])
        self.assertEqual(inferred, "t-explicit")

    def test_infer_tenant_id_from_alerts_uses_unique_candidate(self):
        fake_db = self._FakeDB([("tenant-123",)])
        with patch(
            "services.alerting.integration_security_service.tenant_id_from_scope_header",
            return_value="default",
        ), patch(
            "services.alerting.integration_security_service.get_db_session",
            return_value=self._FakeCtx(fake_db),
        ):
            inferred = infer_tenant_id_from_alerts(None, [{"labels": {"alertname": "CPU boom"}}])
        self.assertEqual(inferred, "tenant-123")

    def test_infer_tenant_id_from_alerts_keeps_base_when_ambiguous(self):
        fake_db = self._FakeDB([("tenant-1",), ("tenant-2",)])
        with patch(
            "services.alerting.integration_security_service.tenant_id_from_scope_header",
            return_value="default",
        ), patch(
            "services.alerting.integration_security_service.get_db_session",
            return_value=self._FakeCtx(fake_db),
        ):
            inferred = infer_tenant_id_from_alerts(None, [{"labels": {"alertname": "CPU boom"}}])
        self.assertEqual(inferred, "default")


if __name__ == '__main__':
    unittest.main()
