"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import unittest
from types import SimpleNamespace

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.access.auth_models import TokenData
from services.alerting.rules_ops import resolve_rule_org_id


class RulesOpsTests(unittest.TestCase):
    def test_resolve_rule_org_id_prefers_rule_org(self):
        service = SimpleNamespace(config=SimpleNamespace(DEFAULT_ORG_ID='default'))
        user = TokenData(
            user_id='u1',
            username='alice',
            tenant_id='t1',
            org_id='user-org',
            role='user',
            permissions=[],
            group_ids=[],
            is_superuser=False,
        )
        self.assertEqual(resolve_rule_org_id(service, 'rule-org', user), 'rule-org')

    def test_resolve_rule_org_id_fallbacks_to_user_then_default(self):
        service = SimpleNamespace(config=SimpleNamespace(DEFAULT_ORG_ID='default-org'))
        user = TokenData(
            user_id='u1',
            username='alice',
            tenant_id='t1',
            org_id='user-org',
            role='user',
            permissions=[],
            group_ids=[],
            is_superuser=False,
        )
        self.assertEqual(resolve_rule_org_id(service, None, user), 'user-org')

        no_user_org = SimpleNamespace(org_id=None)
        self.assertEqual(resolve_rule_org_id(service, None, no_user_org), 'default-org')


if __name__ == '__main__':
    unittest.main()
