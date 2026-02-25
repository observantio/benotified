"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import unittest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.access.auth_models import TokenData
from models.alerting.silences import Silence
from services.alerting.silences_ops import apply_silence_metadata, silence_accessible


class SilencesOpsTests(unittest.TestCase):
    def _user(self, username='alice', groups=None):
        return TokenData(
            user_id='u1',
            username=username,
            tenant_id='t1',
            org_id='o1',
            role='user',
            permissions=[],
            group_ids=groups or [],
            is_superuser=False,
        )

    def _silence(self, created_by='alice', visibility='tenant', shared_group_ids=None):
        return Silence(
            id='s1',
            matchers=[],
            startsAt='2026-01-01T00:00:00Z',
            endsAt='2026-01-01T01:00:00Z',
            createdBy=created_by,
            comment='note',
            visibility=visibility,
            sharedGroupIds=shared_group_ids or [],
        )

    def test_silence_accessible_for_creator_and_tenant_visibility(self):
        user = self._user(username='alice')
        self.assertTrue(silence_accessible(None, self._silence(created_by='alice', visibility='private'), user))
        self.assertTrue(silence_accessible(None, self._silence(created_by='bob', visibility='tenant'), user))

    def test_silence_accessible_for_group_visibility(self):
        user = self._user(username='alice', groups=['g1'])
        silence = self._silence(created_by='bob', visibility='group', shared_group_ids=['g2', 'g1'])
        self.assertTrue(silence_accessible(None, silence, user))

    def test_apply_silence_metadata_updates_fields(self):
        silence = self._silence()

        class Service:
            @staticmethod
            def decode_silence_comment(_comment):
                return {'comment': 'decoded', 'visibility': 'group', 'shared_group_ids': ['g1']}

        updated = apply_silence_metadata(Service(), silence)
        self.assertEqual(updated.comment, 'decoded')
        self.assertEqual(updated.visibility, 'group')
        self.assertEqual(updated.shared_group_ids, ['g1'])


if __name__ == '__main__':
    unittest.main()
