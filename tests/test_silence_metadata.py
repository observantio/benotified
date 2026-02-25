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

from services.alerting.silence_metadata import (
    SILENCE_META_PREFIX,
    decode_silence_comment,
    encode_silence_comment,
    normalize_visibility,
)


class SilenceMetadataTests(unittest.TestCase):
    def test_encode_decode_roundtrip(self):
        encoded = encode_silence_comment("Investigating", "group", ["g1", "g2"])
        self.assertTrue(encoded.startswith(SILENCE_META_PREFIX))

        decoded = decode_silence_comment(encoded)
        self.assertEqual(decoded["comment"], "Investigating")
        self.assertEqual(decoded["visibility"], "group")
        self.assertEqual(decoded["shared_group_ids"], ["g1", "g2"])

    def test_decode_fallback_when_not_prefixed(self):
        decoded = decode_silence_comment("plain comment")
        self.assertEqual(decoded["comment"], "plain comment")
        self.assertEqual(decoded["visibility"], "tenant")
        self.assertEqual(decoded["shared_group_ids"], [])

    def test_normalize_visibility_rejects_invalid_value(self):
        self.assertEqual(normalize_visibility("invalid"), "private")


if __name__ == "__main__":
    unittest.main()
