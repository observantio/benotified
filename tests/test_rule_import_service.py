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

from services.alerting.rule_import_service import RuleImportError, parse_rules_yaml


class RuleImportServiceTests(unittest.TestCase):
    def test_parse_groups_structure_and_defaults(self):
        content = '''
        groups:
          - name: core
            rules:
              - alert: HighLatency
                expr: histogram_quantile(0.95, request_duration_seconds_bucket) > 1
                for: 10m
                labels:
                  severity: critical
                annotations:
                  description: p95 too high
        '''
        rules = parse_rules_yaml(content)
        self.assertEqual(len(rules), 1)
        rule = rules[0]
        self.assertEqual(rule.name, 'HighLatency')
        self.assertEqual(rule.group, 'core')
        self.assertEqual(rule.severity, 'critical')

    def test_parse_spec_groups_structure(self):
        content = '''
        spec:
          groups:
            - name: app
              rules:
                - alert: ErrorRateHigh
                  expr: rate(http_requests_total{status=~"5.."}[5m]) > 0
        '''
        rules = parse_rules_yaml(content)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].group, 'app')

    def test_invalid_yaml_raises_rule_import_error(self):
        with self.assertRaises(RuleImportError):
            parse_rules_yaml('groups: [')


if __name__ == '__main__':
    unittest.main()
