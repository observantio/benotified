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

from models.alerting.rules import AlertRule, RuleSeverity
from services.alerting.ruler_yaml import (
    build_ruler_group_yaml,
    extract_mimir_group_names,
    group_enabled_rules,
    yaml_quote,
)


class RulerYamlTests(unittest.TestCase):
    def _rule(self, name: str, enabled: bool = True, group: str = "infra") -> AlertRule:
        return AlertRule(
            name=name,
            expression='up == 0',
            severity=RuleSeverity.WARNING,
            groupName=group,
            enabled=enabled,
            labels={'team': 'ops'},
            annotations={'summary': 'Host down'},
            duration='5m',
        )

    def test_yaml_quote_escapes_double_quotes_and_backslashes(self):
        self.assertEqual(yaml_quote('a"b\\c'), '"a\\"b\\\\c"')

    def test_group_enabled_rules_filters_disabled(self):
        grouped = group_enabled_rules([
            self._rule('rule-1', enabled=True, group='g1'),
            self._rule('rule-2', enabled=False, group='g1'),
            self._rule('rule-3', enabled=True, group='g2'),
        ])
        self.assertEqual(set(grouped.keys()), {'g1', 'g2'})
        self.assertEqual(len(grouped['g1']), 1)
        self.assertEqual(grouped['g1'][0].name, 'rule-1')

    def test_build_and_extract_group_yaml(self):
        yaml_text = build_ruler_group_yaml('infra', [self._rule('z-rule'), self._rule('a-rule')])
        self.assertIn('name: "infra"', yaml_text)
        self.assertIn('alert: "a-rule"', yaml_text)
        self.assertIn('alert: "z-rule"', yaml_text)

        namespace = 'groups:\n  - name: "infra"\n  - name: "app"\n'
        self.assertEqual(extract_mimir_group_names(namespace), ['infra', 'app'])


if __name__ == '__main__':
    unittest.main()
