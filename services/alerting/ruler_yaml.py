"""
Rule import and alert processing logic for Alertmanager integration, including parsing incoming alerts, determining notification channels, and sending notifications based on alert status and configuration.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from typing import Dict, List

from config import config
from models.alerting.rules import AlertRule

def yaml_quote(value: object) -> str:
    text = str(value)
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def group_enabled_rules(rules: List[AlertRule]) -> Dict[str, List[AlertRule]]:
    grouped: Dict[str, List[AlertRule]] = {}
    for rule in rules:
        if not rule.enabled:
            continue
        group_name = rule.group or config.DEFAULT_RULE_GROUP
        grouped.setdefault(group_name, []).append(rule)
    return grouped


def build_ruler_group_yaml(group_name: str, rules: List[AlertRule]) -> str:
    lines = [f"name: {yaml_quote(group_name)}", "rules:"]
    for rule in sorted(rules, key=lambda entry: entry.name.lower()):
        lines.append(f"  - alert: {yaml_quote(rule.name)}")
        lines.append(f"    expr: {yaml_quote(rule.expr)}")
        lines.append(f"    for: {yaml_quote(rule.duration)}")

        labels = dict(rule.labels or {})
        labels["severity"] = rule.severity
        if labels:
            lines.append("    labels:")
            for key in sorted(labels.keys()):
                lines.append(f"      {key}: {yaml_quote(labels[key])}")

        annotations = rule.annotations or {}
        if annotations:
            lines.append("    annotations:")
            for key in sorted(annotations.keys()):
                lines.append(f"      {key}: {yaml_quote(annotations[key])}")

    return "\n".join(lines) + "\n"


def extract_mimir_group_names(namespace_yaml: str) -> List[str]:
    if not namespace_yaml:
        return []

    names: List[str] = []
    for line in namespace_yaml.splitlines():
        stripped = line.strip()
        if not stripped.startswith("- name:"):
            continue
        value = stripped[len("- name:"):].strip()
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        if value:
            names.append(value)
    return names
