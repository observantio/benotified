"""
Rule import service for parsing and normalizing alert rules from YAML content, supporting various input formats, default values, and error handling.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import yaml

from models.alerting.rules import AlertRuleCreate, RuleSeverity
from models.alerting.silences import Visibility
from services.common.visibility import normalize_visibility

_VALID_SEVERITIES = {"info", "warning", "error", "critical"}


class RuleImportError(ValueError):
    pass


def _as_str_map(raw: Any) -> Dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items() if v is not None}


def _normalize_visibility(value: Any, default_value: str = "private") -> str:
    return normalize_visibility(
        str(value) if value is not None else None,
        default_value=default_value,
        public_alias="public",
        allowed={"tenant", "group", "private", "public"},
    )


def _normalize_rule_entry(
    group_name: str,
    rule_data: Dict[str, Any],
    defaults: Dict[str, Any],
) -> AlertRuleCreate:
    alert_name = (rule_data.get("alert") or rule_data.get("name") or "").strip()
    if not alert_name:
        raise RuleImportError("Rule is missing required field 'alert'")

    expr = (rule_data.get("expr") or "").strip()
    if not expr:
        raise RuleImportError(f"Rule '{alert_name}' is missing required field 'expr'")

    be_meta_raw = rule_data.get("beobservant")
    be_meta: Dict[str, Any] = be_meta_raw if isinstance(be_meta_raw, dict) else {}

    labels = _as_str_map(rule_data.get("labels"))
    annotations = _as_str_map(rule_data.get("annotations"))

    severity = str(
        be_meta.get("severity") or labels.get("severity") or defaults.get("severity") or "warning"
    ).strip().lower()
    if severity not in _VALID_SEVERITIES:
        severity = "warning"
    severity_enum = RuleSeverity(severity)

    channels_raw = be_meta.get("channels")
    channels_src = channels_raw if isinstance(channels_raw, list) else defaults.get("channels")
    channels = [str(c).strip() for c in (channels_src or []) if str(c).strip()]

    shared_raw = be_meta.get("sharedGroupIds")
    shared_src = shared_raw if isinstance(shared_raw, list) else []
    shared_group_ids = [str(gid).strip() for gid in shared_src if str(gid).strip()]

    visibility_str = _normalize_visibility(be_meta.get("visibility") or defaults.get("visibility"), "private")
    visibility_enum = Visibility(visibility_str)

    return AlertRuleCreate(
        orgId=str(be_meta.get("orgId") or be_meta.get("org_id") or defaults.get("orgId") or "").strip() or None,
        name=alert_name,
        expression=expr,
        severity=severity_enum,
        description=annotations.get("description"),
        enabled=bool(be_meta.get("enabled", defaults.get("enabled", True))),
        labels={k: v for k, v in labels.items() if k != "severity"},
        annotations=annotations,
        **{"for": str(rule_data.get("for") or defaults.get("duration") or "5m").strip() or "5m"},
        groupName=str(be_meta.get("group") or group_name or defaults.get("group") or "default").strip() or "default",
        notificationChannels=channels,
        visibility=visibility_enum,
        sharedGroupIds=shared_group_ids,
    )


def parse_rules_yaml(yaml_content: str, defaults: Optional[Dict[str, Any]] = None) -> List[AlertRuleCreate]:
    if not (yaml_content or "").strip():
        raise RuleImportError("YAML content is required")

    try:
        parsed = yaml.safe_load(yaml_content)
    except Exception as exc:
        raise RuleImportError(f"Failed to parse YAML: {exc}") from exc

    if parsed is None:
        raise RuleImportError("YAML content is empty")

    if isinstance(parsed, dict):
        if isinstance(parsed.get("groups"), list):
            groups = parsed["groups"]
        elif isinstance(parsed.get("spec"), dict) and isinstance(parsed["spec"].get("groups"), list):
            groups = parsed["spec"]["groups"]
        else:
            raise RuleImportError("Expected 'groups' or 'spec.groups' in YAML")
    elif isinstance(parsed, list):
        groups = parsed
    else:
        raise RuleImportError("Unsupported YAML structure for rules import")

    defaults = defaults or {}
    results: List[AlertRuleCreate] = []

    for idx, group in enumerate(groups):
        if not isinstance(group, dict):
            continue
        group_name = str(group.get("name") or defaults.get("group") or f"group-{idx + 1}").strip()
        rules = group.get("rules")
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            results.append(_normalize_rule_entry(group_name, rule, defaults))

    if not results:
        raise RuleImportError("No valid alert rules found in YAML")
    return results
