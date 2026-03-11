"""
Payload construction utilities for notification services, providing functions to build message payloads for different notification channels such as Slack, Microsoft Teams, and PagerDuty based on alert data. This module includes functions to extract relevant information from alert objects, format alert details into human-readable text, and construct structured payloads that conform to the expected formats of each notification channel. The utilities ensure that notifications are informative and properly formatted to facilitate quick understanding and response by recipients when alerts are triggered or resolved.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from datetime import datetime

from custom_types.json import JSONDict
from models.alerting.alerts import Alert

NO_VALUE = "(none)"

PD_SEVERITY_MAP = {
    "critical": "critical",
    "high": "critical",
    "error": "error",
    "warning": "warning",
    "info": "info",
}


def _status_text(action: str) -> str:
    normalized = str(action or "").strip().lower()
    if normalized == "test":
        return "TEST"
    if normalized == "resolved":
        return "RESOLVED"
    return "FIRING"

def _fmt(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value) if value is not None else "unknown"


def _alert_start_timestamp(alert: Alert) -> int | None:
    raw = str(alert.starts_at or "").strip()
    if not raw:
        return None
    try:
        return int(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def get_label(alert: Alert, key: str, default: str = "") -> str:
    return str((alert.labels or {}).get(key, default))


def get_annotation(alert: Alert, key: str) -> str | None:
    value = (alert.annotations or {}).get(key)
    return str(value) if value is not None else None


def get_alert_text(alert: Alert) -> str:
    summary = get_annotation(alert, "summary")
    description = get_annotation(alert, "description")
    if summary and description and summary != description:
        return f"{summary}\n{description}"
    return summary or description or "No description"


def _context_value(alert: Alert, *keys: str) -> str:
    annotations = alert.annotations or {}
    labels = alert.labels or {}
    for key in keys:
        value = annotations.get(key)
        if value is None:
            value = labels.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _human_context(alert: Alert) -> list[tuple[str, str]]:
    correlation_id = _context_value(
        alert,
        "beobservantCorrelationId",
        "correlation_id",
        "correlationId",
        "group",
    )
    created_by = _context_value(
        alert,
        "beobservantCreatedByUsername",
        "created_by_username",
        "createdByUsername",
        "beobservantCreatedBy",
        "created_by",
        "createdBy",
    )
    product_name = _context_value(alert, "beobservantProductName", "product")
    rule_name = _context_value(alert, "beobservantRuleName")
    context: list[tuple[str, str]] = []
    if rule_name:
        context.append(("Rule", rule_name))
    if correlation_id:
        context.append(("Correlation ID", correlation_id))
    if product_name:
        context.append(("Product", product_name))
    if created_by:
        context.append(("Created by", created_by))
    return context


def _important_labels(alert: Alert) -> list[tuple[str, str]]:
    skip = {
        "alertname",
        "severity",
        "org_id",
        "orgId",
        "tenant",
        "product",
        "correlation_id",
        "correlationId",
        "group",
    }
    labels = []
    for key, value in sorted((alert.labels or {}).items(), key=lambda item: str(item[0])):
        k = str(key)
        if k in skip:
            continue
        labels.append((k, str(value)))
    return labels


def format_alert_body(alert: Alert, action: str) -> str:
    summary = get_annotation(alert, "summary") or "No summary"
    description = get_annotation(alert, "description") or "No description"

    lines = [
        f"Alert: {get_label(alert, 'alertname', 'Unknown')}",
        f"Status: {_status_text(action)}",
        f"Severity: {get_label(alert, 'severity', 'unknown')}",
        f"Started at: {_fmt(alert.starts_at)}",
    ]

    context = _human_context(alert)
    if context:
        lines.extend(["", "Context:"])
        for key, value in context:
            lines.append(f"  {key}: {value}")

    lines.extend([
        "",
        "Summary:",
        summary,
        "",
        "Description:",
        description,
    ])

    labels = _important_labels(alert)
    if labels:
        lines.extend(["", "Labels:"])
        for key, value in labels:
            lines.append(f"  {key}: {value}")

    return "\n".join(lines)


def build_slack_payload(alert: Alert, action: str) -> JSONDict:
    severity = get_label(alert, "severity").lower()
    status_text = _status_text(action)

    if status_text == "FIRING":
        color = "danger"
    elif status_text == "RESOLVED":
        color = "good"
    else:
        color = "warning"

    ts = _alert_start_timestamp(alert)

    fields: list[JSONDict] = [
        {"title": "Severity", "value": severity or "unknown", "short": True},
        {"title": "Status", "value": status_text, "short": True},
        {"title": "Correlation ID", "value": _context_value(alert, "beobservantCorrelationId", "correlation_id", "correlationId", "group") or NO_VALUE, "short": True},
        {
            "title": "Created by",
            "value": _context_value(
                alert,
                "beobservantCreatedByUsername",
                "created_by_username",
                "createdByUsername",
                "beobservantCreatedBy",
                "created_by",
                "createdBy",
            )
            or NO_VALUE,
            "short": True,
        },
        {"title": "Product", "value": _context_value(alert, "beobservantProductName", "product") or NO_VALUE, "short": True},
        {"title": "Summary", "value": get_annotation(alert, "summary") or NO_VALUE, "short": False},
        {"title": "Description", "value": get_annotation(alert, "description") or NO_VALUE, "short": False},
    ]

    attachment: JSONDict = {
        "color": color,
        "title": f"[{status_text}] {get_label(alert, 'alertname', 'Alert')}",
        "text": get_alert_text(alert),
        "fields": fields,
        "footer": f"Started at: {_fmt(alert.starts_at)}",
    }

    if ts is not None:
        attachment["ts"] = ts

    return {"attachments": [attachment]}


def build_teams_payload(alert: Alert, action: str) -> JSONDict:
    severity = get_label(alert, "severity").lower()
    status_text = _status_text(action)

    if status_text == "FIRING":
        theme_color = "FFA500" if severity == "warning" else "FF0000"
    elif status_text == "RESOLVED":
        theme_color = "00FF00"
    else:
        theme_color = "FFA500"

    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": theme_color,
        "title": f"[{status_text}] {get_label(alert, 'alertname', 'Alert')}",
        "text": get_alert_text(alert),
        "sections": [{
            "facts": [
                {"name": "Severity", "value": severity or "unknown"},
                {"name": "Status", "value": status_text},
                {"name": "Correlation ID", "value": _context_value(alert, "beobservantCorrelationId", "correlation_id", "correlationId", "group") or NO_VALUE},
                {
                    "name": "Created by",
                    "value": _context_value(
                        alert,
                        "beobservantCreatedByUsername",
                        "created_by_username",
                        "createdByUsername",
                        "beobservantCreatedBy",
                        "created_by",
                        "createdBy",
                    )
                    or NO_VALUE,
                },
                {"name": "Product", "value": _context_value(alert, "beobservantProductName", "product") or NO_VALUE},
                {"name": "Started", "value": _fmt(alert.starts_at)},
                {"name": "Summary", "value": get_annotation(alert, "summary") or NO_VALUE},
                {"name": "Description", "value": get_annotation(alert, "description") or NO_VALUE},
            ]
        }]
    }


def build_pagerduty_payload(alert: Alert, action: str, routing_key: str) -> JSONDict:
    status_text = _status_text(action)
    event_action = "resolve" if status_text == "RESOLVED" else "trigger"

    raw_severity = get_label(alert, "severity", "warning").lower()
    severity = PD_SEVERITY_MAP.get(raw_severity, "warning")

    summary = get_annotation(alert, "summary")
    description = get_annotation(alert, "description")

    return {
        "routing_key": routing_key,
        "event_action": event_action,
        "dedup_key": alert.fingerprint or get_label(alert, "alertname", "alert"),
        "payload": {
            "summary": summary or description or get_label(alert, "alertname", "Alert"),
            "severity": severity,
            "source": get_label(alert, "instance", "unknown"),
            "custom_details": {
                "labels": alert.labels or {},
                "annotations": alert.annotations or {},
            },
        },
    }
