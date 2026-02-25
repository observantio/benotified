"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env
ensure_test_env()

from models.alerting.alerts import Alert, AlertStatus, AlertState
from services.notification import payloads as notification_payloads


def _make_alert(**kwargs) -> Alert:
    base = {
        "labels": {"alertname": "DiskFull", "severity": "critical", "instance": "srv1"},
        "annotations": {"summary": "disk almost full", "description": "root partition > 90%"},
        "startsAt": "2023-01-01T00:00:00Z",
        "status": {"state": "active"},
        "fingerprint": "fp-123",
    }
    base.update(kwargs)
    return Alert(**base) 


def test_get_label_and_annotation_and_alert_text():
    a = _make_alert()
    assert notification_payloads.get_label(a, "alertname") == "DiskFull"
    assert notification_payloads.get_annotation(a, "summary") == "disk almost full"
    txt = notification_payloads.get_alert_text(a)
    assert "disk almost full" in txt and "root partition > 90%" in txt
    a2 = _make_alert(annotations={"summary": "same", "description": "same"})
    assert notification_payloads.get_alert_text(a2) == "same"


def test_format_alert_body_and_build_payloads():
    a = _make_alert()
    body = notification_payloads.format_alert_body(a, "firing")
    assert "Alert: DiskFull" in body
    assert "Status: firing" in body
    assert "Labels:" in body
    assert "severity: critical" in body

    slack = notification_payloads.build_slack_payload(a, "firing")
    assert isinstance(slack, dict)
    assert slack["attachments"][0]["color"] == "danger"

    teams = notification_payloads.build_teams_payload(a, "resolved")
    assert teams["themeColor"] == "00FF00"
    aw = _make_alert(labels={"alertname": "X", "severity": "warning"})
    s = notification_payloads.build_slack_payload(aw, "firing")
    assert s["attachments"][0]["color"] == "danger"
    t = notification_payloads.build_teams_payload(aw, "firing")
    assert t["themeColor"] == "FFA500"

    pd = notification_payloads.build_pagerduty_payload(a, "firing", "rk1")
    assert pd["routing_key"] == "rk1"
    assert pd["payload"]["severity"] == "critical"
    assert pd["dedup_key"] == "fp-123"
