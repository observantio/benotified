"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from fastapi import HTTPException

from models.alerting.incidents import AlertIncidentUpdateRequest
from services.storage import incidents as incidents_mod


def _incident_row(
    incident_id: str,
    *,
    status: str = "open",
    visibility: str = "public",
    created_by: str | None = None,
    shared_group_ids: list[str] | None = None,
    hide_when_resolved: bool = False,
    assignee: str | None = None,
    alert_name: str = "CPUHigh",
    fingerprint: str = "fp-1",
    labels: dict[str, object] | None = None,
    annotations: dict[str, object] | None = None,
) -> SimpleNamespace:
    meta = {
        "visibility": visibility,
        "created_by": created_by,
        "shared_group_ids": shared_group_ids or [],
    }
    if hide_when_resolved:
        meta["hide_when_resolved"] = True
    merged_annotations = dict(annotations or {})
    merged_annotations[incidents_mod.INCIDENT_META_KEY] = json.dumps(meta)
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        id=incident_id,
        tenant_id="tenant-a",
        status=status,
        assignee=assignee,
        annotations=merged_annotations,
        labels=labels or {"alertname": alert_name},
        alert_name=alert_name,
        fingerprint=fingerprint,
        updated_at=now,
        last_seen_at=now,
        resolved_at=None,
        starts_at=None,
        severity="warning",
        notes=[],
    )


class _FakeQuery:
    def __init__(self, items):
        self._items = list(items)
        self._offset = 0
        self._limit: int | None = None

    def filter(self, *args, **kwargs):
        for expression in args:
            left = getattr(expression, "left", None)
            right = getattr(expression, "right", None)
            key = getattr(left, "key", None) or getattr(left, "name", None)
            value = getattr(right, "value", None)
            if key is not None and value is not None:
                self._items = [item for item in self._items if getattr(item, key, None) == value]
        return self

    def options(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def offset(self, value: int):
        self._offset = value
        return self

    def limit(self, value: int):
        self._limit = value
        return self

    def all(self):
        items = self._items[self._offset:]
        if self._limit is not None:
            items = items[:self._limit]
        return list(items)

    def first(self):
        items = self.all()
        return items[0] if items else None


class _FakeDB:
    def __init__(self, incidents=None, rules=None):
        self.incidents = list(incidents or [])
        self.rules = list(rules or [])
        self.flushed = 0

    def query(self, model):
        if model is incidents_mod.AlertRuleDB:
            return _FakeQuery(self.rules)
        return _FakeQuery(self.incidents)

    def flush(self):
        self.flushed += 1


@contextmanager
def _db_session(db):
    yield db


def test_incident_storage_helper_functions(monkeypatch):
    assert incidents_mod._json_dict({"a": 1}) == {"a": 1}
    assert incidents_mod._json_dict("bad") == {}

    class FakeRule:
        def __init__(self):
            self.shared_groups = [SimpleNamespace(id="g1"), SimpleNamespace(id="g2")]

    monkeypatch.setattr(incidents_mod, "AlertRuleDB", FakeRule)
    assert incidents_mod._shared_group_ids(FakeRule()) == ["g1", "g2"]
    assert incidents_mod._shared_group_ids(object()) == []

    assert incidents_mod.incident_scope_hint_from_labels({"org_id": "org-1"}) == "org-1"
    assert incidents_mod.incident_key_from_labels({"alertname": "CPUHigh", "product": "api"}) == "rule:CPUHigh|scope:api"
    assert incidents_mod.incident_key_from_labels({}) is None

    row = _incident_row("inc-1", annotations={incidents_mod.INCIDENT_META_KEY: json.dumps({incidents_mod.INCIDENT_META_KEY_IDENTITY: "rule:CPUHigh|scope:*"})})
    assert incidents_mod.incident_key_from_db_row(row) == "rule:CPUHigh|scope:*"
    assert incidents_mod.incident_activity_token_from_row(row).startswith("k:")
    assert incidents_mod._extract_metric_state({"mem_state": "critical"}) == "critical"
    assert incidents_mod._parse_metric_states("high,high, low ") == ["high", "low"]
    assert incidents_mod._merge_metric_states({incidents_mod.METRIC_STATES_ANNOTATION_KEY: "high"}, "low", "high") == "high,low"
    assert incidents_mod._is_alert_suppressed({"status": {"state": "suppressed"}}) is True
    assert incidents_mod._incident_access_allowed(
        visibility="group",
        creator_id="owner",
        user_id="user",
        shared_group_ids=["g1"],
        user_group_ids=["g1"],
    ) is True

    called = []

    async def fake_coro():
        called.append("done")

    incidents_mod._run_async(fake_coro())
    assert called == ["done"]


def test_resolve_incident_jira_credentials(monkeypatch):
    monkeypatch.setattr(incidents_mod, "load_tenant_jira_integrations", lambda tenant_id: [{"id": "jira-1"}])
    monkeypatch.setattr(incidents_mod, "integration_is_usable", lambda item: True)
    monkeypatch.setattr(incidents_mod, "jira_integration_credentials", lambda item: {"base_url": "https://jira.example.com", "token": "x"})
    assert incidents_mod._resolve_incident_jira_credentials("tenant-a", "jira-1") == {
        "base_url": "https://jira.example.com",
        "token": "x",
    }

    monkeypatch.setattr(incidents_mod, "integration_is_usable", lambda item: False)
    assert incidents_mod._resolve_incident_jira_credentials("tenant-a", "jira-1") is None

    monkeypatch.setattr(incidents_mod, "get_effective_jira_credentials", lambda tenant_id: {"base_url": "https://jira.example.com", "token": "y"})
    assert incidents_mod._resolve_incident_jira_credentials("tenant-a", None) == {
        "base_url": "https://jira.example.com",
        "token": "y",
    }


def test_incident_service_summary_list_get_update_and_filter(monkeypatch):
    service = incidents_mod.IncidentStorageService()
    rows = [
        _incident_row("public-open", visibility="public", created_by="owner", assignee=None),
        _incident_row("private-open", visibility="private", created_by="user-1", assignee="user-1"),
        _incident_row("group-open", visibility="group", shared_group_ids=["g1"], assignee="other"),
        _incident_row("resolved-hidden", status="resolved", hide_when_resolved=True),
    ]
    rules = [
        SimpleNamespace(tenant_id="tenant-a", name="CPUHigh", visibility="public", created_by="owner", shared_groups=[], org_id=None, enabled=True),
        SimpleNamespace(tenant_id="tenant-a", name="DiskFull", visibility="group", created_by="owner", shared_groups=[SimpleNamespace(id="g1")], org_id="org-1", enabled=True),
    ]
    db = _FakeDB(rows, rules)

    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: _db_session(db))
    monkeypatch.setattr(incidents_mod, "cap_pagination", lambda limit, offset: (limit or 50, offset))
    monkeypatch.setattr(
        incidents_mod,
        "incident_to_pydantic",
        lambda incident: SimpleNamespace(id=incident.id, status=incident.status, assignee=incident.assignee, annotations=incident.annotations, notes=incident.notes),
    )
    monkeypatch.setattr(
        incidents_mod,
        "has_access",
        lambda visibility, creator_id, user_id, shared_group_ids, user_group_ids, require_write=False: visibility != "private" or creator_id == user_id,
    )

    summary = service.get_incident_summary("tenant-a", "user-1", ["g1"])
    assert summary["open_total"] == 3
    assert summary["unassigned_open"] == 1
    assert summary["assigned_to_me_open"] == 1
    assert summary["by_visibility"]["group"] == 1

    listed = service.list_incidents("tenant-a", "user-1", ["g1"])
    assert [item.id for item in listed] == ["public-open", "private-open", "group-open"]
    assert service.list_incidents("tenant-a", "user-1", ["g1"], visibility="group", group_id="g1")[0].id == "group-open"

    fetched = service.get_incident_for_user("private-open", "tenant-a", user_id="user-1", group_ids=[])
    assert fetched is not None
    assert service.get_incident_for_user("private-open", "tenant-a", user_id="other", group_ids=[]) is None

    update_payload = AlertIncidentUpdateRequest(
        assignee="user-1",
        status="resolved",
        note="handled",
        actorUsername="alice",
        jiraTicketKey="ABC-1",
        jiraTicketUrl="https://jira/browse/ABC-1",
        jiraIntegrationId="jira-1",
        hideWhenResolved=True,
    )
    updated = service.update_incident("public-open", "tenant-a", "user-1", update_payload, ["g1"])
    assert updated is not None
    assert rows[0].status == "resolved"
    assert rows[0].assignee == "user-1"
    assert db.flushed == 1
    meta = incidents_mod.parse_meta(rows[0].annotations)
    assert meta["jira_ticket_key"] == "ABC-1"
    assert meta["hide_when_resolved"] is True
    assert any(note["text"] == "handled" for note in rows[0].notes)
    assert any("marked this incident as resolved" in note["text"] for note in rows[0].notes)

    private_row = rows[1]
    with pytest.raises(HTTPException) as exc:
        service.update_incident(
            "private-open",
            "tenant-a",
            "user-1",
            AlertIncidentUpdateRequest(assignee="other-user"),
            [],
        )
    assert exc.value.status_code == 403
    assert private_row.assignee == "user-1"

    visible_alerts = service.filter_alerts_for_user(
        "tenant-a",
        "user-1",
        ["g1"],
        [
            {"labels": {"alertname": "CPUHigh"}},
            {"labels": {"alertname": "DiskFull", "org_id": "org-1"}},
            {"labels": {}},
        ],
    )
    assert len(visible_alerts) == 2