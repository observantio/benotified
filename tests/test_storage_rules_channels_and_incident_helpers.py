"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.alerting.channels import NotificationChannelCreate
from models.alerting.rules import AlertRuleCreate, RuleSeverity
from services.storage import channels as channels_mod
from services.storage import incidents as incidents_mod
from services.storage import rules as rules_mod


class FakeQuery:
    def __init__(self, rows):
        self.rows = rows

    def options(self, *_args, **_kwargs):
        return self

    def filter(self, *_args, **_kwargs):
        return self

    def join(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def offset(self, *_args, **_kwargs):
        return self

    def limit(self, *_args, **_kwargs):
        return self

    def all(self):
        if self.rows is None:
            return []
        if isinstance(self.rows, list):
            return self.rows
        return [self.rows]

    def first(self):
        if isinstance(self.rows, list):
            return self.rows[0] if self.rows else None
        return self.rows


class FakeDB:
    def __init__(self, *results):
        self.results = list(results)
        self.added = []
        self.deleted = []
        self.flush_count = 0

    def query(self, *_args, **_kwargs):
        rows = self.results.pop(0) if self.results else None
        return FakeQuery(rows)

    def add(self, obj):
        self.added.append(obj)

    def delete(self, obj):
        self.deleted.append(obj)

    def flush(self):
        self.flush_count += 1


class FakeCtx:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        return self.db

    def __exit__(self, exc_type, exc, tb):
        return False


def _rule(**kwargs):
    payload = {
        "id": "rule-1",
        "tenant_id": "tenant",
        "name": "CPUHigh",
        "org_id": None,
        "created_by": "owner",
        "visibility": "private",
        "shared_groups": [],
        "enabled": True,
        "group": "compute",
        "expr": "up == 0",
        "duration": "5m",
        "severity": "warning",
        "labels": {},
        "annotations": {},
        "notification_channels": [],
    }
    payload.update(kwargs)
    return SimpleNamespace(**payload)


def _channel(**kwargs):
    payload = {
        "id": "chan-1",
        "tenant_id": "tenant",
        "created_by": "owner",
        "name": "Email",
        "type": "email",
        "config": {"token": "enc"},
        "enabled": True,
        "visibility": "private",
        "shared_groups": [],
    }
    payload.update(kwargs)
    return SimpleNamespace(**payload)


def test_rule_helpers_and_delivery_lookup(monkeypatch):
    svc = rules_mod.RuleStorageService()
    shared = SimpleNamespace(id="g1")
    rule_private = _rule(shared_groups=[shared])
    assert rules_mod._shared_group_ids(rule_private) == ["g1"]
    assert rules_mod._visibility_of(rule_private) == "private"
    assert rules_mod._creator_of(rule_private) == "owner"

    monkeypatch.setattr(rules_mod, "rule_to_pydantic", lambda obj: {"id": obj.id, "org_id": getattr(obj, "org_id", None)})

    db = FakeDB([])
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(db))
    assert svc.get_alert_rule_by_name_for_delivery("tenant", "") is None
    assert svc.get_alert_rule_by_name_for_delivery("tenant", "CPUHigh") is None

    org_rule = _rule(id="rule-org", org_id="org-1")
    fallback_rule = _rule(id="rule-fallback", org_id=None)
    db = FakeDB([fallback_rule, org_rule])
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(db))
    assert svc.get_alert_rule_by_name_for_delivery("tenant", "CPUHigh", org_id="org-1") == {"id": "rule-org", "org_id": "org-1"}


def test_rule_storage_crud_and_visibility(monkeypatch):
    svc = rules_mod.RuleStorageService()
    rule1 = _rule(id="rule-1", visibility="public")
    rule2 = _rule(id="rule-2", visibility="group", shared_groups=[SimpleNamespace(id="g2")])
    access_calls = []

    def fake_has_access(visibility, creator_id, user_id, shared_group_ids, group_ids, require_write=False):
        access_calls.append((visibility, creator_id, user_id, tuple(shared_group_ids), tuple(group_ids), require_write))
        if require_write:
            return visibility != "group"
        return visibility != "group"

    monkeypatch.setattr(rules_mod, "has_access", fake_has_access)
    monkeypatch.setattr(rules_mod, "cap_pagination", lambda limit, offset: (limit or 50, offset))
    monkeypatch.setattr(rules_mod, "rule_to_pydantic", lambda obj: {"id": obj.id, "visibility": obj.visibility})

    db = FakeDB([("rule-1",)], [("CPUHigh",)], [rule1, rule2], [rule1, rule2], [rule1, rule2], rule1, rule2)
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(db))

    assert svc.get_hidden_rule_ids("tenant", "user") == ["rule-1"]
    assert svc.get_hidden_rule_names("tenant", "user") == ["CPUHigh"]
    assert svc.get_public_alert_rules("tenant") == [{"id": "rule-1", "visibility": "public"}, {"id": "rule-2", "visibility": "group"}]
    assert svc.get_alert_rules("tenant", "user", ["g1"], limit=10, offset=2) == [{"id": "rule-1", "visibility": "public"}]
    assert svc.get_alert_rules_with_owner("tenant", "user", ["g1"], limit=10, offset=2) == [({"id": "rule-1", "visibility": "public"}, "owner")]
    assert svc.get_alert_rule_raw("rule-1", "tenant") is rule1
    assert svc.get_alert_rule("rule-2", "tenant", "user", ["g1"]) is None
    assert access_calls

    missing_db = FakeDB(None, _rule(id="rule-hide"), None, _rule(id="rule-show"), SimpleNamespace(id="existing"))
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(missing_db))
    assert svc.toggle_rule_hidden("tenant", "user", "missing", True) is False
    assert svc.toggle_rule_hidden("tenant", "user", "rule-hide", True) is True
    assert len(missing_db.added) == 1
    assert svc.toggle_rule_hidden("tenant", "user", "rule-show", False) is True
    assert len(missing_db.deleted) == 1

    assign_calls = []
    monkeypatch.setattr(rules_mod, "ensure_tenant_exists", lambda *_args: assign_calls.append("tenant"))
    monkeypatch.setattr(
        rules_mod,
        "assign_shared_groups",
        lambda obj, *_args, **kwargs: assign_calls.append((obj.visibility, tuple(kwargs.get("actor_group_ids") or []))),
    )
    monkeypatch.setattr(rules_mod, "rule_to_pydantic", lambda obj: {"id": obj.id, "name": obj.name, "visibility": obj.visibility})

    create_db = FakeDB()
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(create_db))
    created = svc.create_alert_rule(
        AlertRuleCreate.model_validate(
            {
                "name": "MemHigh",
                "expression": "mem > 90",
                "severity": RuleSeverity.CRITICAL,
                "groupName": "infra",
                "notificationChannels": ["chan-1"],
                "visibility": "group",
                "sharedGroupIds": ["g1"],
            }
        ),
        "tenant",
        "owner",
        ["g1"],
    )
    assert created["visibility"] == "group"
    assert create_db.flush_count == 1

    update_target = _rule(id="rule-1", visibility="private")
    update_db = FakeDB(update_target)
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(update_db))
    denied = svc.update_alert_rule(
        "rule-1",
        AlertRuleCreate.model_validate({"name": "New", "expression": "up", "severity": "warning", "groupName": "g"}),
        "tenant",
        "owner",
        ["g1"],
    )
    assert denied["name"] == "New"

    monkeypatch.setattr(rules_mod, "has_access", lambda *_args, **kwargs: not kwargs.get("require_write", False))
    blocked_db = FakeDB(_rule(id="rule-2", visibility="private"))
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(blocked_db))
    assert svc.delete_alert_rule("rule-2", "tenant", "owner", ["g1"]) is False

    monkeypatch.setattr(rules_mod, "has_access", lambda *_args, **_kwargs: True)
    delete_db = FakeDB(_rule(id="rule-3", visibility="private"))
    monkeypatch.setattr(rules_mod, "get_db_session", lambda: FakeCtx(delete_db))
    assert svc.delete_alert_rule("rule-3", "tenant", "owner", ["g1"]) is True
    assert len(delete_db.deleted) == 1


def test_channel_helpers_and_storage_branches(monkeypatch):
    svc = channels_mod.ChannelStorageService()
    private_rule = _rule(visibility="private", created_by="owner")
    private_channel = _channel(visibility="private", created_by="owner")
    other_channel = _channel(id="chan-2", visibility="private", created_by="other")
    group_rule = _rule(visibility="group", shared_groups=[SimpleNamespace(id="g1")])
    group_channel = _channel(visibility="group", shared_groups=[SimpleNamespace(id="g1")])
    public_channel = _channel(id="chan-3", visibility="public")

    assert channels_mod._shared_group_ids(group_channel) == ["g1"]
    assert channels_mod._visibility_of(private_channel) == "private"
    assert channels_mod._creator_of(private_channel) == "owner"
    assert channels_mod._config_dict(private_channel) == {"token": "enc"}
    assert svc._rule_channel_compatible(private_rule, private_channel) is True
    assert svc._rule_channel_compatible(private_rule, other_channel) is False
    assert svc._rule_channel_compatible(group_rule, group_channel) is True
    assert svc._rule_channel_compatible(group_rule, public_channel) is True
    assert svc._rule_channel_compatible(_rule(visibility="public"), public_channel) is True

    monkeypatch.setattr(channels_mod, "cap_pagination", lambda limit, offset: (limit or 50, offset))
    monkeypatch.setattr(channels_mod, "has_access", lambda visibility, *_args, **_kwargs: visibility != "group")
    monkeypatch.setattr(channels_mod, "decrypt_config", lambda cfg: {**cfg, "decrypted": True})
    monkeypatch.setattr(channels_mod, "encrypt_config", lambda cfg: {**cfg, "encrypted": True})
    monkeypatch.setattr(channels_mod, "channel_to_pydantic", lambda obj: {"id": obj.id, "config": obj.config})
    monkeypatch.setattr(channels_mod, "channel_to_pydantic_for_viewer", lambda obj, user_id: {"id": obj.id, "user": user_id, "config": obj.config})
    monkeypatch.setattr(channels_mod, "ensure_tenant_exists", lambda *_args: None)
    monkeypatch.setattr(channels_mod, "assign_shared_groups", lambda *_args, **_kwargs: None)

    db = FakeDB([private_channel, group_channel], private_channel)
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(db))
    listed = svc.get_notification_channels("tenant", "user", ["g1"], limit=10, offset=1)
    assert listed == [{"id": "chan-1", "user": "user", "config": {"token": "enc", "decrypted": True}}]
    assert svc.get_notification_channel("chan-1", "tenant", "user", ["g1"])["id"] == "chan-1"

    denied_db = FakeDB(group_channel)
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(denied_db))
    assert svc.get_notification_channel("chan-2", "tenant", "user", ["g2"]) is None

    create_db = FakeDB()
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(create_db))
    created = svc.create_notification_channel(
        NotificationChannelCreate.model_validate(
            {
                "name": "Slack",
                "type": "slack",
                "config": {"webhook": "url"},
                "visibility": "group",
                "sharedGroupIds": ["g1"],
            }
        ),
        "tenant",
        "owner",
        ["g1"],
    )
    assert created["user"] == "owner"
    assert create_db.flush_count == 1

    update_target = _channel(id="chan-1", created_by="owner")
    update_db = FakeDB(update_target)
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(update_db))
    updated = svc.update_notification_channel(
        "chan-1",
        NotificationChannelCreate.model_validate({"name": "Teams", "type": "teams", "config": {"hook": "1"}}),
        "tenant",
        "owner",
        ["g1"],
    )
    assert updated["id"] == "chan-1"

    missing_update_db = FakeDB(_channel(id="chan-2", created_by="other"))
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(missing_update_db))
    assert svc.update_notification_channel(
        "chan-2",
        NotificationChannelCreate.model_validate({"name": "Nope", "type": "email", "config": {}}),
        "tenant",
        "owner",
    ) is None

    delete_db = FakeDB(_channel(id="chan-1", created_by="owner"), _channel(id="chan-3", created_by="other"), _channel(id="chan-4", created_by="owner"))
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(delete_db))
    assert svc.delete_notification_channel("chan-1", "tenant", "owner") is True
    assert svc.is_notification_channel_owner("chan-3", "tenant", "owner") is False
    assert svc.is_notification_channel_owner("chan-4", "tenant", "owner") is True

    monkeypatch.setattr(svc, "get_notification_channel", lambda *_args, **_kwargs: None)
    assert svc.test_notification_channel("chan-1", "tenant", "owner") == {"success": False, "error": "Channel not found"}
    monkeypatch.setattr(svc, "get_notification_channel", lambda *_args, **_kwargs: SimpleNamespace(name="Slack", type="slack"))
    assert svc.test_notification_channel("chan-1", "tenant", "owner")["success"] is True

    rule_with_specific = _rule(id="rule-a", notification_channels=["chan-1", "missing", "chan-2"], visibility="private")
    rule_no_specific = _rule(id="rule-b", notification_channels=[], visibility="group", shared_groups=[SimpleNamespace(id="g1")])
    ch1 = _channel(id="chan-1", visibility="private", created_by="owner")
    ch2 = _channel(id="chan-2", visibility="private", created_by="other", enabled=False)
    ch3 = _channel(id="chan-3", visibility="group", shared_groups=[SimpleNamespace(id="g1")])
    ch4 = _channel(id="chan-4", visibility="public")
    delivery_db = FakeDB([rule_with_specific, rule_no_specific], [ch1, ch2, ch3, ch4])
    monkeypatch.setattr(channels_mod, "get_db_session", lambda: FakeCtx(delivery_db))
    delivered = svc.get_notification_channels_for_rule_name("tenant", "CPUHigh", org_id="org-x")
    assert delivered == [
        {"id": "chan-1", "config": {"token": "enc", "decrypted": True}},
        {"id": "chan-3", "config": {"token": "enc", "decrypted": True}},
        {"id": "chan-4", "config": {"token": "enc", "decrypted": True}},
    ]


def test_incident_run_async_falls_back_to_new_loop(monkeypatch):
    events = []

    async def noop():
        return None

    def fake_asyncio_run(_coro):
        raise RuntimeError("loop running")

    class FakeLoop:
        def run_until_complete(self, coro):
            events.append("run")
            coro.close()

        def close(self):
            events.append("close")

    monkeypatch.setattr(incidents_mod.asyncio, "run", fake_asyncio_run)
    monkeypatch.setattr(incidents_mod.asyncio, "new_event_loop", lambda: FakeLoop())

    incidents_mod._run_async(noop())

    assert events == ["run", "close"]


@pytest.mark.asyncio
async def test_incident_helpers_and_jira_side_effects(monkeypatch):
    class FakeAlertRule:
        def __init__(self, shared_groups):
            self.shared_groups = shared_groups

    monkeypatch.setattr(incidents_mod, "AlertRuleDB", FakeAlertRule)
    shared_rule = FakeAlertRule([SimpleNamespace(id="g1")])
    incident_row = SimpleNamespace(
        annotations={incidents_mod.INCIDENT_META_KEY: '{"incident_key":"rule:CPU|scope:tenant-a"}'},
        labels={"alertname": "CPU", "org_id": "tenant-a"},
        alert_name="CPU",
        fingerprint="fp-1",
    )

    assert incidents_mod._json_dict({"a": 1}) == {"a": 1}
    assert incidents_mod._json_dict("x") == {}
    assert incidents_mod._shared_group_ids(shared_rule) == ["g1"]
    assert incidents_mod.incident_scope_hint_from_labels({"org_id": "tenant-a"}) == "tenant-a"
    assert incidents_mod.incident_key_from_labels({"alertname": "CPU", "org_id": "tenant-a"}) == "rule:CPU|scope:tenant-a"
    assert incidents_mod.incident_key_from_labels({"severity": "warning"}) is None
    assert incidents_mod.incident_key_from_db_row(incident_row) == "rule:CPU|scope:tenant-a"
    assert incidents_mod.incident_activity_token_from_row(incident_row) == "k:rule:CPU|scope:tenant-a"
    assert incidents_mod._extract_metric_state({"metric_state": "critical"}) == "critical"
    assert incidents_mod._parse_metric_states("a, b,a,,c") == ["a", "b", "c"]
    assert incidents_mod._merge_metric_states({incidents_mod.METRIC_STATES_ANNOTATION_KEY: "warn"}, "warn", "crit") == "warn,crit"
    monkeypatch.setattr(incidents_mod, "is_suppressed_status", lambda status: status == {"state": "suppressed"})
    assert incidents_mod._is_alert_suppressed({"status": {"state": "suppressed"}}) is True
    assert incidents_mod._incident_access_allowed(
        visibility="group",
        creator_id="owner",
        user_id="user",
        shared_group_ids=["g1"],
        user_group_ids=["g1"],
    ) is True

    usable_integration = {"id": "jira-1", "base_url": "https://jira", "username": "u"}
    monkeypatch.setattr(incidents_mod, "load_tenant_jira_integrations", lambda _tenant: [usable_integration])
    monkeypatch.setattr(incidents_mod, "integration_is_usable", lambda item: bool(item.get("base_url")))
    monkeypatch.setattr(incidents_mod, "jira_integration_credentials", lambda item: {"base_url": item["base_url"], "user": item["username"]})
    monkeypatch.setattr(incidents_mod, "get_effective_jira_credentials", lambda _tenant: {"base_url": "https://tenant-jira", "token": "x"})
    assert incidents_mod._resolve_incident_jira_credentials("tenant", "jira-1") == {"base_url": "https://jira", "user": "u"}
    assert incidents_mod._resolve_incident_jira_credentials("tenant", None) == {"base_url": "https://tenant-jira", "token": "x"}

    notes = []

    async def fake_transition_issue_to_todo(**kwargs):
        notes.append(("todo", kwargs))

    async def fake_add_comment(**kwargs):
        notes.append(("comment", kwargs))

    monkeypatch.setattr(incidents_mod, "_resolve_incident_jira_credentials", lambda *_args: {"base_url": "https://jira"})

    def fake_run_async(coro):
        notes.append((coro.cr_code.co_name, None))
        coro.close()

    monkeypatch.setattr(incidents_mod, "_run_async", fake_run_async)
    monkeypatch.setattr(incidents_mod.jira_service, "transition_issue_to_todo", fake_transition_issue_to_todo)
    monkeypatch.setattr(incidents_mod.jira_service, "add_comment", fake_add_comment)
    jira_incident = SimpleNamespace(
        annotations={incidents_mod.INCIDENT_META_KEY: '{"jira_ticket_key":"ABC-1","jira_integration_id":"jira-1"}'},
    )
    incidents_mod._move_reopened_incident_jira_ticket_to_todo("tenant", jira_incident)
    incidents_mod._sync_reopened_incident_note_to_jira(
        "tenant",
        jira_incident,
        note_text="Reopened",
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    assert notes[0][0] == "fake_transition_issue_to_todo"
    assert notes[1][0] == "fake_add_comment"

    monkeypatch.setattr(incidents_mod, "_resolve_incident_jira_credentials", lambda *_args: None)
    incidents_mod._move_reopened_incident_jira_ticket_to_todo("tenant", jira_incident)
    incidents_mod._sync_reopened_incident_note_to_jira(
        "tenant",
        jira_incident,
        note_text="Ignored",
        created_at=datetime.now(timezone.utc),
    )


def test_incident_update_private_assignment_guard(monkeypatch):
    svc = incidents_mod.IncidentStorageService()
    incident = SimpleNamespace(
        id="inc-1",
        tenant_id="tenant",
        status="open",
        assignee=None,
        annotations={incidents_mod.INCIDENT_META_KEY: '{"visibility":"private","created_by":"owner"}'},
    )
    db = FakeDB(incident)
    monkeypatch.setattr(incidents_mod, "get_db_session", lambda: FakeCtx(db))
    monkeypatch.setattr(incidents_mod, "normalize_storage_visibility", lambda value: value)
    monkeypatch.setattr(incidents_mod, "_incident_access_allowed", lambda **_kwargs: True)
    with pytest.raises(HTTPException) as exc:
        svc.update_incident(
            "inc-1",
            "tenant",
            "owner",
            incidents_mod.AlertIncidentUpdateRequest(assignee="someone-else"),
            [],
        )
    assert exc.value.status_code == 403