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

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.access.auth_models import Role, TokenData
from models.alerting.incidents import AlertIncident
from services.incidents import helpers as helpers_mod
from services.storage import serializers as serializers_mod


def _user(**kwargs) -> TokenData:
    payload = {
        "user_id": "u1",
        "username": "alice",
        "tenant_id": "tenant",
        "org_id": "org",
        "role": Role.ADMIN,
        "permissions": ["read:incidents"],
        "group_ids": ["g1"],
    }
    payload.update(kwargs)
    return TokenData(**payload)


def _incident(**kwargs) -> AlertIncident:
    payload = {
        "id": "inc-1",
        "fingerprint": "fp-1",
        "alertName": "CPUHigh",
        "severity": "critical",
        "status": "open",
        "notes": [],
        "labels": {},
        "annotations": {},
        "lastSeenAt": datetime.now(timezone.utc),
        "createdAt": datetime.now(timezone.utc),
        "updatedAt": datetime.now(timezone.utc),
    }
    payload.update(kwargs)
    return AlertIncident.model_validate(payload)


def test_incident_helper_formatting_and_author_rewrites():
    incident = _incident(
        annotations={"summary": "CPU > 90", "description": "Service degradation"},
        notes=[
            {"author": "u1", "text": "u1 acknowledged incident", "createdAt": "2024-01-01T00:00:00Z"},
            {"author": "jira:bot", "text": "ignore", "createdAt": "2024-01-01T00:00:00Z"},
            {"author": "", "text": "", "createdAt": "2024-01-01T00:00:00Z"},
        ],
    )
    current_user = _user()

    assert helpers_mod.format_incident_description(incident, "  manual text  ") == "manual text"
    assert helpers_mod.format_incident_description(_incident(annotations={"description": "Detail", "summary": "Summary"}), None) == "Detail -> Summary"
    assert helpers_mod.format_incident_description(_incident(annotations={}), None) == "CPUHigh"
    assert helpers_mod.map_severity_to_jira_priority("critical") == "High"
    assert helpers_mod.map_severity_to_jira_priority("warning") == "Medium"
    assert helpers_mod.map_severity_to_jira_priority("info") == "Low"
    assert helpers_mod.format_note_for_jira_comment(" body ", "Alice", "2024-01-01T00:00:00Z").startswith("Alice · 2024-01-01 00:00:00 UTC")
    assert helpers_mod.format_note_for_jira_comment("body", "Alice", "not-a-date") == "Alice · not-a-date\nbody"
    assert helpers_mod.resolve_note_author_display("", current_user) == "Unknown user"
    assert helpers_mod.resolve_note_author_display("u1", current_user) == "alice"
    assert helpers_mod.resolve_note_author_display("550e8400-e29b-41d4-a716-446655440000", current_user) == "Unknown user"
    assert helpers_mod.resolve_note_author_display("bob", current_user) == "bob"
    assert helpers_mod.rewrite_note_text_for_author("u1 updated status", "u1", "alice") == "alice updated status"
    assert helpers_mod.rewrite_note_text_for_author("u1 updated status", "u1", "Unknown user") == "u1 updated status"
    assert helpers_mod.rewrite_note_text_for_actor("u1 updated status", "u1", "alice") == "alice updated status"

    bodies = helpers_mod.build_formatted_incident_note_bodies(incident, current_user)
    assert len(bodies) == 1
    assert "alice acknowledged incident" in bodies[0]


@pytest.mark.asyncio
async def test_incident_helper_jira_sync_paths(monkeypatch):
    current_user = _user()
    incident = _incident(id="inc-1", jiraTicketKey="ABC-1")
    calls = []

    async def fake_add_comment(issue_key, text, credentials=None):
        calls.append(("comment", issue_key, text, credentials))

    async def fake_transition_to_todo(issue_key, credentials=None):
        calls.append(("todo", issue_key, credentials))

    async def fake_transition_to_in_progress(issue_key, credentials=None):
        calls.append(("progress", issue_key, credentials))

    async def fake_transition_to_done(issue_key, credentials=None):
        calls.append(("done", issue_key, credentials))

    monkeypatch.setattr(helpers_mod, "resolve_incident_jira_credentials", lambda *_args: {"base_url": "https://jira"})
    monkeypatch.setattr(helpers_mod.jira_service, "add_comment", fake_add_comment)
    monkeypatch.setattr(helpers_mod.jira_service, "transition_issue_to_todo", fake_transition_to_todo)
    monkeypatch.setattr(helpers_mod.jira_service, "transition_issue_to_in_progress", fake_transition_to_in_progress)
    monkeypatch.setattr(helpers_mod.jira_service, "transition_issue_to_done", fake_transition_to_done)

    await helpers_mod.sync_note_to_jira_comment(incident, tenant_id="tenant", current_user=current_user, note_text="u1 investigating")
    await helpers_mod.move_incident_ticket_to_todo(incident, tenant_id="tenant", current_user=current_user)
    await helpers_mod.move_incident_ticket_to_in_progress(incident, tenant_id="tenant", current_user=current_user)
    await helpers_mod.move_incident_ticket_to_done(incident, tenant_id="tenant", current_user=current_user)

    assert calls[0][0] == "comment"
    assert "alice" in calls[0][2]
    assert calls[1][0] == "todo"
    assert calls[2][0] == "progress"
    assert calls[3][0] == "done"

    monkeypatch.setattr(helpers_mod, "resolve_incident_jira_credentials", lambda *_args: None)
    await helpers_mod.sync_note_to_jira_comment(incident, tenant_id="tenant", current_user=current_user, note_text="skip")

    async def raise_jira_error(*_args, **_kwargs):
        raise helpers_mod.JiraError("boom")

    monkeypatch.setattr(helpers_mod, "resolve_incident_jira_credentials", lambda *_args: {"base_url": "https://jira"})
    monkeypatch.setattr(helpers_mod.jira_service, "add_comment", raise_jira_error)
    monkeypatch.setattr(helpers_mod.jira_service, "transition_issue_to_todo", raise_jira_error)
    monkeypatch.setattr(helpers_mod.jira_service, "transition_issue_to_in_progress", raise_jira_error)
    monkeypatch.setattr(helpers_mod.jira_service, "transition_issue_to_done", raise_jira_error)
    await helpers_mod.sync_note_to_jira_comment(incident, tenant_id="tenant", current_user=current_user, note_text="still safe")
    await helpers_mod.move_incident_ticket_to_todo(incident, tenant_id="tenant", current_user=current_user)
    await helpers_mod.move_incident_ticket_to_in_progress(incident, tenant_id="tenant", current_user=current_user)
    await helpers_mod.move_incident_ticket_to_done(incident, tenant_id="tenant", current_user=current_user)


def test_storage_serializers_cover_rule_channel_and_incident_payloads():
    now = datetime.now(timezone.utc)
    rule = SimpleNamespace(
        id="rule-1",
        created_by="owner",
        org_id="org-1",
        name="CPUHigh",
        expr="up == 0",
        duration="5m",
        severity="critical",
        labels={"service": "api"},
        annotations={"summary": "CPU"},
        enabled=True,
        group="infra",
        notification_channels=["chan-1"],
        visibility="group",
        shared_groups=[SimpleNamespace(id="g1")],
        is_hidden=True,
    )
    channel = SimpleNamespace(
        id="chan-1",
        name="Pager",
        type="pagerduty",
        enabled=True,
        config={"secret": "value"},
        created_by="owner",
        visibility="private",
        shared_groups=[SimpleNamespace(id="g1")],
        is_hidden=False,
    )
    incident = SimpleNamespace(
        id="inc-1",
        fingerprint="fp-1",
        alert_name="CPUHigh",
        severity="critical",
        status="IncidentStatus.RESOLVED",
        assignee="u1",
        notes=[{"author": "system", "text": "closed", "createdAt": now.isoformat()}],
        labels={"service": "api"},
        annotations={
            serializers_mod.INCIDENT_META_KEY: '{"visibility":"group","shared_group_ids":["g1"],"jira_ticket_key":"ABC-1","jira_ticket_url":"https://jira/browse/ABC-1","jira_integration_id":"jira-1","correlation_id":"corr-1","user_managed":true,"hide_when_resolved":true}',
            "summary": "CPU high",
        },
        starts_at=now,
        last_seen_at=now,
        resolved_at=now,
        created_at=now,
        updated_at=now,
    )

    rule_model = serializers_mod.rule_to_pydantic(rule)
    assert rule_model.shared_group_ids == ["g1"]
    assert rule_model.is_hidden is True

    owner_view = serializers_mod.channel_to_pydantic_for_viewer(channel, viewer_user_id="owner")
    other_view = serializers_mod.channel_to_pydantic_for_viewer(channel, viewer_user_id="other")
    default_view = serializers_mod.channel_to_pydantic(channel)
    assert owner_view.config == {"secret": "value"}
    assert other_view.config == {}
    assert default_view.config == {"secret": "value"}

    incident_model = serializers_mod.incident_to_pydantic(incident)
    assert incident_model.status == "resolved"
    assert incident_model.visibility == "group"
    assert incident_model.shared_group_ids == ["g1"]
    assert incident_model.jira_ticket_key == "ABC-1"
    assert incident_model.annotations["beobservantCorrelationId"] == "corr-1"
    assert serializers_mod.incident_to_pydantic(
        SimpleNamespace(
            id="inc-2",
            fingerprint="fp-2",
            alert_name="DiskFull",
            severity="warning",
            status="open",
            assignee=None,
            notes=[],
            labels={},
            annotations={serializers_mod.INCIDENT_META_KEY: '{"visibility":"invalid"}'},
            starts_at=None,
            last_seen_at=now,
            resolved_at=None,
            created_at=now,
            updated_at=now,
        )
    ).visibility == "public"