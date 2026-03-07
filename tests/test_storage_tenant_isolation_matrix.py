"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations
import uuid
import pytest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from database import get_db_session
from db_models import Tenant
from models.alerting.channels import ChannelType, NotificationChannelCreate
from models.alerting.incidents import AlertIncidentUpdateRequest
from models.alerting.rules import AlertRuleCreate, RuleSeverity
from services.storage_db_service import DatabaseStorageService


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _ensure_tenant(tenant_id: str) -> None:
    with get_db_session() as db:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if tenant is None:
            db.add(
                Tenant(
                    id=tenant_id,
                    name=_id(f"tenant-{tenant_id}"),
                    display_name=f"Tenant {tenant_id}",
                    is_active=True,
                    settings={},
                )
            )


def _ensure_tenant_user(tenant_id: str, user_id: str) -> None:
    _ensure_tenant(tenant_id)


@pytest.mark.skipif(
    not __import__("database", fromlist=[""]).connection_test(),
    reason="DB not available",
)
def test_incident_tenant_isolation_matrix():
    service = DatabaseStorageService()
    tenant_a, tenant_b = _id("tenant-a"), _id("tenant-b")
    user_a, user_b = _id("user-a"), _id("user-b")
    _ensure_tenant_user(tenant_a, user_a)
    _ensure_tenant_user(tenant_b, user_b)

    service.sync_incidents_from_alerts(
        tenant_a,
        [
            {
                "fingerprint": _id("fp-a"),
                "labels": {"alertname": "AOnlyAlert", "severity": "critical"},
                "annotations": {"summary": "a"},
            }
        ],
        False,
    )
    service.sync_incidents_from_alerts(
        tenant_b,
        [
            {
                "fingerprint": _id("fp-b"),
                "labels": {"alertname": "BOnlyAlert", "severity": "warning"},
                "annotations": {"summary": "b"},
            }
        ],
        False,
    )

    incidents_a = service.list_incidents(tenant_a, user_a, group_ids=[])
    incidents_b = service.list_incidents(tenant_b, user_b, group_ids=[])
    assert incidents_a and incidents_b
    assert all(inc.alert_name == "AOnlyAlert" for inc in incidents_a)
    assert all(inc.alert_name == "BOnlyAlert" for inc in incidents_b)

    incident_a_id = incidents_a[0].id
    assert service.get_incident_for_user(incident_a_id, tenant_b, user_b, []) is None
    assert service.update_incident(
        incident_a_id,
        tenant_b,
        user_b,
        AlertIncidentUpdateRequest(note="cross-tenant attempt"),
    ) is None


@pytest.mark.skipif(
    not __import__("database", fromlist=[""]).connection_test(),
    reason="DB not available",
)
def test_rule_tenant_isolation_matrix():
    service = DatabaseStorageService()
    tenant_a, tenant_b = _id("tenant-a"), _id("tenant-b")
    user_a, user_b = _id("user-a"), _id("user-b")
    _ensure_tenant_user(tenant_a, user_a)
    _ensure_tenant_user(tenant_b, user_b)

    rule = service.create_alert_rule(
        AlertRuleCreate(
            name=_id("rule"),
            expression='sum(rate(http_requests_total[5m])) > 0',
            severity=RuleSeverity.WARNING,
            groupName="tenant-isolation",
            enabled=True,
            labels={},
            annotations={},
        ),
        tenant_a,
        user_a,
        group_ids=[],
    )

    assert service.get_alert_rule(rule.id, tenant_b, user_b, []) is None
    assert (
        service.update_alert_rule(
            rule.id,
            AlertRuleCreate(
                name=_id("rule-updated"),
                expression='up == 0',
                severity=RuleSeverity.CRITICAL,
                groupName="tenant-isolation",
                enabled=True,
                labels={},
                annotations={},
            ),
            tenant_b,
            user_b,
            group_ids=[],
        )
        is None
    )
    assert service.delete_alert_rule(rule.id, tenant_b, user_b, group_ids=[]) is False


@pytest.mark.skipif(
    not __import__("database", fromlist=[""]).connection_test(),
    reason="DB not available",
)
def test_rule_updates_require_owner_even_when_rule_is_shared():
    service = DatabaseStorageService()
    tenant_id = _id("tenant")
    owner_id, viewer_id = _id("owner"), _id("viewer")
    _ensure_tenant_user(tenant_id, owner_id)

    rule = service.create_alert_rule(
        AlertRuleCreate(
            name=_id("shared-rule"),
            expression="up == 0",
            severity=RuleSeverity.WARNING,
            groupName="owner-only-updates",
            enabled=True,
            labels={},
            annotations={},
            visibility="tenant",
        ),
        tenant_id,
        owner_id,
        group_ids=[],
    )
    # Viewer can read because the rule is tenant-visible.
    assert service.get_alert_rule(rule.id, tenant_id, viewer_id, []) is not None
    # Viewer cannot mutate because writes are owner-only.
    assert (
        service.update_alert_rule(
            rule.id,
            AlertRuleCreate(
                name=_id("attempted-update"),
                expression="up == 1",
                severity=RuleSeverity.CRITICAL,
                groupName="owner-only-updates",
                enabled=True,
                labels={},
                annotations={},
                visibility="tenant",
            ),
            tenant_id,
            viewer_id,
            group_ids=[],
        )
        is None
    )
    assert service.delete_alert_rule(rule.id, tenant_id, viewer_id, group_ids=[]) is False


@pytest.mark.skipif(
    not __import__("database", fromlist=[""]).connection_test(),
    reason="DB not available",
)
def test_channel_tenant_isolation_matrix():
    service = DatabaseStorageService()
    tenant_a, tenant_b = _id("tenant-a"), _id("tenant-b")
    user_a, user_b = _id("user-a"), _id("user-b")
    _ensure_tenant_user(tenant_a, user_a)
    _ensure_tenant_user(tenant_b, user_b)

    channel = service.create_notification_channel(
        NotificationChannelCreate(
            name=_id("channel"),
            type=ChannelType.SLACK,
            config={"webhook_url": "https://hooks.slack.test/abc"},
            enabled=True,
            visibility="private",
        ),
        tenant_a,
        user_a,
        group_ids=[],
    )

    assert service.get_notification_channel(channel.id, tenant_b, user_b, group_ids=[]) is None
    assert (
        service.update_notification_channel(
            channel.id,
            NotificationChannelCreate(
                name=_id("channel-updated"),
                type=ChannelType.SLACK,
                config={"webhook_url": "https://hooks.slack.test/def"},
                enabled=True,
                visibility="private",
            ),
            tenant_b,
            user_b,
            group_ids=[],
        )
        is None
    )
    assert service.delete_notification_channel(channel.id, tenant_b, user_b, group_ids=[]) is False


@pytest.mark.skipif(
    not __import__("database", fromlist=[""]).connection_test(),
    reason="DB not available",
)
def test_toggle_jira_hidden_is_idempotent():
    service = DatabaseStorageService()
    tenant_id = _id("tenant")
    user_id = _id("user")
    integration_id = _id("jira")
    _ensure_tenant_user(tenant_id, user_id)

    assert service.toggle_jira_integration_hidden(tenant_id, user_id, integration_id, True) is True
    assert service.toggle_jira_integration_hidden(tenant_id, user_id, integration_id, True) is True

    hidden_ids = service.get_hidden_jira_integration_ids(tenant_id, user_id)
    assert hidden_ids.count(integration_id) == 1

    assert service.toggle_jira_integration_hidden(tenant_id, user_id, integration_id, False) is True
    assert integration_id not in service.get_hidden_jira_integration_ids(tenant_id, user_id)


@pytest.mark.skipif(
    not __import__("database", fromlist=[""]).connection_test(),
    reason="DB not available",
)
def test_incident_sync_idempotent_and_out_of_order_updates():
    service = DatabaseStorageService()
    tenant_id = _id("tenant")
    user_id = _id("user")
    _ensure_tenant(tenant_id)

    fingerprint = _id("fp")
    alert_open = {
        "fingerprint": fingerprint,
        "labels": {"alertname": "IdempotentAlert", "severity": "critical"},
        "annotations": {"summary": "open"},
    }
    alert_reopen = {
        "fingerprint": fingerprint,
        "labels": {"alertname": "IdempotentAlert", "severity": "warning"},
        "annotations": {"summary": "reopen"},
    }

    service.sync_incidents_from_alerts(tenant_id, [alert_open], resolve_missing=False)
    service.sync_incidents_from_alerts(tenant_id, [alert_open], resolve_missing=False)
    open_incidents = service.list_incidents(tenant_id, user_id, group_ids=[], status="open")
    assert len(open_incidents) == 1
    assert open_incidents[0].severity == "critical"

    service.sync_incidents_from_alerts(tenant_id, [], resolve_missing=True)
    resolved_incidents = service.list_incidents(tenant_id, user_id, group_ids=[], status="resolved")
    assert len(resolved_incidents) == 1

    service.sync_incidents_from_alerts(tenant_id, [alert_reopen], resolve_missing=False)
    reopened = service.list_incidents(tenant_id, user_id, group_ids=[], status="open")
    assert len(reopened) == 1
    assert reopened[0].severity == "warning"


@pytest.mark.skipif(
    not __import__("database", fromlist=[""]).connection_test(),
    reason="DB not available",
)
def test_group_incident_requires_active_group_membership_even_for_creator():
    service = DatabaseStorageService()
    tenant_id = _id("tenant")
    owner_id = _id("owner")
    _ensure_tenant_user(tenant_id, owner_id)

    rule = service.create_alert_rule(
        AlertRuleCreate(
            name=_id("group-rule"),
            expression="up == 0",
            severity=RuleSeverity.WARNING,
            groupName="group-incidents",
            enabled=True,
            labels={},
            annotations={},
            visibility="group",
            sharedGroupIds=["g1"],
        ),
        tenant_id,
        owner_id,
        group_ids=["g1"],
    )
    assert rule is not None

    service.sync_incidents_from_alerts(
        tenant_id,
        [
            {
                "fingerprint": _id("fp-group"),
                "labels": {"alertname": rule.name, "severity": "critical"},
                "annotations": {"summary": "group incident"},
            }
        ],
        False,
    )

    visible_with_group = service.list_incidents(tenant_id, owner_id, group_ids=["g1"])
    assert len(visible_with_group) == 1
    incident_id = visible_with_group[0].id

    hidden_without_group = service.list_incidents(tenant_id, owner_id, group_ids=[])
    assert hidden_without_group == []

    assert service.get_incident_for_user(incident_id, tenant_id, owner_id, group_ids=[]) is None
    assert (
        service.update_incident(
            incident_id,
            tenant_id,
            owner_id,
            AlertIncidentUpdateRequest(note="should-not-work"),
            group_ids=[],
        )
        is None
    )
