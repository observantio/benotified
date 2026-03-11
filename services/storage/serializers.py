"""
Serializers for converting internal storage models to Pydantic models used in API responses, ensuring proper data formatting and handling of sensitive information based on user permissions.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from db_models import AlertIncident as AlertIncidentDB
from db_models import AlertRule as AlertRuleDB
from db_models import NotificationChannel as NotificationChannelDB
from models.alerting.channels import NotificationChannel as NotificationChannelPydantic
from models.alerting.incidents import AlertIncident as AlertIncidentPydantic, IncidentStatus
from models.alerting.rules import AlertRule as AlertRulePydantic
from services.common.meta import INCIDENT_META_KEY, parse_meta, _safe_group_ids

logger = logging.getLogger(__name__)


def rule_to_pydantic(r: AlertRuleDB) -> AlertRulePydantic:
    payload = {
        "id": r.id,
        "createdBy": getattr(r, "created_by", None),
        "orgId": r.org_id,
        "name": r.name,
        "expression": r.expr,
        "for": r.duration,
        "severity": r.severity,
        "labels": r.labels or {},
        "annotations": r.annotations or {},
        "enabled": r.enabled,
        "groupName": r.group,
        "notificationChannels": r.notification_channels or [],
        "visibility": r.visibility or "private",
        "sharedGroupIds": [g.id for g in r.shared_groups] if getattr(r, "shared_groups", None) else [],
        "isHidden": bool(getattr(r, "is_hidden", False)),
    }
    return AlertRulePydantic.parse_obj(payload)


def channel_to_pydantic(ch: NotificationChannelDB) -> NotificationChannelPydantic:
    return channel_to_pydantic_for_viewer(ch, viewer_user_id=getattr(ch, "created_by", None))


def channel_to_pydantic_for_viewer(ch: NotificationChannelDB, viewer_user_id: object) -> NotificationChannelPydantic:
    raw_config = getattr(ch, "config", None) or {}
    payload = {
        "id": ch.id,
        "name": ch.name,
        "type": ch.type,
        "enabled": ch.enabled,
        "config": raw_config if (getattr(ch, "created_by", None) and ch.created_by == viewer_user_id) else {},
        "createdBy": ch.created_by,
        "visibility": ch.visibility or "private",
        "sharedGroupIds": [g.id for g in ch.shared_groups] if getattr(ch, "shared_groups", None) else [],
        "isHidden": bool(getattr(ch, "is_hidden", False)),
    }
    return NotificationChannelPydantic.parse_obj(payload)


def incident_to_pydantic(incident: AlertIncidentDB) -> AlertIncidentPydantic:
    annotations = incident.annotations or {}
    meta = parse_meta(annotations)

    note_items = [
        {
            "author": n.get("author", "system"),
            "text": n.get("text", ""),
            "createdAt": n.get("createdAt") or datetime.now(timezone.utc),
        }
        for n in (incident.notes or [])
        if isinstance(n, dict)
    ]

    status_value = incident.status
    if isinstance(status_value, IncidentStatus):
        status_value = status_value.value
    if isinstance(status_value, str) and status_value.startswith("IncidentStatus."):
        status_value = status_value.split(".", 1)[1].lower()

    visibility_value = str(meta.get("visibility") or "public").lower()
    if visibility_value not in {"public", "private", "group"}:
        visibility_value = "public"

    safe_annotations = {str(k): str(v) for k, v in annotations.items() if k != INCIDENT_META_KEY and v is not None}
    if "beobservantCorrelationId" not in safe_annotations:
        corr = str(meta.get("correlation_id") or meta.get("incident_key") or "").strip()
        if corr:
            safe_annotations["beobservantCorrelationId"] = corr

    payload = {
        "id": incident.id,
        "fingerprint": incident.fingerprint,
        "alertName": incident.alert_name,
        "severity": incident.severity,
        "status": status_value,
        "assignee": incident.assignee,
        "notes": note_items,
        "labels": incident.labels or {},
        "annotations": safe_annotations,
        "visibility": visibility_value,
        "sharedGroupIds": _safe_group_ids(meta),
        "jiraTicketKey": meta.get("jira_ticket_key"),
        "jiraTicketUrl": meta.get("jira_ticket_url"),
        "jiraIntegrationId": meta.get("jira_integration_id"),
        "startsAt": incident.starts_at,
        "lastSeenAt": incident.last_seen_at,
        "resolvedAt": incident.resolved_at,
        "createdAt": incident.created_at,
        "updatedAt": incident.updated_at,
        "userManaged": bool(meta.get("user_managed")),
        "hideWhenResolved": bool(meta.get("hide_when_resolved")),
    }
    return AlertIncidentPydantic.parse_obj(payload)
