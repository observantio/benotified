"""
Serializers for the storage service, providing functions to serialize and deserialize data related to alert rules, incidents, and notification channels for storage in the database. This module includes logic to convert complex data structures into formats suitable for database storage, as well as to reconstruct those structures when retrieving data from the database. The serializers ensure that data is consistently formatted and can be easily stored and retrieved while maintaining the integrity of the information related to alerting and notification configurations.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""


from datetime import datetime, timezone
import logging
from typing import Any
from models.alerting.incidents import AlertIncident as AlertIncidentPydantic, IncidentStatus
from models.alerting.rules import AlertRule as AlertRulePydantic
from models.alerting.channels import NotificationChannel as NotificationChannelPydantic
from services.common.meta import INCIDENT_META_KEY, _parse_meta, _safe_group_ids

logger = logging.getLogger(__name__)

def rule_to_pydantic(r) -> AlertRulePydantic:
    payload = {
        "id": r.id,
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
        "sharedGroupIds": [g.id for g in r.shared_groups] if r.shared_groups else [],
    }
    return AlertRulePydantic.parse_obj(payload)


def channel_to_pydantic(ch) -> NotificationChannelPydantic:
    return channel_to_pydantic_for_viewer(ch, viewer_user_id=ch.created_by)


def channel_to_pydantic_for_viewer(ch, viewer_user_id: Any) -> NotificationChannelPydantic:
    raw_config = ch.config or {}
    payload = {
        "id": ch.id,
        "name": ch.name,
        "type": ch.type,
        "enabled": ch.enabled,
        "config": raw_config if (ch.created_by and ch.created_by == viewer_user_id) else {},
        "createdBy": ch.created_by,
        "visibility": ch.visibility or "private",
        "sharedGroupIds": [g.id for g in ch.shared_groups] if ch.shared_groups else [],
    }
    return NotificationChannelPydantic.parse_obj(payload)


def incident_to_pydantic(incident) -> AlertIncidentPydantic:
    annotations = incident.annotations or {}
    meta = _parse_meta(annotations)

    note_items = [
        {
            "author": n.get("author", "system"),
            "text": n.get("text", ""),
            "createdAt": n.get("createdAt") or datetime.now(timezone.utc),
        }
        for n in (incident.notes or []) if isinstance(n, dict)
    ]

    status_value = incident.status
    if isinstance(status_value, IncidentStatus):
        status_value = status_value.value
    if isinstance(status_value, str) and status_value.startswith("IncidentStatus."):
        status_value = status_value.split(".", 1)[1].lower()

    visibility_value = str(meta.get("visibility") or "public").lower()
    if visibility_value not in {"public", "private", "group"}:
        visibility_value = "public"

    safe_annotations = {
        str(k): str(v) for k, v in annotations.items()
        if k != INCIDENT_META_KEY and v is not None
    }

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
