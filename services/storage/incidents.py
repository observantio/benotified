"""
Incidents management service for handling alert incidents, including synchronization with incoming alerts, access control, and integration with Jira for issue tracking.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""


from __future__ import annotations

import hashlib
import json
import logging
import asyncio
import uuid
from collections.abc import Coroutine
from datetime import datetime, timezone
from typing import List, Mapping, Optional

from fastapi import HTTPException, status as http_status
from sqlalchemy.orm import Session, joinedload

from config import config as app_config
from custom_types.json import JSONDict
from database import get_db_session
from db_models import AlertIncident as AlertIncidentDB
from db_models import AlertRule as AlertRuleDB
from models.alerting.incidents import AlertIncident, AlertIncidentUpdateRequest
from services.common.access import has_access
from services.common.meta import INCIDENT_META_KEY, parse_meta, _safe_group_ids
from services.common.pagination import cap_pagination
from services.common.tenants import ensure_tenant_exists
from services.common.visibility import normalize_storage_visibility
from services.alerting.integration_security_service import (
    get_effective_jira_credentials,
    integration_is_usable,
    jira_integration_credentials,
    load_tenant_jira_integrations,
)
from services.jira_service import JiraError, jira_service
from services.alerting.suppression import is_suppressed_status
from services.storage.serializers import incident_to_pydantic

logger = logging.getLogger(__name__)


def _json_dict(value: object) -> JSONDict:
    return value if isinstance(value, dict) else {}


def _shared_group_ids(db_obj: object) -> List[str]:
    rule = db_obj if isinstance(db_obj, AlertRuleDB) else None
    return [g.id for g in rule.shared_groups] if rule and rule.shared_groups else []


INCIDENT_META_KEY_IDENTITY = "incident_key"
METRIC_STATES_ANNOTATION_KEY = "beobservantMetricStates"


def incident_scope_hint_from_labels(labels: Mapping[str, object]) -> str:
    for key in ("org_id", "orgId", "tenant", "product"):
        value = str((labels or {}).get(key) or "").strip()
        if value:
            return value
    return ""


def incident_key_from_labels(labels: Mapping[str, object]) -> Optional[str]:
    alert_name = str((labels or {}).get("alertname") or "").strip()
    if not alert_name:
        return None
    scope_hint = incident_scope_hint_from_labels(labels) or "*"
    return f"rule:{alert_name}|scope:{scope_hint}"


def incident_key_from_db_row(incident: AlertIncidentDB) -> Optional[str]:
    annotations = incident.annotations if isinstance(incident.annotations, dict) else {}
    meta = parse_meta(annotations)
    key = str(meta.get(INCIDENT_META_KEY_IDENTITY) or "").strip()
    if key:
        return key

    labels = incident.labels if isinstance(incident.labels, dict) else {}
    fallback_key = incident_key_from_labels(labels)
    if fallback_key:
        return fallback_key

    alert_name = str(getattr(incident, "alert_name", "") or "").strip()
    if not alert_name:
        return None
    return f"rule:{alert_name}|scope:*"


def incident_activity_token_from_row(incident: AlertIncidentDB) -> str:
    key = incident_key_from_db_row(incident)
    if key:
        return f"k:{key}"
    return f"fp:{str(getattr(incident, 'fingerprint', '') or '')}"


def _extract_metric_state(labels: Mapping[str, object]) -> str:
    return str(
        labels.get("state")
        or labels.get("metric_state")
        or labels.get("mem_state")
        or ""
    ).strip()


def _parse_metric_states(value: object) -> List[str]:
    raw = str(value or "").strip()
    if not raw:
        return []
    seen: set[str] = set()
    out: List[str] = []
    for part in raw.split(","):
        state = str(part or "").strip()
        if not state or state in seen:
            continue
        seen.add(state)
        out.append(state)
    return out


def _merge_metric_states(annotations: Mapping[str, object], *states: str) -> str:
    existing_states = _parse_metric_states(
        (annotations or {}).get(METRIC_STATES_ANNOTATION_KEY),
    )
    seen = set(existing_states)
    merged = list(existing_states)
    for state in states:
        normalized = str(state or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        merged.append(normalized)
    return ",".join(merged)


def _is_alert_suppressed(alert: JSONDict) -> bool:
    return is_suppressed_status(alert.get("status") or {})


def _incident_access_allowed(
    *,
    visibility: str,
    creator_id: Optional[str],
    user_id: str,
    shared_group_ids: List[str],
    user_group_ids: List[str],
    require_write: bool = False,
) -> bool:
    # Group incidents are always group-membership scoped, even for original creator.
    if visibility == "group":
        return bool(set(shared_group_ids) & set(user_group_ids))
    # For non-group incidents, preserve existing incident behavior where mutation
    # follows visibility/read access rather than owner-only writes.
    return has_access(
        visibility,
        creator_id,
        user_id,
        shared_group_ids,
        user_group_ids,
        require_write=False,
    )


def _resolve_rule_by_alertname(db: Session, tenant_id: str, labels: Mapping[str, object]) -> Optional[AlertRuleDB]:
    alertname = labels.get("alertname")
    if not alertname:
        return None

    org_id_hint = str(
        labels.get("org_id")
        or labels.get("orgId")
        or labels.get("tenant")
        or labels.get("product")
        or ""
    ).strip()

    try:
        q = db.query(AlertRuleDB).filter(AlertRuleDB.tenant_id == tenant_id, AlertRuleDB.name == alertname)
        if org_id_hint:
            return (
                q.filter((AlertRuleDB.org_id == org_id_hint) | (AlertRuleDB.org_id.is_(None)))
                .order_by(AlertRuleDB.org_id.desc())
                .first()
            )
        return q.first()
    except (TypeError, ValueError) as exc:
        logger.debug("Failed to resolve rule for alertname=%s: %s", alertname, exc)
        return None


def _run_async(coro: Coroutine[object, object, object]) -> None:
    try:
        asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(coro)
        finally:
            loop.close()


def _resolve_incident_jira_credentials(tenant_id: str, integration_id: Optional[str]) -> Optional[JSONDict]:
    integration_id = str(integration_id or "").strip()
    if integration_id:
        for item in load_tenant_jira_integrations(tenant_id):
            if str(item.get("id") or "").strip() != integration_id:
                continue
            if not integration_is_usable(item):
                return None
            return {str(key): value for key, value in jira_integration_credentials(item).items()}
    tenant_credentials = get_effective_jira_credentials(tenant_id)
    if tenant_credentials.get("base_url"):
        return {str(key): value for key, value in tenant_credentials.items()}
    return None


def _move_reopened_incident_jira_ticket_to_todo(tenant_id: str, incident: AlertIncidentDB) -> None:
    annotations = incident.annotations if isinstance(incident.annotations, dict) else {}
    meta = parse_meta(annotations)
    issue_key = str(meta.get("jira_ticket_key") or "").strip()
    if not issue_key:
        return
    integration_id = str(meta.get("jira_integration_id") or "").strip() or None
    credentials = _resolve_incident_jira_credentials(tenant_id, integration_id)
    if not credentials:
        return
    try:
        _run_async(jira_service.transition_issue_to_todo(issue_key=issue_key, credentials=credentials))
    except JiraError as exc:
        logger.warning("Failed moving Jira issue %s to To Do for refired incident: %s", issue_key, exc)


def _sync_reopened_incident_note_to_jira(
    tenant_id: str,
    incident: AlertIncidentDB,
    *,
    note_text: str,
    created_at: datetime,
) -> None:
    annotations = incident.annotations if isinstance(incident.annotations, dict) else {}
    meta = parse_meta(annotations)
    issue_key = str(meta.get("jira_ticket_key") or "").strip()
    if not issue_key:
        return
    integration_id = str(meta.get("jira_integration_id") or "").strip() or None
    credentials = _resolve_incident_jira_credentials(tenant_id, integration_id)
    if not credentials:
        return
    when_label = created_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    body = f"System · {when_label}\n{note_text}"
    try:
        _run_async(jira_service.add_comment(issue_key=issue_key, text=body, credentials=credentials))
    except JiraError as exc:
        logger.warning("Failed syncing refire note to Jira issue %s: %s", issue_key, exc)


class IncidentStorageService:
    def unlink_jira_integration_from_incidents(
        self,
        tenant_id: str,
        integration_id: str,
    ) -> int:
        target_integration_id = str(integration_id or "").strip()
        if not target_integration_id:
            return 0

        updated_count = 0
        with get_db_session() as db:
            incidents = (
                db.query(AlertIncidentDB)
                .filter(AlertIncidentDB.tenant_id == tenant_id)
                .all()
            )
            for incident in incidents:
                annotations = incident.annotations if isinstance(incident.annotations, dict) else {}
                meta = parse_meta(annotations)
                linked_id = str(meta.get("jira_integration_id") or "").strip()
                if linked_id != target_integration_id:
                    continue

                meta.pop("jira_integration_id", None)
                meta.pop("jira_ticket_key", None)
                meta.pop("jira_ticket_url", None)
                incident.annotations = {**annotations, INCIDENT_META_KEY: json.dumps(meta)}
                updated_count += 1

            if updated_count:
                db.flush()

        return updated_count

    def get_incident_summary(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> JSONDict:
        group_ids = group_ids or []
        open_total = 0
        unassigned_open = 0
        assigned_open = 0
        assigned_to_me_open = 0
        by_visibility: dict[str, int] = {"public": 0, "private": 0, "group": 0}

        with get_db_session() as db:
            incidents = (
                db.query(AlertIncidentDB)
                .filter(AlertIncidentDB.tenant_id == tenant_id)
                .all()
            )

            for incident in incidents:
                meta = parse_meta(incident.annotations or {})
                inc_visibility = str(meta.get("visibility") or "public").lower()
                if inc_visibility not in {"public", "private", "group"}:
                    inc_visibility = "public"

                creator_id = str(meta.get("created_by") or "") or None
                if not _incident_access_allowed(
                    visibility=inc_visibility,
                    creator_id=creator_id,
                    user_id=user_id,
                    shared_group_ids=_safe_group_ids(meta),
                    user_group_ids=group_ids,
                ):
                    continue

                if str(incident.status or "").lower() == "resolved":
                    continue

                open_total += 1
                by_visibility[inc_visibility] += 1

                assignee = str(incident.assignee or "").strip()
                if not assignee:
                    unassigned_open += 1
                else:
                    assigned_open += 1
                    if assignee == str(user_id):
                        assigned_to_me_open += 1

        return {
            "open_total": open_total,
            "unassigned_open": unassigned_open,
            "assigned_open": assigned_open,
            "assigned_to_me_open": assigned_to_me_open,
            "by_visibility": by_visibility,
        }

    def sync_incidents_from_alerts(self, tenant_id: str, alerts: List[JSONDict], resolve_missing: bool = True) -> None:
        now = datetime.now(timezone.utc)
        active_incident_tokens: set[str] = set()

        with get_db_session() as db:
            ensure_tenant_exists(db, tenant_id)
            for alert in alerts or []:
                alert_data = _json_dict(alert)
                if _is_alert_suppressed(alert):
                    continue
                labels = _json_dict(alert_data.get("labels", {}))
                annotations = _json_dict(alert_data.get("annotations", {}))
                metric_state = _extract_metric_state(labels)
                incident_key = incident_key_from_labels(labels)
                fingerprint = alert_data.get("fingerprint") or labels.get("fingerprint")

                if not fingerprint:
                    stable_blob = json.dumps(
                        {
                            "alertname": labels.get("alertname") or "",
                            "severity": labels.get("severity") or "",
                            "labels": labels,
                            "annotations": annotations,
                        },
                        sort_keys=True,
                        default=str,
                    )
                    fingerprint = f"derived-{hashlib.sha256(stable_blob.encode()).hexdigest()}"

                active_incident_tokens.add(f"k:{incident_key}" if incident_key else f"fp:{fingerprint}")

                incident: Optional[AlertIncidentDB] = None
                if incident_key:
                    alert_name = str(labels.get("alertname") or "").strip()
                    if alert_name:
                        candidates = (
                            db.query(AlertIncidentDB)
                            .filter(
                                AlertIncidentDB.tenant_id == tenant_id,
                                AlertIncidentDB.alert_name == alert_name,
                            )
                            .order_by(AlertIncidentDB.updated_at.desc())
                            .all()
                        )
                        matching_candidates = [
                            item for item in candidates if incident_key_from_db_row(item) == incident_key
                        ]
                        if matching_candidates:
                            canonical = matching_candidates[0]
                            if len(matching_candidates) > 1:
                                duplicate_ids = [str(item.id) for item in matching_candidates[1:]]
                                logger.info(
                                    "Deduplicating incidents for key=%s tenant=%s keeping=%s duplicates=%s",
                                    incident_key,
                                    tenant_id,
                                    canonical.id,
                                    duplicate_ids,
                                )
                                for duplicate in matching_candidates[1:]:
                                    duplicate_state = ""
                                    if isinstance(getattr(duplicate, "labels", None), dict):
                                        duplicate_state = str(
                                            duplicate.labels.get("state")
                                            or duplicate.labels.get("metric_state")
                                            or duplicate.labels.get("mem_state")
                                            or ""
                                        ).strip()
                                    state_text = duplicate_state or "unknown"
                                    dedupe_note = (
                                        f"System deduplicated this incident into #{canonical.id} "
                                        f"(correlation scope: {incident_key}; metric state: {state_text})"
                                    )
                                    if str(duplicate.status or "").lower() != "resolved":
                                        duplicate.status = "resolved"
                                        duplicate.resolved_at = now
                                    existing_notes = list(duplicate.notes or [])
                                    existing_notes.append(
                                        {
                                            "author": "system",
                                            "text": dedupe_note,
                                            "createdAt": now.isoformat(),
                                        }
                                    )
                                    duplicate.notes = existing_notes
                                merged_states = _merge_metric_states(
                                    canonical.annotations if isinstance(canonical.annotations, dict) else {},
                                    *[
                                        _extract_metric_state(item.labels if isinstance(item.labels, dict) else {})
                                        for item in matching_candidates
                                    ],
                                )
                                canonical_annotations = (
                                    canonical.annotations if isinstance(canonical.annotations, dict) else {}
                                )
                                canonical.annotations = {
                                    **canonical_annotations,
                                    METRIC_STATES_ANNOTATION_KEY: merged_states,
                                }
                            incident = canonical
                if not incident:
                    incident = (
                        db.query(AlertIncidentDB)
                        .filter(AlertIncidentDB.tenant_id == tenant_id, AlertIncidentDB.fingerprint == fingerprint)
                        .first()
                    )

                parsed_starts = None
                starts_at_value = alert_data.get("startsAt") or alert_data.get("starts_at")
                starts_at = starts_at_value if isinstance(starts_at_value, str) else None
                if starts_at:
                    try:
                        parsed_starts = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
                    except ValueError:
                        parsed_starts = None

                rule = _resolve_rule_by_alertname(db, tenant_id, labels)

                if not incident:
                    metadata = {
                        "visibility": (rule.visibility or "public") if rule else "public",
                        "shared_group_ids": _shared_group_ids(rule) if rule else [],
                        "created_by": rule.created_by if rule else None,
                        "correlation_id": str(getattr(rule, "group", "") or "").strip() if rule else "",
                        INCIDENT_META_KEY_IDENTITY: incident_key,
                    }
                    merged_states = _merge_metric_states(annotations, metric_state)
                    incident = AlertIncidentDB(
                        id=str(uuid.uuid4()),
                        tenant_id=tenant_id,
                        fingerprint=fingerprint,
                        alert_name=str(labels.get("alertname") or "Unnamed alert"),
                        severity=str(labels.get("severity") or "warning"),
                        status="open",
                        labels=labels,
                        starts_at=parsed_starts,
                        last_seen_at=now,
                        resolved_at=None,
                        notes=[],
                        annotations={
                            **annotations,
                            METRIC_STATES_ANNOTATION_KEY: merged_states,
                            INCIDENT_META_KEY: json.dumps(metadata),
                        },
                    )
                    db.add(incident)
                    continue

                existing_meta = parse_meta(incident.annotations or {})
                previous_status = str(incident.status or "")

                incident.alert_name = str(labels.get("alertname") or incident.alert_name)
                incident.severity = str(labels.get("severity") or incident.severity)
                incident.labels = labels

                if previous_status == "resolved" or incident.resolved_at is not None:
                    incident.assignee = None
                    existing_meta.pop("user_managed", None)

                if rule:
                    existing_meta["visibility"] = rule.visibility or existing_meta.get("visibility", "public")
                    existing_meta["shared_group_ids"] = _shared_group_ids(rule)
                    existing_meta["correlation_id"] = str(getattr(rule, "group", "") or "").strip()
                    if rule.created_by:
                        existing_meta["created_by"] = rule.created_by
                if incident_key:
                    existing_meta[INCIDENT_META_KEY_IDENTITY] = incident_key
                if not str(existing_meta.get("correlation_id") or "").strip() and incident_key:
                    existing_meta["correlation_id"] = incident_key

                merged_states = _merge_metric_states(
                    incident.annotations if isinstance(incident.annotations, dict) else {},
                    metric_state,
                )
                incident.annotations = {
                    **annotations,
                    METRIC_STATES_ANNOTATION_KEY: merged_states,
                    INCIDENT_META_KEY: json.dumps(existing_meta),
                }
                if parsed_starts and not incident.starts_at:
                    incident.starts_at = parsed_starts
                incident.status = "open"
                incident.last_seen_at = now
                incident.resolved_at = None

                if previous_status.lower() == "resolved":
                    reopen_note = "System reopened this incident because the alert fired again"
                    existing_notes = list(incident.notes or [])
                    existing_notes.append(
                        {
                            "author": "system",
                            "text": reopen_note,
                            "createdAt": now.isoformat(),
                        }
                    )
                    incident.notes = existing_notes
                    _move_reopened_incident_jira_ticket_to_todo(tenant_id, incident)
                    _sync_reopened_incident_note_to_jira(
                        tenant_id,
                        incident,
                        note_text=reopen_note,
                        created_at=now,
                    )

            if resolve_missing:
                open_incidents = db.query(AlertIncidentDB).filter(
                    AlertIncidentDB.tenant_id == tenant_id,
                    AlertIncidentDB.status == "open",
                )
                for incident in open_incidents.all():
                    if parse_meta(incident.annotations or {}).get("user_managed"):
                        continue
                    if incident_activity_token_from_row(incident) not in active_incident_tokens:
                        incident.status = "resolved"
                        incident.resolved_at = now

    def list_incidents(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
        status: Optional[str] = None,
        visibility: Optional[str] = None,
        group_id: Optional[str] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[AlertIncident]:
        group_ids = group_ids or []
        capped_limit, capped_offset = cap_pagination(limit, offset)

        with get_db_session() as db:
            q = db.query(AlertIncidentDB).filter(AlertIncidentDB.tenant_id == tenant_id)
            if status:
                q = q.filter(AlertIncidentDB.status == status)

            incidents = (
                q.order_by(AlertIncidentDB.updated_at.desc())
                .offset(capped_offset)
                .limit(capped_limit)
                .all()
            )

            result: List[AlertIncident] = []
            for incident in incidents:
                meta = parse_meta(incident.annotations or {})
                inc_visibility = str(meta.get("visibility") or "public").lower()
                if inc_visibility not in {"public", "private", "group"}:
                    inc_visibility = "public"

                if incident.status == "resolved" and meta.get("hide_when_resolved") and not status:
                    continue
                if visibility and inc_visibility != visibility:
                    continue

                creator_id = meta.get("created_by")
                shared_group_ids = _safe_group_ids(meta)

                if group_id:
                    if group_id not in group_ids or inc_visibility != "group" or group_id not in shared_group_ids:
                        continue

                if not _incident_access_allowed(
                    visibility=inc_visibility,
                    creator_id=str(creator_id or "") or None,
                    user_id=user_id,
                    shared_group_ids=shared_group_ids,
                    user_group_ids=group_ids,
                ):
                    continue

                if inc_visibility == "public" and group_id:
                    continue

                result.append(incident_to_pydantic(incident))

            return result

    def get_incident_for_user(
        self,
        incident_id: str,
        tenant_id: str,
        user_id: Optional[str] = None,
        group_ids: Optional[List[str]] = None,
        require_write: bool = False,
    ) -> Optional[AlertIncident]:
        group_ids = group_ids or []
        with get_db_session() as db:
            incident = (
                db.query(AlertIncidentDB)
                .filter(AlertIncidentDB.id == incident_id, AlertIncidentDB.tenant_id == tenant_id)
                .first()
            )
            if not incident:
                return None
            if user_id:
                meta = parse_meta(incident.annotations or {})
                inc_visibility = str(meta.get("visibility") or "public").lower()
                if inc_visibility not in {"public", "private", "group"}:
                    inc_visibility = "public"
                creator_id = str(meta.get("created_by") or "") or None
                if not _incident_access_allowed(
                    visibility=inc_visibility,
                    creator_id=creator_id,
                    user_id=user_id,
                    shared_group_ids=_safe_group_ids(meta),
                    user_group_ids=group_ids,
                    require_write=require_write,
                ):
                    return None
            return incident_to_pydantic(incident)

    def update_incident(
        self,
        incident_id: str,
        tenant_id: str,
        user_id: str,
        payload: AlertIncidentUpdateRequest,
        group_ids: Optional[List[str]] = None,
    ) -> Optional[AlertIncident]:
        user_group_ids = [str(g).strip() for g in (group_ids or []) if str(g).strip()]
        with get_db_session() as db:
            incident = (
                db.query(AlertIncidentDB)
                .filter(AlertIncidentDB.id == incident_id, AlertIncidentDB.tenant_id == tenant_id)
                .first()
            )
            if not incident:
                return None

            previous_status = str(incident.status or "")
            resolved_note_text: Optional[str] = None

            meta = parse_meta(incident.annotations or {})
            visibility = normalize_storage_visibility(str(meta.get("visibility") or "public"))
            creator_id = str(meta.get("created_by") or "") or None
            if not _incident_access_allowed(
                visibility=visibility,
                creator_id=creator_id,
                user_id=user_id,
                shared_group_ids=_safe_group_ids(meta),
                user_group_ids=user_group_ids,
                require_write=True,
            ):
                return None

            if payload.assignee is not None:
                requested_assignee = payload.assignee.strip() or None
                if requested_assignee and visibility == "private" and requested_assignee != user_id:
                    raise HTTPException(
                        status_code=http_status.HTTP_403_FORBIDDEN,
                        detail="Private incidents can only be assigned to yourself",
                    )
                incident.assignee = requested_assignee

            manual_manage_flag: Optional[bool] = None
            if payload.status is not None:
                status_value = payload.status.value if hasattr(payload.status, "value") else str(payload.status)
                if status_value.startswith("IncidentStatus."):
                    status_value = status_value.split(".", 1)[1].lower()
                incident.status = status_value
                if incident.status == "resolved":
                    incident.resolved_at = datetime.now(timezone.utc)
                    manual_manage_flag = False
                    if previous_status.lower() != "resolved":
                        actor_name = (
                            getattr(payload, "actor_username", None)
                            or user_id
                        )
                        resolved_note_text = f"{actor_name} marked this incident as resolved"
                else:
                    incident.resolved_at = None
                    if incident.status == "open":
                        manual_manage_flag = True

            annotations = incident.annotations if isinstance(incident.annotations, dict) else {}
            meta = parse_meta(annotations)
            if not meta.get("created_by"):
                meta["created_by"] = user_id

            if manual_manage_flag is True:
                meta["user_managed"] = True
            elif manual_manage_flag is False:
                meta.pop("user_managed", None)

            hide_flag = getattr(payload, "hide_when_resolved", None)
            if hide_flag is True:
                meta["hide_when_resolved"] = True
            elif hide_flag is False:
                meta.pop("hide_when_resolved", None)

            for meta_key, payload_attr in [
                ("jira_ticket_key", "jira_ticket_key"),
                ("jira_ticket_url", "jira_ticket_url"),
                ("jira_integration_id", "jira_integration_id"),
            ]:
                val = getattr(payload, payload_attr, None)
                if val is not None:
                    stripped = val.strip()
                    if stripped:
                        meta[meta_key] = stripped
                    else:
                        meta.pop(meta_key, None)

            meta["updated_by"] = user_id
            incident.annotations = {**annotations, INCIDENT_META_KEY: json.dumps(meta)}

            now_iso = datetime.now(timezone.utc).isoformat()
            notes = list(incident.notes or [])
            if payload.note:
                notes.append({"author": user_id, "text": payload.note, "createdAt": now_iso})
            if resolved_note_text:
                notes.append({"author": user_id, "text": resolved_note_text, "createdAt": now_iso})
            if notes != list(incident.notes or []):
                incident.notes = notes

            db.flush()
            return incident_to_pydantic(incident)

    def filter_alerts_for_user(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]],
        alerts: List[JSONDict],
    ) -> List[JSONDict]:
        user_group_ids = [str(g) for g in (group_ids or []) if str(g).strip()]
        if not alerts:
            return []

        with get_db_session() as db:
            visible: List[JSONDict] = []
            for alert in alerts:
                labels = _json_dict(alert.get("labels"))
                alertname = str(labels.get("alertname") or "").strip()
                if not alertname:
                    continue

                org_id_hint = str(
                    labels.get("org_id")
                    or labels.get("orgId")
                    or labels.get("tenant")
                    or labels.get("product")
                    or ""
                ).strip()

                candidates = (
                    db.query(AlertRuleDB)
                    .options(joinedload(AlertRuleDB.shared_groups))
                    .filter(
                        AlertRuleDB.tenant_id == tenant_id,
                        AlertRuleDB.name == alertname,
                        AlertRuleDB.enabled.is_(True),
                    )
                    .limit(int(app_config.MAX_QUERY_LIMIT))
                    .all()
                )
                if not candidates:
                    continue

                if org_id_hint:
                    org_matched = [r for r in candidates if str(r.org_id or "") == org_id_hint]
                    candidates = org_matched or [r for r in candidates if not r.org_id] or candidates

                if any(
                    has_access(
                        normalize_storage_visibility(getattr(r, "visibility", None)),
                        getattr(r, "created_by", None),
                        user_id,
                        _shared_group_ids(r),
                        user_group_ids,
                    )
                    for r in candidates
                ):
                    visible.append(alert)

            return visible
