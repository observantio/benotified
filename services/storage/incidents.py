# services/storage/incidents.py
"""
Storage service for managing alert incidents.

Copyright (c) 2026 Stefan Kumarasinghe
Licensed under the Apache License, Version 2.0
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, cast

from fastapi import HTTPException, status
from sqlalchemy.orm import Session, joinedload

from config import config as app_config
from database import get_db_session
from db_models import AlertIncident as AlertIncidentDB
from db_models import AlertRule as AlertRuleDB
from models.alerting.incidents import AlertIncident, AlertIncidentUpdateRequest
from services.common.access import has_access
from services.common.meta import INCIDENT_META_KEY, parse_meta, _safe_group_ids
from services.common.pagination import cap_pagination
from services.common.visibility import normalize_storage_visibility
from services.storage.serializers import incident_to_pydantic

logger = logging.getLogger(__name__)


def _shared_group_ids(db_obj) -> List[str]:
    return [g.id for g in db_obj.shared_groups] if getattr(db_obj, "shared_groups", None) else []


def _resolve_rule_by_alertname(db: Session, tenant_id: str, labels: Dict[str, Any]) -> Optional[AlertRuleDB]:
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


class IncidentStorageService:
    def __init__(self, backend: Optional[object] = None):
        self._backend = backend

    def sync_incidents_from_alerts(self, tenant_id: str, alerts: List[Dict[str, Any]], resolve_missing: bool = True) -> None:
        now = datetime.now(timezone.utc)
        active_fingerprints: set[str] = set()

        with get_db_session() as db:
            for alert in alerts or []:
                labels = alert.get("labels", {}) or {}
                annotations = alert.get("annotations", {}) or {}
                fingerprint = alert.get("fingerprint") or labels.get("fingerprint")

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

                active_fingerprints.add(fingerprint)

                incident = (
                    db.query(AlertIncidentDB)
                    .filter(AlertIncidentDB.tenant_id == tenant_id, AlertIncidentDB.fingerprint == fingerprint)
                    .first()
                )

                parsed_starts = None
                starts_at = alert.get("startsAt") or alert.get("starts_at")
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
                    }
                    incident = AlertIncidentDB(
                        id=str(uuid.uuid4()),
                        tenant_id=tenant_id,
                        fingerprint=fingerprint,
                        alert_name=labels.get("alertname") or "Unnamed alert",
                        severity=labels.get("severity") or "warning",
                        status="open",
                        labels=labels,
                        starts_at=parsed_starts,
                        last_seen_at=now,
                        resolved_at=None,
                        notes=[],
                        annotations={**annotations, INCIDENT_META_KEY: json.dumps(metadata)},
                    )
                    db.add(incident)
                    continue

                existing_meta = parse_meta(incident.annotations or {})
                previous_status = str(incident.status or "")

                incident.alert_name = labels.get("alertname") or incident.alert_name
                incident.severity = labels.get("severity") or incident.severity
                incident.labels = labels

                if previous_status == "resolved" or incident.resolved_at is not None:
                    incident.assignee = None
                    existing_meta.pop("user_managed", None)

                if rule:
                    existing_meta["visibility"] = rule.visibility or existing_meta.get("visibility", "public")
                    existing_meta["shared_group_ids"] = _shared_group_ids(rule)
                    if rule.created_by:
                        existing_meta["created_by"] = rule.created_by

                incident.annotations = {**annotations, INCIDENT_META_KEY: json.dumps(existing_meta)}
                if parsed_starts and not incident.starts_at:
                    incident.starts_at = parsed_starts
                incident.status = "open"
                incident.last_seen_at = now
                incident.resolved_at = None

            if resolve_missing:
                open_incidents = db.query(AlertIncidentDB).filter(
                    AlertIncidentDB.tenant_id == tenant_id,
                    AlertIncidentDB.status == "open",
                )
                for incident in open_incidents.all():
                    if parse_meta(incident.annotations or {}).get("user_managed"):
                        continue
                    if incident.fingerprint not in active_fingerprints:
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

                if creator_id == user_id:
                    result.append(incident_to_pydantic(incident))
                    continue

                if inc_visibility == "public":
                    if not group_id:
                        result.append(incident_to_pydantic(incident))
                    continue

                if inc_visibility == "group":
                    if group_id:
                        if group_id in group_ids and group_id in shared_group_ids:
                            result.append(incident_to_pydantic(incident))
                    elif group_ids and set(group_ids) & set(shared_group_ids):
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
                if not has_access(
                    inc_visibility,
                    creator_id,
                    user_id,
                    _safe_group_ids(meta),
                    group_ids,
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
    ) -> Optional[AlertIncident]:
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

            if payload.assignee is not None:
                requested_assignee = payload.assignee.strip() or None
                if requested_assignee and visibility == "private" and requested_assignee != user_id:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
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
                        resolved_note_text = f"{user_id} marked this incident as resolved"
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
        alerts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        user_group_ids = [str(g) for g in (group_ids or []) if str(g).strip()]
        if not alerts:
            return []

        with get_db_session() as db:
            visible: List[Dict[str, Any]] = []
            for alert in alerts:
                labels = alert.get("labels") or {}
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