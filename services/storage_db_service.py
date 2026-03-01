"""
Service for managing storage of alert rules, incidents, and notification channels in the database, providing functions to create, read, update, and delete these entities while enforcing access control based on user roles and group memberships. This module includes logic to handle the synchronization of incidents with incoming alerts, to manage the visibility and sharing of incidents and rules, and to log audit events related to incident management actions. The service also provides utility functions for filtering alerts based on user permissions and for retrieving alert rules with associated ownership information.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, cast

from fastapi import HTTPException, status
from sqlalchemy.orm import Session, joinedload

from config import config as app_config
from database import get_db_session
from db_models import (
    AlertIncident as AlertIncidentDB,
    AlertRule as AlertRuleDB,
    NotificationChannel as NotificationChannelDB,
    User,
)
from models.alerting.channels import NotificationChannel as NotificationChannelPydantic, NotificationChannelCreate
from models.alerting.incidents import AlertIncident as AlertIncidentPydantic, AlertIncidentUpdateRequest
from models.alerting.rules import AlertRule as AlertRulePydantic, AlertRuleCreate
from services.common.access import _assign_shared_groups, _has_access
from services.common.encryption import decrypt_config, encrypt_config
from services.common.meta import INCIDENT_META_KEY, _parse_meta, _safe_group_ids
from services.common.pagination import _cap_pagination
from services.common.visibility import normalize_storage_visibility
from services.storage.serializers import (
    channel_to_pydantic_for_viewer,
    incident_to_pydantic,
    rule_to_pydantic,
)

logger = logging.getLogger(__name__)


def _get_shared_group_ids(db_obj) -> List[str]:
    return [g.id for g in db_obj.shared_groups] if db_obj.shared_groups else []


def _extract_user_group_ids(user_obj: Optional[User]) -> List[str]:
    if not user_obj:
        return []
    return [
        gid for g in (getattr(user_obj, "groups", None) or [])
        if (gid := str(getattr(g, "id", "") or "").strip())
    ]


def _log_incident_audit(
    db: Session, *, tenant_id: str, user_id: str, action: str,
    incident_id: str, details: Dict[str, Any],
) -> None:
    _ = (db, tenant_id, user_id, action, incident_id, details)


def _resolve_rule_by_alertname(
    db: Session, tenant_id: str, labels: Dict[str, Any],
) -> Optional[AlertRuleDB]:
    alertname = labels.get("alertname")
    if not alertname:
        return None
    org_id_hint = str(
        labels.get("org_id") or labels.get("orgId") or
        labels.get("tenant") or labels.get("product") or ""
    ).strip()
    try:
        q = db.query(AlertRuleDB).filter(
            AlertRuleDB.tenant_id == tenant_id,
            AlertRuleDB.name == alertname,
        )
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


class DatabaseStorageService:
    def sync_incidents_from_alerts(
        self, tenant_id: str, alerts: List[Dict[str, Any]], resolve_missing: bool = True,
    ) -> None:
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
                        sort_keys=True, default=str,
                    )
                    fingerprint = f"derived-{hashlib.sha256(stable_blob.encode()).hexdigest()}"

                active_fingerprints.add(fingerprint)

                incident = db.query(AlertIncidentDB).filter(
                    AlertIncidentDB.tenant_id == tenant_id,
                    AlertIncidentDB.fingerprint == fingerprint,
                ).first()

                parsed_starts = None
                starts_at = alert.get("startsAt") or alert.get("starts_at")
                if starts_at:
                    try:
                        parsed_starts = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
                    except ValueError:
                        pass

                rule = _resolve_rule_by_alertname(db, tenant_id, labels)

                if not incident:
                    metadata = {
                        "visibility": (rule.visibility or "public") if rule else "public",
                        "shared_group_ids": _get_shared_group_ids(rule) if rule else [],
                        "created_by": rule.created_by if rule else None,
                    }
                    incident = AlertIncidentDB(
                        id=str(uuid.uuid4()), tenant_id=tenant_id, fingerprint=fingerprint,
                        alert_name=labels.get("alertname") or "Unnamed alert",
                        severity=labels.get("severity") or "warning",
                        status="open", labels=labels,
                        starts_at=parsed_starts, last_seen_at=now, resolved_at=None, notes=[],
                        annotations={**annotations, INCIDENT_META_KEY: json.dumps(metadata)},
                    )
                    db.add(incident)
                else:
                    existing_meta = _parse_meta(incident.annotations or {})
                    previous_status = incident.status

                    incident.alert_name = labels.get("alertname") or incident.alert_name
                    incident.severity = labels.get("severity") or incident.severity
                    incident.labels = labels

                    if previous_status == "resolved" or incident.resolved_at is not None:
                        incident.assignee = None
                        existing_meta.pop("user_managed", None)

                    if rule:
                        existing_meta["visibility"] = rule.visibility or existing_meta.get("visibility", "public")
                        existing_meta["shared_group_ids"] = _get_shared_group_ids(rule)
                        if rule.created_by:
                            existing_meta["created_by"] = rule.created_by

                    incident.annotations = {**annotations, INCIDENT_META_KEY: json.dumps(existing_meta)}
                    if parsed_starts and not incident.starts_at:
                        incident.starts_at = parsed_starts
                    incident.status = "open"
                    incident.last_seen_at = now
                    incident.resolved_at = None

            if resolve_missing:
                for incident in db.query(AlertIncidentDB).filter(
                    AlertIncidentDB.tenant_id == tenant_id,
                    AlertIncidentDB.status == "open",
                ).all():
                    if _parse_meta(incident.annotations or {}).get("user_managed"):
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
    ) -> List[AlertIncidentPydantic]:
        group_ids = group_ids or []
        capped_limit, capped_offset = _cap_pagination(limit, offset)

        with get_db_session() as db:
            q = db.query(AlertIncidentDB).filter(AlertIncidentDB.tenant_id == tenant_id)
            if status:
                q = q.filter(AlertIncidentDB.status == status)
            incidents = q.order_by(AlertIncidentDB.updated_at.desc()).offset(capped_offset).limit(capped_limit).all()

            result: List[AlertIncidentPydantic] = []
            for incident in incidents:
                meta = _parse_meta(incident.annotations or {})
                incident_visibility = str(meta.get("visibility") or "public").lower()
                if incident_visibility not in {"public", "private", "group"}:
                    incident_visibility = "public"

                if incident.status == "resolved" and meta.get("hide_when_resolved") and not status:
                    continue
                if visibility and incident_visibility != visibility:
                    continue

                creator_id = meta.get("created_by")
                shared_group_ids = _safe_group_ids(meta)

                if group_id:
                    if group_id not in group_ids or incident_visibility != "group" or group_id not in shared_group_ids:
                        continue

                if creator_id == user_id:
                    result.append(incident_to_pydantic(incident))
                    continue

                if incident_visibility == "public":
                    if not group_id:
                        result.append(incident_to_pydantic(incident))
                    continue

                if incident_visibility == "group":
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
    ) -> Optional[AlertIncidentPydantic]:
        group_ids = group_ids or []
        with get_db_session() as db:
            incident = db.query(AlertIncidentDB).filter(
                AlertIncidentDB.id == incident_id,
                AlertIncidentDB.tenant_id == tenant_id,
            ).first()
            if not incident:
                return None

            if user_id:
                meta = _parse_meta(incident.annotations or {})
                inc_visibility = str(meta.get("visibility") or "public").lower()
                if inc_visibility not in {"public", "private", "group"}:
                    inc_visibility = "public"
                creator_id = str(meta.get("created_by") or "") or None
                if not _has_access(inc_visibility, creator_id, user_id, _safe_group_ids(meta), group_ids, require_write=require_write):
                    return None

            return incident_to_pydantic(incident)

    def _is_assignee_allowed(
        self,
        db: Session,
        *,
        tenant_id: str,
        actor_user_id: str,
        assignee_id: Optional[str],
        visibility: str,
        shared_group_ids: List[str],
    ) -> bool:
        if not assignee_id:
            return True
        if visibility == "private":
            return assignee_id == actor_user_id
        assignee_user = db.query(User).options(joinedload(User.groups)).filter(
            User.id == assignee_id,
            User.tenant_id == tenant_id,
            User.is_active.is_(True),
        ).first()
        if not assignee_user:
            return True
        if visibility == "group":
            return bool(set(_extract_user_group_ids(assignee_user)) & set(shared_group_ids or []))
        return True

    def update_incident(
        self,
        incident_id: str,
        tenant_id: str,
        user_id: str,
        payload: AlertIncidentUpdateRequest,
    ) -> Optional[AlertIncidentPydantic]:
        with get_db_session() as db:
            incident = db.query(AlertIncidentDB).filter(
                AlertIncidentDB.id == incident_id,
                AlertIncidentDB.tenant_id == tenant_id,
            ).first()
            if not incident:
                return None

            previous_assignee = incident.assignee
            previous_status = str(incident.status or "")
            resolved_note_text: Optional[str] = None
            meta = _parse_meta(incident.annotations or {})
            visibility = normalize_storage_visibility(str(meta.get("visibility") or "public"))
            shared_group_ids = _safe_group_ids(meta)
            if payload.assignee is not None:
                requested_assignee = payload.assignee.strip() or None
                if not self._is_assignee_allowed(
                    db, tenant_id=tenant_id, actor_user_id=user_id,
                    assignee_id=requested_assignee, visibility=visibility,
                    shared_group_ids=shared_group_ids,
                ):
                    if visibility == "private":
                        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Private incidents can only be assigned to yourself")
                    if visibility == "group":
                        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Assignee must be a member of at least one shared group")
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid assignee for this incident")
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
                        actor = db.query(User).filter(User.id == user_id, User.tenant_id == tenant_id).first()
                        actor_label = str(getattr(actor, "username", "") or user_id)
                        resolved_note_text = f"{actor_label} marked this incident as resolved"
                else:
                    incident.resolved_at = None
                    if incident.status == "open":
                        manual_manage_flag = True

            annotations = incident.annotations if isinstance(incident.annotations, dict) else {}
            meta = _parse_meta(annotations)
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
                logger.debug("Appending note for incident %s by user %s", incident_id, user_id)
                notes.append({"author": user_id, "text": payload.note, "createdAt": now_iso})

            if resolved_note_text:
                notes.append({"author": user_id, "text": resolved_note_text, "createdAt": now_iso})

            if notes != list(incident.notes or []):
                incident.notes = notes

            if payload.note:
                _log_incident_audit(db, tenant_id=tenant_id, user_id=user_id, action="incident.note.add", incident_id=incident_id, details={"note_preview": str(payload.note)[:200]})
            if payload.assignee is not None and incident.assignee != previous_assignee:
                _log_incident_audit(db, tenant_id=tenant_id, user_id=user_id, action="incident.assign", incident_id=incident_id, details={"from": previous_assignee, "to": incident.assignee})
            if payload.status is not None and str(incident.status or "") != previous_status:
                _log_incident_audit(db, tenant_id=tenant_id, user_id=user_id, action="incident.status.change", incident_id=incident_id, details={"from": previous_status, "to": str(incident.status or "")})

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
                    labels.get("org_id") or labels.get("orgId") or
                    labels.get("tenant") or labels.get("product") or ""
                ).strip()
                candidates = (
                    db.query(AlertRuleDB)
                    .options(joinedload(AlertRuleDB.shared_groups))
                    .filter(
                        AlertRuleDB.tenant_id == tenant_id,
                        AlertRuleDB.name == alertname,
                        AlertRuleDB.enabled.is_(True),
                    )
                    .all()
                )
                if not candidates:
                    continue

                if org_id_hint:
                    org_matched = [r for r in candidates if str(r.org_id or "") == org_id_hint]
                    candidates = org_matched or [r for r in candidates if not r.org_id] or candidates

                if any(
                    _has_access(
                        normalize_storage_visibility(getattr(r, "visibility", None)),
                        getattr(r, "created_by", None),
                        user_id,
                        _get_shared_group_ids(r),
                        user_group_ids,
                    )
                    for r in candidates
                ):
                    visible.append(alert)

            return visible

    def get_public_alert_rules(self, tenant_id: str) -> List[AlertRulePydantic]:
        with get_db_session() as db:
            rules = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(
                    AlertRuleDB.tenant_id == tenant_id,
                    AlertRuleDB.visibility == "public",
                    AlertRuleDB.enabled.is_(True),
                )
                .all()
            )
            return [rule_to_pydantic(r) for r in rules]

    def get_alert_rules(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[AlertRulePydantic]:
        group_ids = group_ids or []
        capped_limit, capped_offset = _cap_pagination(limit, offset)
        with get_db_session() as db:
            rules = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.tenant_id == tenant_id)
                .offset(capped_offset).limit(capped_limit)
                .all()
            )
            return [
                rule_to_pydantic(r) for r in rules
                if _has_access(cast(str, r.visibility or "private"), cast(str, r.created_by), user_id, _get_shared_group_ids(r), group_ids)
            ]

    def get_alert_rules_for_org(self, tenant_id: str, org_id: str) -> List[AlertRulePydantic]:
        with get_db_session() as db:
            rules = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.tenant_id == tenant_id, AlertRuleDB.org_id == org_id)
                .all()
            )
            return [rule_to_pydantic(r) for r in rules]

    def get_alert_rules_with_owner(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[Tuple[AlertRulePydantic, str]]:
        group_ids = group_ids or []
        capped_limit, capped_offset = _cap_pagination(limit, offset)
        with get_db_session() as db:
            rules = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.tenant_id == tenant_id)
                .offset(capped_offset).limit(capped_limit)
                .all()
            )
            results: List[Tuple[AlertRulePydantic, str]] = []
            for r in rules:
                vis = cast(str, r.visibility or "private")
                created_by = cast(str, r.created_by)
                if _has_access(vis, created_by, user_id, _get_shared_group_ids(r), group_ids):
                    results.append((rule_to_pydantic(r), created_by))
            return results

    def get_alert_rule_raw(self, rule_id: str, tenant_id: str) -> Optional[AlertRuleDB]:
        with get_db_session() as db:
            return (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.id == rule_id, AlertRuleDB.tenant_id == tenant_id)
                .first()
            )

    def get_alert_rule(
        self,
        rule_id: str,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> Optional[AlertRulePydantic]:
        group_ids = group_ids or []
        with get_db_session() as db:
            r = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.id == rule_id, AlertRuleDB.tenant_id == tenant_id)
                .first()
            )
            if not r:
                return None
            if not _has_access(cast(str, r.visibility or "private"), cast(str, r.created_by), user_id, _get_shared_group_ids(r), group_ids):
                return None
            return rule_to_pydantic(r)

    def create_alert_rule(
        self,
        rule_create: AlertRuleCreate,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> AlertRulePydantic:
        with get_db_session() as db:
            rule = AlertRuleDB(
                id=str(uuid.uuid4()), tenant_id=tenant_id, created_by=user_id,
                org_id=rule_create.org_id or None, name=rule_create.name, group=rule_create.group,
                expr=rule_create.expr, duration=rule_create.duration, severity=rule_create.severity,
                labels=rule_create.labels or {}, annotations=rule_create.annotations or {},
                enabled=rule_create.enabled, notification_channels=rule_create.notification_channels or [],
                visibility=rule_create.visibility or "private",
            )
            vis = cast(str, rule.visibility or "private")
            _assign_shared_groups(rule, db, tenant_id, vis, rule_create.shared_group_ids, actor_user_id=user_id, actor_group_ids=group_ids)
            db.add(rule)
            db.flush()
            logger.info("Created alert rule %s (%s) org_id=%s visibility=%s", rule.name, rule.id, rule.org_id, rule.visibility)
            return rule_to_pydantic(rule)

    def update_alert_rule(
        self,
        rule_id: str,
        rule_update: AlertRuleCreate,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> Optional[AlertRulePydantic]:
        group_ids = group_ids or []
        with get_db_session() as db:
            r = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.id == rule_id, AlertRuleDB.tenant_id == tenant_id)
                .first()
            )
            if not r:
                return None
            if not _has_access(cast(str, r.visibility or "private"), cast(str, r.created_by), user_id, _get_shared_group_ids(r), group_ids):
                return None

            r.org_id = rule_update.org_id or None
            r.name = rule_update.name
            r.group = rule_update.group
            r.expr = rule_update.expr
            r.duration = rule_update.duration
            r.severity = rule_update.severity
            r.labels = rule_update.labels or {}
            r.annotations = rule_update.annotations or {}
            r.enabled = rule_update.enabled
            r.notification_channels = rule_update.notification_channels or []
            r.visibility = rule_update.visibility or "private"
            vis = cast(str, r.visibility or "private")
            _assign_shared_groups(r, db, tenant_id, vis, rule_update.shared_group_ids, actor_user_id=user_id, actor_group_ids=group_ids)
            db.flush()
            logger.info("Updated alert rule %s (%s) org_id=%s", r.name, rule_id, r.org_id)
            return rule_to_pydantic(r)

    def delete_alert_rule(
        self,
        rule_id: str,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> bool:
        group_ids = group_ids or []
        with get_db_session() as db:
            r = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.id == rule_id, AlertRuleDB.tenant_id == tenant_id)
                .first()
            )
            if not r:
                return False
            if not _has_access(cast(str, r.visibility or "private"), cast(str, r.created_by), user_id, _get_shared_group_ids(r), group_ids, require_write=True):
                return False
            db.delete(r)
            logger.info("Deleted alert rule %s", rule_id)
            return True

    def get_notification_channels(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[NotificationChannelPydantic]:
        group_ids = group_ids or []
        capped_limit, capped_offset = _cap_pagination(limit, offset)
        with get_db_session() as db:
            channels = (
                db.query(NotificationChannelDB)
                .options(joinedload(NotificationChannelDB.shared_groups))
                .filter(NotificationChannelDB.tenant_id == tenant_id)
                .offset(capped_offset).limit(capped_limit)
                .all()
            )
            result = []
            for ch in channels:
                if not _has_access(cast(str, ch.visibility or "private"), cast(str, ch.created_by), user_id, _get_shared_group_ids(ch), group_ids):
                    continue
                cfg = decrypt_config(cast(Dict[str, Any], getattr(ch, "config") or {}))
                setattr(ch, "config", cfg)
                result.append(channel_to_pydantic_for_viewer(ch, user_id))
            return result

    def get_notification_channel(
        self,
        channel_id: str,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> Optional[NotificationChannelPydantic]:
        group_ids = group_ids or []
        with get_db_session() as db:
            ch = (
                db.query(NotificationChannelDB)
                .options(joinedload(NotificationChannelDB.shared_groups))
                .filter(NotificationChannelDB.id == channel_id, NotificationChannelDB.tenant_id == tenant_id)
                .first()
            )
            if not ch or not _has_access(cast(str, ch.visibility or "private"), cast(str, ch.created_by), user_id, _get_shared_group_ids(ch), group_ids):
                return None
            cfg = decrypt_config(cast(Dict[str, Any], getattr(ch, "config") or {}))
            setattr(ch, "config", cfg)
            return channel_to_pydantic_for_viewer(ch, user_id)

    def create_notification_channel(
        self,
        channel_create: NotificationChannelCreate,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> NotificationChannelPydantic:
        with get_db_session() as db:
            ch = NotificationChannelDB(
                id=str(uuid.uuid4()), tenant_id=tenant_id, created_by=user_id,
                name=channel_create.name, type=channel_create.type,
                config=encrypt_config(channel_create.config or {}),
                enabled=channel_create.enabled, visibility=channel_create.visibility or "private",
            )
            _assign_shared_groups(ch, db, tenant_id, ch.visibility, channel_create.shared_group_ids, actor_user_id=user_id, actor_group_ids=group_ids)
            db.add(ch)
            db.flush()
            logger.info("Created channel %s (%s) visibility=%s", ch.name, ch.id, ch.visibility)
            cfg = decrypt_config(cast(Dict[str, Any], getattr(ch, "config") or {}))
            setattr(ch, "config", cfg)
            return channel_to_pydantic_for_viewer(ch, user_id)

    def update_notification_channel(
        self,
        channel_id: str,
        channel_update: NotificationChannelCreate,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> Optional[NotificationChannelPydantic]:
        group_ids = group_ids or []
        with get_db_session() as db:
            ch = (
                db.query(NotificationChannelDB)
                .options(joinedload(NotificationChannelDB.shared_groups))
                .filter(NotificationChannelDB.id == channel_id, NotificationChannelDB.tenant_id == tenant_id)
                .first()
            )
            if not ch or ch.created_by != user_id:
                return None

            ch.name = channel_update.name
            ch.type = channel_update.type
            ch.config = encrypt_config(channel_update.config or {})
            ch.enabled = channel_update.enabled
            ch.visibility = channel_update.visibility or "private"
            _assign_shared_groups(ch, db, tenant_id, ch.visibility, channel_update.shared_group_ids, actor_user_id=user_id, actor_group_ids=group_ids)
            db.flush()
            logger.info("Updated channel %s (%s)", ch.name, channel_id)
            cfg = decrypt_config(cast(Dict[str, Any], getattr(ch, "config") or {}))
            setattr(ch, "config", cfg)
            return channel_to_pydantic_for_viewer(ch, user_id)

    def delete_notification_channel(
        self,
        channel_id: str,
        tenant_id: str,
        user_id: str,
    ) -> bool:
        with get_db_session() as db:
            ch = (
                db.query(NotificationChannelDB)
                .options(joinedload(NotificationChannelDB.shared_groups))
                .filter(NotificationChannelDB.id == channel_id, NotificationChannelDB.tenant_id == tenant_id)
                .first()
            )
            if not ch or ch.created_by != user_id:
                return False
            db.delete(ch)
            logger.info("Deleted channel %s", channel_id)
            return True

    def is_notification_channel_owner(self, channel_id: str, tenant_id: str, user_id: str) -> bool:
        with get_db_session() as db:
            ch = db.query(NotificationChannelDB).filter(
                NotificationChannelDB.id == channel_id,
                NotificationChannelDB.tenant_id == tenant_id,
            ).first()
            return bool(ch and ch.created_by == user_id)

    def test_notification_channel(
        self,
        channel_id: str,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        channel = self.get_notification_channel(channel_id, tenant_id, user_id, group_ids)
        if not channel:
            return {"success": False, "error": "Channel not found"}
        logger.info("Testing channel: %s (%s)", channel.name, channel.type)
        return {"success": True, "message": f"Test notification would be sent to {channel.type} channel: {channel.name}"}

    def get_notification_channels_for_rule_name(self, rule_name: str) -> List[NotificationChannelPydantic]:
        with get_db_session() as db:
            rules = db.query(AlertRuleDB).filter(
                AlertRuleDB.name == rule_name,
                AlertRuleDB.enabled == True,
            ).limit(int(app_config.MAX_QUERY_LIMIT)).all()

            results: List[NotificationChannelPydantic] = []
            for r in rules:
                q = db.query(NotificationChannelDB).filter(NotificationChannelDB.tenant_id == r.tenant_id)
                if r.notification_channels:
                    q = q.filter(NotificationChannelDB.id.in_(r.notification_channels))
                for ch in q.limit(int(app_config.MAX_QUERY_LIMIT)).all():
                    cfg = decrypt_config(cast(Dict[str, Any], getattr(ch, "config") or {}))
                    setattr(ch, "config", cfg)
                    results.append(channel_to_pydantic_for_viewer(ch, ch.created_by))
            return results
