"""
Group-share revocation helpers for BeNotified resources.
"""

from __future__ import annotations

import json
from typing import Dict, List, Set

from sqlalchemy.orm import Session
from sqlalchemy.orm import joinedload
from sqlalchemy.orm.attributes import flag_modified

from custom_types.json import JSONDict
from db_models import AlertIncident, AlertRule, Group, NotificationChannel, Tenant
from services.common.meta import INCIDENT_META_KEY, _safe_group_ids, parse_meta


def _normalize_ids(values: List[str] | None) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for value in values or []:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out


def prune_removed_member_group_shares(
    db: Session,
    *,
    tenant_id: str,
    group_id: str,
    removed_user_ids: List[str] | None,
    removed_usernames: List[str] | None = None,
) -> Dict[str, int]:
    target_group_id = str(group_id or "").strip()
    removed_ids = set(_normalize_ids(removed_user_ids))
    removed_names = {name.lower() for name in _normalize_ids(removed_usernames)}
    counts = {
        "rules": 0,
        "channels": 0,
        "incidents": 0,
        "jira_integrations": 0,
    }
    if not target_group_id or (not removed_ids and not removed_names):
        return counts

    def _is_removed_actor(actor: object) -> bool:
        candidate = str(actor or "").strip()
        if not candidate:
            return False
        if candidate in removed_ids:
            return True
        return candidate.lower() in removed_names

    rule_rows = (
        db.query(AlertRule)
        .options(joinedload(AlertRule.shared_groups))
        .filter(
            AlertRule.tenant_id == tenant_id,
            AlertRule.visibility == "group",
            AlertRule.shared_groups.any(Group.id == target_group_id),
        )
        .all()
    )
    for row in rule_rows:
        if not _is_removed_actor(row.created_by):
            continue
        before = [str(g.id) for g in row.shared_groups]
        after = [g for g in row.shared_groups if str(g.id) != target_group_id]
        if len(after) == len(before):
            continue
        row.shared_groups = after
        if not row.shared_groups:
            row.visibility = "private"
        counts["rules"] += 1

    channel_rows = (
        db.query(NotificationChannel)
        .options(joinedload(NotificationChannel.shared_groups))
        .filter(
            NotificationChannel.tenant_id == tenant_id,
            NotificationChannel.visibility == "group",
            NotificationChannel.shared_groups.any(Group.id == target_group_id),
        )
        .all()
    )
    for channel_row in channel_rows:
        if not _is_removed_actor(channel_row.created_by):
            continue
        before = [str(g.id) for g in channel_row.shared_groups]
        after = [g for g in channel_row.shared_groups if str(g.id) != target_group_id]
        if len(after) == len(before):
            continue
        channel_row.shared_groups = after
        if not channel_row.shared_groups:
            channel_row.visibility = "private"
        counts["channels"] += 1

    incidents = (
        db.query(AlertIncident)
        .filter(AlertIncident.tenant_id == tenant_id)
        .all()
    )
    for incident in incidents:
        annotations = incident.annotations if isinstance(incident.annotations, dict) else {}
        meta = parse_meta(annotations)
        creator_id = str(meta.get("created_by") or "").strip()
        if not _is_removed_actor(creator_id):
            continue

        visibility = str(meta.get("visibility") or "public").strip().lower()
        if visibility != "group":
            continue

        shared_group_ids = _safe_group_ids(meta)
        if target_group_id not in shared_group_ids:
            continue

        remaining_group_ids = [gid for gid in shared_group_ids if gid != target_group_id]
        meta["shared_group_ids"] = remaining_group_ids
        if not remaining_group_ids:
            meta["visibility"] = "private"
        incident.annotations = {**annotations, INCIDENT_META_KEY: json.dumps(meta)}
        counts["incidents"] += 1

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    settings: JSONDict = dict(tenant.settings) if tenant and isinstance(tenant.settings, dict) else {}
    jira_items = settings.get("jira_integrations")
    if isinstance(jira_items, list):
        changed = 0
        for item in jira_items:
            if not isinstance(item, dict):
                continue
            creator_id = str(item.get("createdBy") or "").strip()
            visibility = str(item.get("visibility") or "private").strip().lower()
            if not _is_removed_actor(creator_id) or visibility != "group":
                continue
            shared = _normalize_ids(item.get("sharedGroupIds") if isinstance(item.get("sharedGroupIds"), list) else [])
            if target_group_id not in shared:
                continue
            remaining = [gid for gid in shared if gid != target_group_id]
            item["sharedGroupIds"] = remaining
            if not remaining:
                item["visibility"] = "private"
            changed += 1
        if changed and tenant:
            settings["jira_integrations"] = jira_items
            tenant.settings = settings
            flag_modified(tenant, "settings")
            counts["jira_integrations"] = changed

    return counts
