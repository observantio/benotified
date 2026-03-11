"""
Storage service for managing notification channels, including CRUD operations, access control, and testing functionality.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""


from __future__ import annotations

import logging
import uuid
from typing import List, Optional

from sqlalchemy.orm import joinedload

from config import config as app_config
from custom_types.json import JSONDict
from database import get_db_session
from db_models import AlertRule as AlertRuleDB
from db_models import NotificationChannel as NotificationChannelDB
from models.alerting.channels import NotificationChannel, NotificationChannelCreate
from services.common.access import has_access, assign_shared_groups
from services.common.encryption import decrypt_config, encrypt_config
from services.common.pagination import cap_pagination
from services.common.tenants import ensure_tenant_exists
from services.common.visibility import normalize_storage_visibility
from services.storage.serializers import channel_to_pydantic, channel_to_pydantic_for_viewer

logger = logging.getLogger(__name__)


def _shared_group_ids(db_obj: NotificationChannelDB) -> List[str]:
    return [g.id for g in db_obj.shared_groups] if db_obj.shared_groups else []


def _visibility_of(channel: NotificationChannelDB) -> str:
    return str(getattr(channel, "visibility", None) or "private")


def _creator_of(channel: NotificationChannelDB) -> str:
    return str(getattr(channel, "created_by", None) or "")


def _config_dict(channel: NotificationChannelDB) -> JSONDict:
    raw_config = getattr(channel, "config", None)
    return raw_config if isinstance(raw_config, dict) else {}


class ChannelStorageService:
    @staticmethod
    def _rule_channel_compatible(rule: AlertRuleDB, channel: NotificationChannelDB) -> bool:
        rule_visibility = normalize_storage_visibility(getattr(rule, "visibility", None))
        channel_visibility = normalize_storage_visibility(getattr(channel, "visibility", None))
        rule_owner = str(getattr(rule, "created_by", "") or "").strip()
        channel_owner = str(getattr(channel, "created_by", "") or "").strip()
        rule_groups = {str(g.id) for g in (getattr(rule, "shared_groups", None) or []) if str(getattr(g, "id", "")).strip()}
        channel_groups = {str(g.id) for g in (getattr(channel, "shared_groups", None) or []) if str(getattr(g, "id", "")).strip()}

        # Private rules can only trigger private owner-bound channels.
        if rule_visibility == "private":
            return bool(channel_visibility == "private" and rule_owner and rule_owner == channel_owner)

        # Group rules can only trigger tenant/public channels or channels shared to overlapping groups.
        if rule_visibility == "group":
            if channel_visibility == "group":
                return bool(rule_groups & channel_groups)
            return channel_visibility == "public"

        # Tenant/public rules can only trigger tenant/public channels.
        return channel_visibility == "public"

    def get_notification_channels(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[NotificationChannel]:
        group_ids = group_ids or []
        capped_limit, capped_offset = cap_pagination(limit, offset)

        with get_db_session() as db:
            channels = (
                db.query(NotificationChannelDB)
                .options(joinedload(NotificationChannelDB.shared_groups))
                .filter(NotificationChannelDB.tenant_id == tenant_id)
                .offset(capped_offset)
                .limit(capped_limit)
                .all()
            )

            results: List[NotificationChannel] = []
            for ch in channels:
                if not has_access(
                    _visibility_of(ch),
                    _creator_of(ch),
                    user_id,
                    _shared_group_ids(ch),
                    group_ids,
                ):
                    continue
                raw_cfg = decrypt_config(_config_dict(ch))
                setattr(ch, "config", raw_cfg)
                results.append(channel_to_pydantic_for_viewer(ch, user_id))
            return results

    def get_notification_channel(
        self,
        channel_id: str,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> Optional[NotificationChannel]:
        group_ids = group_ids or []
        with get_db_session() as db:
            ch = (
                db.query(NotificationChannelDB)
                .options(joinedload(NotificationChannelDB.shared_groups))
                .filter(NotificationChannelDB.id == channel_id, NotificationChannelDB.tenant_id == tenant_id)
                .first()
            )
            if not ch:
                return None
            if not has_access(
                _visibility_of(ch),
                _creator_of(ch),
                user_id,
                _shared_group_ids(ch),
                group_ids,
            ):
                return None
            raw_cfg = decrypt_config(_config_dict(ch))
            setattr(ch, "config", raw_cfg)
            return channel_to_pydantic_for_viewer(ch, user_id)

    def create_notification_channel(
        self,
        channel_create: NotificationChannelCreate,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> NotificationChannel:
        with get_db_session() as db:
            ensure_tenant_exists(db, tenant_id)
            ch = NotificationChannelDB(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                created_by=user_id,
                name=channel_create.name,
                type=channel_create.type,
                config=encrypt_config(channel_create.config or {}),
                enabled=channel_create.enabled,
                visibility=channel_create.visibility or "private",
            )
            assign_shared_groups(
                ch,
                db,
                tenant_id,
                _visibility_of(ch),
                channel_create.shared_group_ids,
                actor_group_ids=group_ids,
            )
            db.add(ch)
            db.flush()
            logger.info("Created channel %s (%s) visibility=%s", ch.name, ch.id, ch.visibility)

            cfg = decrypt_config(_config_dict(ch))
            setattr(ch, "config", cfg)
            return channel_to_pydantic_for_viewer(ch, user_id)

    def update_notification_channel(
        self,
        channel_id: str,
        channel_update: NotificationChannelCreate,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> Optional[NotificationChannel]:
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
            assign_shared_groups(
                ch,
                db,
                tenant_id,
                _visibility_of(ch),
                channel_update.shared_group_ids,
                actor_group_ids=group_ids,
            )

            db.flush()
            logger.info("Updated channel %s (%s)", ch.name, channel_id)

            cfg = decrypt_config(_config_dict(ch))
            setattr(ch, "config", cfg)
            return channel_to_pydantic_for_viewer(ch, user_id)

    def delete_notification_channel(self, channel_id: str, tenant_id: str, user_id: str) -> bool:
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
    ) -> dict[str, object]:
        channel = self.get_notification_channel(channel_id, tenant_id, user_id, group_ids)
        if not channel:
            return {"success": False, "error": "Channel not found"}
        logger.info("Testing channel: %s (%s)", channel.name, channel.type)
        return {"success": True, "message": f"Test notification would be sent to {channel.type} channel: {channel.name}"}

    def get_notification_channels_for_rule_name(
        self,
        tenant_id: str,
        rule_name: str,
        org_id: Optional[str] = None,
    ) -> List[NotificationChannel]:
        with get_db_session() as db:
            rules = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.name == rule_name, AlertRuleDB.enabled.is_(True))
                .filter(AlertRuleDB.tenant_id == tenant_id)
                .limit(int(app_config.MAX_QUERY_LIMIT))
                .all()
            )
            if not rules:
                logger.info(
                    "No enabled rules found for delivery: tenant=%s rule=%s org=%s",
                    tenant_id,
                    rule_name,
                    org_id or "",
                )
                return []
            if org_id:
                org_matched = [r for r in rules if str(getattr(r, "org_id", "") or "") == str(org_id)]
                rules = org_matched or [r for r in rules if not getattr(r, "org_id", None)] or rules

            tenant_channels = (
                db.query(NotificationChannelDB)
                .options(joinedload(NotificationChannelDB.shared_groups))
                .filter(NotificationChannelDB.tenant_id == tenant_id)
                .limit(int(app_config.MAX_QUERY_LIMIT))
                .all()
            )
            channel_by_id = {str(ch.id): ch for ch in tenant_channels}

            results: List[NotificationChannel] = []
            seen_ids: set[str] = set()
            debug_notes: List[str] = []
            for r in rules:
                configured_ids = [str(cid) for cid in (r.notification_channels or []) if str(cid).strip()]
                if configured_ids:
                    candidate_channels = [channel_by_id[cid] for cid in configured_ids if cid in channel_by_id]
                    missing_ids = [cid for cid in configured_ids if cid not in channel_by_id]
                    disabled_ids = [str(ch.id) for ch in candidate_channels if not bool(ch.enabled)]
                    if missing_ids:
                        debug_notes.append(f"rule={r.id}:missing={missing_ids}")
                    if disabled_ids:
                        debug_notes.append(f"rule={r.id}:disabled={disabled_ids}")
                    candidate_channels = [ch for ch in candidate_channels if bool(ch.enabled)]
                else:
                    candidate_channels = [ch for ch in tenant_channels if bool(ch.enabled)]
                    debug_notes.append(f"rule={r.id}:no_explicit_channel_ids")

                compatible_skipped = 0
                for ch in candidate_channels:
                    if ch.id in seen_ids:
                        continue
                    if not self._rule_channel_compatible(r, ch):
                        compatible_skipped += 1
                        continue
                    raw_cfg = decrypt_config(_config_dict(ch))
                    setattr(ch, "config", raw_cfg)
                    results.append(channel_to_pydantic(ch))
                    seen_ids.add(str(ch.id))
                if compatible_skipped:
                    debug_notes.append(f"rule={r.id}:incompatible_skipped={compatible_skipped}")
            if not results:
                logger.info(
                    "No deliverable channels after resolution: tenant=%s rule=%s org=%s matched_rules=%s notes=%s",
                    tenant_id,
                    rule_name,
                    org_id or "",
                    [str(getattr(r, "id", "")) for r in rules],
                    ";".join(debug_notes) if debug_notes else "none",
                )
            return results
