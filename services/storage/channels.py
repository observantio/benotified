"""
Storage service for managing notification channels, providing functions to create, read, update, and delete notification channels while enforcing access control based on channel visibility and user/group permissions. This module interacts with the database to persist channel configurations, including encrypted channel settings, and ensures that users can only access channels they have permission to view or modify. The service also includes functionality to test notification channels by simulating a notification send operation, as well as retrieving channels associated with specific alert rules for use in the alerting system.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
import uuid
from typing import Any, Dict, List, Optional, cast

from sqlalchemy.orm import joinedload

from models.alerting.channels import NotificationChannel, NotificationChannelCreate
from database import get_db_session
from db_models import NotificationChannel as NotificationChannelDB, AlertRule as AlertRuleDB
from config import config as app_config

from services.common.pagination import _cap_pagination
from services.common.access import _has_access, _assign_shared_groups
from services.common.encryption import encrypt_config, decrypt_config
from services.storage.serializers import _channel_to_pydantic_for_viewer, _channel_to_pydantic

logger = logging.getLogger(__name__)


class ChannelStorageService:
    def __init__(self, backend):
        self._backend = backend

    def get_notification_channels(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[NotificationChannel]:
        group_ids = group_ids or []
        capped_limit, capped_offset = _cap_pagination(limit, offset)
        with get_db_session() as db:
            channels = db.query(NotificationChannelDB).options(joinedload(NotificationChannelDB.shared_groups)).filter(
                NotificationChannelDB.tenant_id == tenant_id
            ).offset(capped_offset).limit(capped_limit).all()

            results: List[NotificationChannel] = []
            for ch in channels:
                raw_cfg = decrypt_config(cast(Dict[str, Any], getattr(ch, "config") or {}))
                setattr(ch, "config", raw_cfg)
                shared_group_ids = [g.id for g in ch.shared_groups] if ch.shared_groups else []
                if _has_access(cast(str, ch.visibility or "private"), cast(str, ch.created_by), user_id, shared_group_ids, group_ids):
                    results.append(_channel_to_pydantic_for_viewer(ch, user_id))
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
            ch = db.query(NotificationChannelDB).options(joinedload(NotificationChannelDB.shared_groups)).filter(
                NotificationChannelDB.id == channel_id, NotificationChannelDB.tenant_id == tenant_id
            ).first()
            if not ch or not _has_access(cast(str, ch.visibility or "private"), cast(str, ch.created_by), user_id, [g.id for g in ch.shared_groups] if ch.shared_groups else [], group_ids):
                return None
            raw_cfg = decrypt_config(cast(Dict[str, Any], getattr(ch, "config") or {}))
            setattr(ch, "config", raw_cfg)
            return _channel_to_pydantic_for_viewer(ch, user_id)

    def create_notification_channel(
        self,
        channel_create: NotificationChannelCreate,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> NotificationChannel:
        with get_db_session() as db:
            ch = NotificationChannelDB(
                id=str(uuid.uuid4()), tenant_id=tenant_id, created_by=user_id,
                name=channel_create.name, type=channel_create.type,
                config=encrypt_config(channel_create.config or {}),
                enabled=channel_create.enabled, visibility=channel_create.visibility or "private",
            )
            _assign_shared_groups(ch, db, tenant_id, cast(str, ch.visibility or "private"), channel_create.shared_group_ids, actor_user_id=user_id, actor_group_ids=group_ids)
            db.add(ch)
            db.flush()
            logger.info("Created channel %s (%s) visibility=%s", ch.name, ch.id, ch.visibility)
            cfg = decrypt_config(cast(Dict[str, Any], getattr(ch, "config") or {}))
            setattr(ch, "config", cfg)
            return _channel_to_pydantic_for_viewer(ch, user_id)

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
            ch = db.query(NotificationChannelDB).options(joinedload(NotificationChannelDB.shared_groups)).filter(
                NotificationChannelDB.id == channel_id, NotificationChannelDB.tenant_id == tenant_id
            ).first()
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
            return _channel_to_pydantic_for_viewer(ch, user_id)

    def delete_notification_channel(
        self,
        channel_id: str,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> bool:
        with get_db_session() as db:
            ch = db.query(NotificationChannelDB).options(joinedload(NotificationChannelDB.shared_groups)).filter(
                NotificationChannelDB.id == channel_id, NotificationChannelDB.tenant_id == tenant_id
            ).first()
            if not ch or ch.created_by != user_id:
                return False
            db.delete(ch)
            logger.info("Deleted channel %s", channel_id)
            return True

    def is_notification_channel_owner(self, channel_id: str, tenant_id: str, user_id: str) -> bool:
        with get_db_session() as db:
            ch = db.query(NotificationChannelDB).filter(
                NotificationChannelDB.id == channel_id, NotificationChannelDB.tenant_id == tenant_id
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

    def get_notification_channels_for_rule_name(self, rule_name: str) -> List[NotificationChannel]:
        with get_db_session() as db:
            rules = db.query(AlertRuleDB).filter(
                AlertRuleDB.name == rule_name, AlertRuleDB.enabled == True
            ).limit(int(app_config.MAX_QUERY_LIMIT)).all()

            results: List[NotificationChannel] = []
            for r in rules:
                q = db.query(NotificationChannelDB).filter(NotificationChannelDB.tenant_id == r.tenant_id)
                if r.notification_channels:
                    q = q.filter(NotificationChannelDB.id.in_(r.notification_channels))
                for ch in q.limit(int(app_config.MAX_QUERY_LIMIT)).all():
                    # decrypt for owner-view semantics in the serializer
                    raw_cfg = decrypt_config(cast(Dict[str, Any], getattr(ch, "config") or {}))
                    setattr(ch, "config", raw_cfg)
                    results.append(_channel_to_pydantic(ch, ch.created_by))
            return results
