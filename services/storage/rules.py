# services/storage/rules.py
"""
Storage service for managing alert rules.

Copyright (c) 2026 Stefan Kumarasinghe
Licensed under the Apache License, Version 2.0
"""

from __future__ import annotations

import logging
import uuid
from typing import List, Optional, Tuple, cast

from sqlalchemy.orm import joinedload

from database import get_db_session
from db_models import AlertRule as AlertRuleDB
from models.alerting.rules import AlertRule, AlertRuleCreate
from services.common.access import has_access, assign_shared_groups
from services.common.pagination import cap_pagination
from services.storage.serializers import rule_to_pydantic

logger = logging.getLogger(__name__)


def _shared_group_ids(db_obj) -> List[str]:
    return [g.id for g in db_obj.shared_groups] if getattr(db_obj, "shared_groups", None) else []


class RuleStorageService:
    def __init__(self, backend: Optional[object] = None):
        self._backend = backend

    def get_public_alert_rules(self, tenant_id: str) -> List[AlertRule]:
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
    ) -> List[AlertRule]:
        group_ids = group_ids or []
        capped_limit, capped_offset = cap_pagination(limit, offset)

        with get_db_session() as db:
            rules = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.tenant_id == tenant_id)
                .offset(capped_offset)
                .limit(capped_limit)
                .all()
            )
            out: List[AlertRule] = []
            for r in rules:
                if has_access(cast(str, r.visibility or "private"), cast(str, r.created_by), user_id, _shared_group_ids(r), group_ids):
                    out.append(rule_to_pydantic(r))
            return out

    def get_alert_rules_for_org(self, tenant_id: str, org_id: str) -> List[AlertRule]:
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
    ) -> List[Tuple[AlertRule, str]]:
        group_ids = group_ids or []
        capped_limit, capped_offset = cap_pagination(limit, offset)

        with get_db_session() as db:
            rules = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.tenant_id == tenant_id)
                .offset(capped_offset)
                .limit(capped_limit)
                .all()
            )

            out: List[Tuple[AlertRule, str]] = []
            for r in rules:
                if has_access(cast(str, r.visibility or "private"), cast(str, r.created_by), user_id, _shared_group_ids(r), group_ids):
                    out.append((rule_to_pydantic(r), cast(str, r.created_by)))
            return out

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
    ) -> Optional[AlertRule]:
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
            if not has_access(cast(str, r.visibility or "private"), cast(str, r.created_by), user_id, _shared_group_ids(r), group_ids):
                return None
            return rule_to_pydantic(r)

    def create_alert_rule(
        self,
        rule_create: AlertRuleCreate,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> AlertRule:
        with get_db_session() as db:
            rule = AlertRuleDB(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                created_by=user_id,
                org_id=rule_create.org_id or None,
                name=rule_create.name,
                group=rule_create.group,
                expr=rule_create.expr,
                duration=rule_create.duration,
                severity=rule_create.severity,
                labels=rule_create.labels or {},
                annotations=rule_create.annotations or {},
                enabled=rule_create.enabled,
                notification_channels=rule_create.notification_channels or [],
                visibility=rule_create.visibility or "private",
            )
            assign_shared_groups(
                rule,
                db,
                tenant_id,
                cast(str, rule.visibility or "private"),
                rule_create.shared_group_ids,
                actor_group_ids=group_ids,
            )
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
    ) -> Optional[AlertRule]:
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
            if not has_access(cast(str, r.visibility or "private"), cast(str, r.created_by), user_id, _shared_group_ids(r), group_ids):
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

            assign_shared_groups(
                r,
                db,
                tenant_id,
                cast(str, r.visibility or "private"),
                rule_update.shared_group_ids,
                actor_group_ids=group_ids,
            )
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
            if not has_access(
                cast(str, r.visibility or "private"),
                cast(str, r.created_by),
                user_id,
                _shared_group_ids(r),
                group_ids,
                require_write=True,
            ):
                return False
            db.delete(r)
            logger.info("Deleted alert rule %s", rule_id)
            return True