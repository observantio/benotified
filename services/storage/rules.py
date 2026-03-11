"""
Rules management service for handling alert rules, including CRUD operations, access control, and visibility management.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""


from __future__ import annotations

import logging
import uuid
from typing import List, Optional, Tuple

from sqlalchemy.orm import joinedload

from database import get_db_session
from db_models import AlertRule as AlertRuleDB, HiddenAlertRule
from models.alerting.rules import AlertRule, AlertRuleCreate
from services.common.access import has_access, assign_shared_groups
from services.common.pagination import cap_pagination
from services.common.tenants import ensure_tenant_exists
from services.storage.serializers import rule_to_pydantic

logger = logging.getLogger(__name__)


def _shared_group_ids(db_obj: AlertRuleDB) -> List[str]:
    return [g.id for g in db_obj.shared_groups] if db_obj.shared_groups else []


def _visibility_of(rule: AlertRuleDB) -> str:
    return str(rule.visibility or "private")


def _creator_of(rule: AlertRuleDB) -> str:
    return str(rule.created_by or "")

class RuleStorageService:
    def get_alert_rule_by_name_for_delivery(
        self,
        tenant_id: str,
        rule_name: str,
        org_id: Optional[str] = None,
    ) -> Optional[AlertRule]:
        target_name = str(rule_name or "").strip()
        if not target_name:
            return None
        with get_db_session() as db:
            rules = (
                db.query(AlertRuleDB)
                .options(joinedload(AlertRuleDB.shared_groups))
                .filter(AlertRuleDB.tenant_id == tenant_id, AlertRuleDB.name == target_name)
                .all()
            )
            if not rules:
                return None
            if org_id:
                org_matched = [r for r in rules if str(getattr(r, "org_id", "") or "") == str(org_id)]
                rules = org_matched or [r for r in rules if not getattr(r, "org_id", None)] or rules
            return rule_to_pydantic(rules[0])

    def get_hidden_rule_ids(self, tenant_id: str, user_id: str) -> List[str]:
        with get_db_session() as db:
            rows = (
                db.query(HiddenAlertRule.rule_id)
                .filter(
                    HiddenAlertRule.tenant_id == tenant_id,
                    HiddenAlertRule.user_id == user_id,
                )
                .all()
            )
            return [str(rule_id) for (rule_id,) in rows]

    def get_hidden_rule_names(self, tenant_id: str, user_id: str) -> List[str]:
        with get_db_session() as db:
            rows = (
                db.query(AlertRuleDB.name)
                .join(HiddenAlertRule, HiddenAlertRule.rule_id == AlertRuleDB.id)
                .filter(
                    HiddenAlertRule.tenant_id == tenant_id,
                    HiddenAlertRule.user_id == user_id,
                    AlertRuleDB.tenant_id == tenant_id,
                )
                .all()
            )
            return [str(name) for (name,) in rows if str(name or "").strip()]

    def toggle_rule_hidden(self, tenant_id: str, user_id: str, rule_id: str, hidden: bool) -> bool:
        with get_db_session() as db:
            rule = (
                db.query(AlertRuleDB)
                .filter(
                    AlertRuleDB.id == rule_id,
                    AlertRuleDB.tenant_id == tenant_id,
                )
                .first()
            )
            if not rule:
                return False

            existing = (
                db.query(HiddenAlertRule)
                .filter(
                    HiddenAlertRule.tenant_id == tenant_id,
                    HiddenAlertRule.user_id == user_id,
                    HiddenAlertRule.rule_id == rule_id,
                )
                .first()
            )

            if hidden:
                if not existing:
                    db.add(
                        HiddenAlertRule(
                            tenant_id=tenant_id,
                            user_id=user_id,
                            rule_id=rule_id,
                        )
                    )
            else:
                if existing:
                    db.delete(existing)
            return True

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
                if has_access(_visibility_of(r), _creator_of(r), user_id, _shared_group_ids(r), group_ids):
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
                if has_access(_visibility_of(r), _creator_of(r), user_id, _shared_group_ids(r), group_ids):
                    out.append((rule_to_pydantic(r), _creator_of(r)))
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
            if not has_access(_visibility_of(r), _creator_of(r), user_id, _shared_group_ids(r), group_ids):
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
            ensure_tenant_exists(db, tenant_id)
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
                _visibility_of(rule),
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
            if not has_access(_visibility_of(r), _creator_of(r), user_id, _shared_group_ids(r), group_ids):
                return None
            if not has_access(
                _visibility_of(r),
                _creator_of(r),
                user_id,
                _shared_group_ids(r),
                group_ids,
                require_write=True,
            ):
                return None

            r.org_id = rule_update.org_id or None
            r.name = rule_update.name
            r.group = rule_update.group
            r.expr = rule_update.expr
            r.duration = rule_update.duration or "5m"
            r.severity = rule_update.severity
            r.labels = {str(key): value for key, value in (rule_update.labels or {}).items()}
            r.annotations = {str(key): value for key, value in (rule_update.annotations or {}).items()}
            r.enabled = rule_update.enabled
            r.notification_channels = [str(channel) for channel in (rule_update.notification_channels or [])]
            r.visibility = rule_update.visibility or "private"

            assign_shared_groups(
                r,
                db,
                tenant_id,
                _visibility_of(r),
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
                _visibility_of(r),
                _creator_of(r),
                user_id,
                _shared_group_ids(r),
                group_ids,
                require_write=True,
            ):
                return False
            db.delete(r)
            logger.info("Deleted alert rule %s", rule_id)
            return True
