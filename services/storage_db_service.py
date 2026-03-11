"""
Storage service for managing alert incidents, rules, and notification channels, providing a unified interface for database operations and ensuring proper access control and data handling based on user permissions.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""


from __future__ import annotations

from typing import List, Optional, Tuple

from sqlalchemy.dialects.postgresql import insert as pg_insert

from custom_types.json import JSONDict
from database import get_db_session
from db_models import AlertRule as AlertRuleDB, HiddenJiraIntegration, HiddenNotificationChannel, HiddenSilence
from models.alerting.channels import NotificationChannel, NotificationChannelCreate
from models.alerting.incidents import AlertIncident, AlertIncidentUpdateRequest
from models.alerting.rules import AlertRule, AlertRuleCreate

from services.storage.channels import ChannelStorageService
from services.storage.incidents import IncidentStorageService
from services.storage.revocation import prune_removed_member_group_shares
from services.storage.rules import RuleStorageService


class DatabaseStorageService:
    def __init__(self) -> None:
        self.channels = ChannelStorageService()
        self.incidents = IncidentStorageService()
        self.rules = RuleStorageService()

    def sync_incidents_from_alerts(self, tenant_id: str, alerts: List[JSONDict], resolve_missing: bool = True) -> None:
        return self.incidents.sync_incidents_from_alerts(tenant_id, alerts, resolve_missing)

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
        return self.incidents.list_incidents(
            tenant_id=tenant_id,
            user_id=user_id,
            group_ids=group_ids,
            status=status,
            visibility=visibility,
            group_id=group_id,
            limit=limit,
            offset=offset,
        )

    def get_incident_summary(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> JSONDict:
        return self.incidents.get_incident_summary(
            tenant_id=tenant_id,
            user_id=user_id,
            group_ids=group_ids,
        )

    def unlink_jira_integration_from_incidents(
        self,
        tenant_id: str,
        integration_id: str,
    ) -> int:
        return self.incidents.unlink_jira_integration_from_incidents(
            tenant_id=tenant_id,
            integration_id=integration_id,
        )

    def get_incident_for_user(
        self,
        incident_id: str,
        tenant_id: str,
        user_id: Optional[str] = None,
        group_ids: Optional[List[str]] = None,
        require_write: bool = False,
    ) -> Optional[AlertIncident]:
        return self.incidents.get_incident_for_user(
            incident_id=incident_id,
            tenant_id=tenant_id,
            user_id=user_id,
            group_ids=group_ids,
            require_write=require_write,
        )

    def update_incident(
        self,
        incident_id: str,
        tenant_id: str,
        user_id: str,
        payload: AlertIncidentUpdateRequest,
        group_ids: Optional[List[str]] = None,
    ) -> Optional[AlertIncident]:
        return self.incidents.update_incident(incident_id, tenant_id, user_id, payload, group_ids=group_ids)

    def filter_alerts_for_user(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]],
        alerts: List[JSONDict],
    ) -> List[JSONDict]:
        return self.incidents.filter_alerts_for_user(tenant_id, user_id, group_ids, alerts)

    def get_public_alert_rules(self, tenant_id: str) -> List[AlertRule]:
        return self.rules.get_public_alert_rules(tenant_id)

    def get_alert_rules(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[AlertRule]:
        return self.rules.get_alert_rules(tenant_id, user_id, group_ids=group_ids, limit=limit, offset=offset)

    def get_alert_rules_for_org(self, tenant_id: str, org_id: str) -> List[AlertRule]:
        return self.rules.get_alert_rules_for_org(tenant_id, org_id)

    def get_hidden_rule_ids(self, tenant_id: str, user_id: str) -> List[str]:
        return self.rules.get_hidden_rule_ids(tenant_id, user_id)

    def get_hidden_rule_names(self, tenant_id: str, user_id: str) -> List[str]:
        return self.rules.get_hidden_rule_names(tenant_id, user_id)

    def toggle_rule_hidden(self, tenant_id: str, user_id: str, rule_id: str, hidden: bool) -> bool:
        return self.rules.toggle_rule_hidden(tenant_id, user_id, rule_id, hidden)

    def get_alert_rules_with_owner(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[Tuple[AlertRule, str]]:
        return self.rules.get_alert_rules_with_owner(tenant_id, user_id, group_ids=group_ids, limit=limit, offset=offset)

    def get_alert_rule_raw(self, rule_id: str, tenant_id: str) -> AlertRuleDB | None:
        return self.rules.get_alert_rule_raw(rule_id, tenant_id)

    def get_alert_rule(
        self,
        rule_id: str,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> Optional[AlertRule]:
        return self.rules.get_alert_rule(rule_id, tenant_id, user_id, group_ids=group_ids)

    def get_alert_rule_by_name_for_delivery(
        self,
        tenant_id: str,
        rule_name: str,
        org_id: Optional[str] = None,
    ) -> Optional[AlertRule]:
        return self.rules.get_alert_rule_by_name_for_delivery(tenant_id, rule_name, org_id=org_id)

    def create_alert_rule(
        self,
        rule_create: AlertRuleCreate,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> AlertRule:
        return self.rules.create_alert_rule(rule_create, tenant_id, user_id, group_ids=group_ids)

    def update_alert_rule(
        self,
        rule_id: str,
        rule_update: AlertRuleCreate,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> Optional[AlertRule]:
        return self.rules.update_alert_rule(rule_id, rule_update, tenant_id, user_id, group_ids=group_ids)

    def delete_alert_rule(
        self,
        rule_id: str,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> bool:
        return self.rules.delete_alert_rule(rule_id, tenant_id, user_id, group_ids=group_ids)

    def get_notification_channels(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[NotificationChannel]:
        return self.channels.get_notification_channels(tenant_id, user_id, group_ids=group_ids, limit=limit, offset=offset)

    def get_notification_channel(
        self,
        channel_id: str,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> Optional[NotificationChannel]:
        return self.channels.get_notification_channel(channel_id, tenant_id, user_id, group_ids=group_ids)

    def create_notification_channel(
        self,
        channel_create: NotificationChannelCreate,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> NotificationChannel:
        return self.channels.create_notification_channel(channel_create, tenant_id, user_id, group_ids=group_ids)

    def update_notification_channel(
        self,
        channel_id: str,
        channel_update: NotificationChannelCreate,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> Optional[NotificationChannel]:
        return self.channels.update_notification_channel(channel_id, channel_update, tenant_id, user_id, group_ids=group_ids)

    def delete_notification_channel(self, channel_id: str, tenant_id: str, user_id: str) -> bool:
        return self.channels.delete_notification_channel(channel_id, tenant_id, user_id)

    def is_notification_channel_owner(self, channel_id: str, tenant_id: str, user_id: str) -> bool:
        return self.channels.is_notification_channel_owner(channel_id, tenant_id, user_id)

    def test_notification_channel(
        self,
        channel_id: str,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> dict[str, object]:
        return self.channels.test_notification_channel(channel_id, tenant_id, user_id, group_ids=group_ids)

    def get_notification_channels_for_rule_name(
        self,
        tenant_id: str,
        rule_name: str,
        org_id: Optional[str] = None,
    ) -> List[NotificationChannel]:
        return self.channels.get_notification_channels_for_rule_name(tenant_id, rule_name, org_id=org_id)

    def get_hidden_silence_ids(self, tenant_id: str, user_id: str) -> List[str]:
        with get_db_session() as db:
            rows = (
                db.query(HiddenSilence.silence_id)
                .filter(
                    HiddenSilence.tenant_id == tenant_id,
                    HiddenSilence.user_id == user_id,
                )
                .all()
            )
            return [str(silence_id) for (silence_id,) in rows]

    def toggle_silence_hidden(self, tenant_id: str, user_id: str, silence_id: str, hidden: bool) -> bool:
        with get_db_session() as db:
            existing = (
                db.query(HiddenSilence)
                .filter(
                    HiddenSilence.tenant_id == tenant_id,
                    HiddenSilence.user_id == user_id,
                    HiddenSilence.silence_id == silence_id,
                )
                .first()
            )

            if hidden:
                if not existing:
                    db.add(
                        HiddenSilence(
                            tenant_id=tenant_id,
                            user_id=user_id,
                            silence_id=silence_id,
                        )
                    )
            else:
                if existing:
                    db.delete(existing)
            return True

    def get_hidden_channel_ids(self, tenant_id: str, user_id: str) -> List[str]:
        with get_db_session() as db:
            rows = (
                db.query(HiddenNotificationChannel.channel_id)
                .filter(
                    HiddenNotificationChannel.tenant_id == tenant_id,
                    HiddenNotificationChannel.user_id == user_id,
                )
                .all()
            )
            return [str(channel_id) for (channel_id,) in rows]

    def toggle_channel_hidden(self, tenant_id: str, user_id: str, channel_id: str, hidden: bool) -> bool:
        with get_db_session() as db:
            existing = (
                db.query(HiddenNotificationChannel)
                .filter(
                    HiddenNotificationChannel.tenant_id == tenant_id,
                    HiddenNotificationChannel.user_id == user_id,
                    HiddenNotificationChannel.channel_id == channel_id,
                )
                .first()
            )
            if hidden:
                if not existing:
                    db.add(
                        HiddenNotificationChannel(
                            tenant_id=tenant_id,
                            user_id=user_id,
                            channel_id=channel_id,
                        )
                    )
            else:
                if existing:
                    db.delete(existing)
            return True

    def prune_removed_member_group_shares(
        self,
        tenant_id: str,
        group_id: str,
        removed_user_ids: Optional[List[str]] = None,
        removed_usernames: Optional[List[str]] = None,
    ) -> dict[str, int]:
        with get_db_session() as db:
            return prune_removed_member_group_shares(
                db,
                tenant_id=tenant_id,
                group_id=group_id,
                removed_user_ids=removed_user_ids or [],
                removed_usernames=removed_usernames or [],
            )

    def get_hidden_jira_integration_ids(self, tenant_id: str, user_id: str) -> List[str]:
        with get_db_session() as db:
            rows = (
                db.query(HiddenJiraIntegration.integration_id)
                .filter(
                    HiddenJiraIntegration.tenant_id == tenant_id,
                    HiddenJiraIntegration.user_id == user_id,
                )
                .all()
            )
            return [str(integration_id) for (integration_id,) in rows]

    def toggle_jira_integration_hidden(
        self,
        tenant_id: str,
        user_id: str,
        integration_id: str,
        hidden: bool,
    ) -> bool:
        with get_db_session() as db:
            if hidden:
                db.execute(
                    pg_insert(HiddenJiraIntegration)
                    .values(
                        tenant_id=tenant_id,
                        user_id=user_id,
                        integration_id=integration_id,
                    )
                    .on_conflict_do_nothing(
                        index_elements=[
                            HiddenJiraIntegration.tenant_id,
                            HiddenJiraIntegration.user_id,
                            HiddenJiraIntegration.integration_id,
                        ]
                    )
                )
            else:
                existing = (
                    db.query(HiddenJiraIntegration)
                    .filter(
                        HiddenJiraIntegration.tenant_id == tenant_id,
                        HiddenJiraIntegration.user_id == user_id,
                        HiddenJiraIntegration.integration_id == integration_id,
                    )
                    .first()
                )
                if existing:
                    db.delete(existing)
            return True
