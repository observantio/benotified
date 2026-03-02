
"""
Storage service that composes per-domain storage services (rules/incidents/channels).
Keeps the public API stable while keeping domain logic out of this file.

Copyright (c) 2026 Stefan Kumarasinghe
Licensed under the Apache License, Version 2.0
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from models.alerting.channels import NotificationChannel, NotificationChannelCreate
from models.alerting.incidents import AlertIncident, AlertIncidentUpdateRequest
from models.alerting.rules import AlertRule, AlertRuleCreate

from services.storage.channels import ChannelStorageService
from services.storage.incidents import IncidentStorageService
from services.storage.rules import RuleStorageService


class DatabaseStorageService:
    def __init__(self):
        self.channels = ChannelStorageService()
        self.incidents = IncidentStorageService()
        self.rules = RuleStorageService()

    def sync_incidents_from_alerts(self, tenant_id: str, alerts: List[Dict[str, Any]], resolve_missing: bool = True) -> None:
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
    ) -> Optional[AlertIncident]:
        return self.incidents.update_incident(incident_id, tenant_id, user_id, payload)

    def filter_alerts_for_user(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]],
        alerts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
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

    def get_alert_rules_with_owner(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[Tuple[AlertRule, str]]:
        return self.rules.get_alert_rules_with_owner(tenant_id, user_id, group_ids=group_ids, limit=limit, offset=offset)

    def get_alert_rule_raw(self, rule_id: str, tenant_id: str):
        return self.rules.get_alert_rule_raw(rule_id, tenant_id)

    def get_alert_rule(
        self,
        rule_id: str,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
    ) -> Optional[AlertRule]:
        return self.rules.get_alert_rule(rule_id, tenant_id, user_id, group_ids=group_ids)

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
    ) -> Dict[str, Any]:
        return self.channels.test_notification_channel(channel_id, tenant_id, user_id, group_ids=group_ids)

    def get_notification_channels_for_rule_name(self, rule_name: str) -> List[NotificationChannel]:
        return self.channels.get_notification_channels_for_rule_name(rule_name)