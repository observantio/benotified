"""
Service for managing interactions with AlertManager, providing functions to retrieve and manage alerts, silences, and notification channels. This module includes logic to interact with the AlertManager API for operations such as listing alerts, creating and deleting silences, and retrieving the status of the AlertManager instance. The service also handles the encoding and decoding of silence metadata within silence comments, enforces security for webhook endpoints, and provides utility functions related to alerting and silencing. Additionally, it includes functionality to synchronize alert rules with Mimir and to notify external services based on alert conditions.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import json
import logging
from hmac import compare_digest
from typing import Dict, List, Optional
from fastapi import HTTPException, Request, status

from config import config
from database import get_db_session
from db_models import PurgedSilence
from middleware.dependencies import enforce_public_endpoint_security
from middleware.resilience import with_retry, with_timeout
from models.access.auth_models import TokenData
from models.alerting.alerts import Alert, AlertGroup
from models.alerting.silences import Silence, SilenceCreate
from models.alerting.rules import AlertRule
from models.alerting.receivers import AlertManagerStatus
from services.common.http_client import create_async_client
from services.alerting.silence_metadata import (
    SILENCE_META_PREFIX,
    normalize_visibility,
    encode_silence_comment,
    decode_silence_comment,
)
from services.alerting.ruler_yaml import (
    yaml_quote,
    group_enabled_rules,
    build_ruler_group_yaml,
    extract_mimir_group_names,
)
from services.alerting.alerts_ops import (
    list_metric_names,
    get_alerts,
    get_alert_groups,
    post_alerts,
    delete_alerts,
)
from services.alerting.silences_ops import (
    apply_silence_metadata,
    silence_accessible,
    get_silences,
    get_silence,
    create_silence,
    delete_silence,
    update_silence,
)
from services.alerting.channels_ops import notify_for_alerts, get_status, get_receivers
from services.alerting.rules_ops import resolve_rule_org_id, sync_mimir_rules_for_org

logger = logging.getLogger(__name__)
LABELS_JSON_ERROR = "Invalid filter_labels JSON"
MIMIR_RULES_NAMESPACE = "beobservant"
MIMIR_RULER_CONFIG_BASEPATH = "/prometheus/config/v1/rules"


class AlertManagerService:
    def __init__(self, alertmanager_url: str = config.ALERTMANAGER_URL):
        self.alertmanager_url = alertmanager_url.rstrip("/")
        self.timeout = config.DEFAULT_TIMEOUT
        self._client = create_async_client(self.timeout)
        self._mimir_client = create_async_client(self.timeout)
        self.logger = logger
        self.config = config
        self.status_model = AlertManagerStatus
        self.MIMIR_RULES_NAMESPACE = MIMIR_RULES_NAMESPACE
        self.MIMIR_RULER_CONFIG_BASEPATH = MIMIR_RULER_CONFIG_BASEPATH

    def parse_filter_labels(self, filter_labels: Optional[str]) -> Optional[Dict[str, str]]:
        if not filter_labels:
            return None
        try:
            parsed = json.loads(filter_labels)
        except json.JSONDecodeError as exc:
            raise ValueError(LABELS_JSON_ERROR) from exc
        if not isinstance(parsed, dict):
            raise ValueError(LABELS_JSON_ERROR)
        return {str(k): str(v) for k, v in parsed.items()}

    def parse_filter_labels_or_none(self, filter_labels: Optional[str]) -> Optional[Dict[str, str]]:
        if not filter_labels:
            return None
        return self.parse_filter_labels(filter_labels)

    def user_scope(self, current_user: TokenData) -> tuple[str, str, List[str]]:
        return (
            current_user.tenant_id,
            current_user.user_id,
            getattr(current_user, "group_ids", []) or [],
        )

    def enforce_webhook_security(self, request: Request, *, scope: str) -> None:
        enforce_public_endpoint_security(
            request,
            scope=scope,
            limit=config.RATE_LIMIT_PUBLIC_PER_MINUTE,
            window_seconds=60,
            allowlist=config.WEBHOOK_IP_ALLOWLIST,
        )
        expected = config.INBOUND_WEBHOOK_TOKEN
        if not expected:
            if config.IS_PRODUCTION:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="INBOUND_WEBHOOK_TOKEN is required in production",
                )
            return

        provided_header = request.headers.get("x-beobservant-webhook-token")
        if provided_header and compare_digest(provided_header, expected):
            return

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            bearer = auth_header.split(" ", 1)[1].strip()
            if bearer and compare_digest(bearer, expected):
                return

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook token")

    def display_user_label(self, user_obj, fallback: str) -> str:
        if not user_obj:
            return fallback
        name = (getattr(user_obj, "full_name", None) or getattr(user_obj, "username", None) or fallback or "system").strip()
        email = (getattr(user_obj, "email", None) or "").strip()
        return f"{name} <{email}>" if email else name

    def normalize_visibility(self, value: Optional[str]) -> str:
        return normalize_visibility(value)

    def encode_silence_comment(self, comment: str, visibility: str, shared_group_ids: List[str]) -> str:
        return encode_silence_comment(comment, visibility, shared_group_ids)

    def decode_silence_comment(self, comment: Optional[str]) -> Dict[str, object]:
        return decode_silence_comment(comment)

    def apply_silence_metadata(self, silence: Silence) -> Silence:
        return apply_silence_metadata(self, silence)

    def silence_accessible(self, silence: Silence, current_user: TokenData) -> bool:
        return silence_accessible(self, silence, current_user)

    def resolve_rule_org_id(self, rule_org_id: Optional[str], current_user: TokenData) -> str:
        return resolve_rule_org_id(self, rule_org_id, current_user)

    async def notify_for_alerts(self, alerts_list, storage_service, notification_service) -> None:
        return await notify_for_alerts(self, alerts_list, storage_service, notification_service)

    async def list_metric_names(self, org_id: str) -> List[str]:
        return await list_metric_names(self, org_id)

    def _yaml_quote(self, value: object) -> str:
        return yaml_quote(value)

    def _group_enabled_rules(self, rules: List[AlertRule]) -> Dict[str, List[AlertRule]]:
        return group_enabled_rules(rules)

    def _build_ruler_group_yaml(self, group_name: str, rules: List[AlertRule]) -> str:
        return build_ruler_group_yaml(group_name, rules)

    def _extract_mimir_group_names(self, namespace_yaml: str) -> List[str]:
        return extract_mimir_group_names(namespace_yaml)

    async def sync_mimir_rules_for_org(self, org_id: str, rules: List[AlertRule]) -> None:
        return await sync_mimir_rules_for_org(self, org_id, rules)

    @with_retry()
    @with_timeout()
    async def get_alerts(
        self,
        filter_labels: Optional[Dict[str, str]] = None,
        active: Optional[bool] = None,
        silenced: Optional[bool] = None,
        inhibited: Optional[bool] = None,
    ) -> List[Alert]:
        return await get_alerts(self, filter_labels, active, silenced, inhibited)

    async def get_alert_groups(self, filter_labels: Optional[Dict[str, str]] = None) -> List[AlertGroup]:
        return await get_alert_groups(self, filter_labels)

    async def post_alerts(self, alerts: List[Alert]) -> bool:
        return await post_alerts(self, alerts)

    async def get_silences(self, filter_labels: Optional[Dict[str, str]] = None) -> List[Silence]:
        return await get_silences(self, filter_labels)

    async def get_silence(self, silence_id: str) -> Optional[Silence]:
        return await get_silence(self, silence_id)

    async def create_silence(self, silence: SilenceCreate) -> Optional[str]:
        return await create_silence(self, silence)

    async def delete_silence(self, silence_id: str) -> bool:
        if not await delete_silence(self, silence_id):
            return False
        try:
            with get_db_session() as db:
                if not db.query(PurgedSilence).filter_by(id=silence_id).first():
                    db.add(PurgedSilence(id=silence_id, tenant_id=None))
                    db.commit()
                    self.logger.info("Purged silence %s persisted to DB", silence_id)
        except Exception as exc:
            self.logger.warning("Failed to persist purged silence %s: %s", silence_id, exc)
        return True

    async def get_status(self) -> Optional[AlertManagerStatus]:
        return await get_status(self)

    async def get_receivers(self) -> List[str]:
        return await get_receivers(self)

    async def delete_alerts(self, filter_labels: Optional[Dict[str, str]] = None) -> bool:
        return await delete_alerts(self, filter_labels)

    async def update_silence(self, silence_id: str, silence: SilenceCreate) -> Optional[str]:
        return await update_silence(self, silence_id, silence)
