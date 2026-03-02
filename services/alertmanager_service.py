"""
Service for managing interactions with AlertManager, providing functions to retrieve and manage alerts, silences, and notification channels.

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
from models.alerting.receivers import AlertManagerStatus
from models.alerting.rules import AlertRule
from models.alerting.silences import Silence, SilenceCreate
from services.alerting.alerts_ops import (
    delete_alerts as delete_alerts_ops,
    get_alert_groups as get_alert_groups_ops,
    get_alerts as get_alerts_ops,
    list_metric_names as list_metric_names_ops,
    post_alerts as post_alerts_ops,
)
from services.alerting.channels_ops import (
    get_receivers as get_receivers_ops,
    get_status as get_status_ops,
    notify_for_alerts as notify_for_alerts_ops,
)
from services.alerting.ruler_yaml import (
    build_ruler_group_yaml,
    extract_mimir_group_names,
    group_enabled_rules,
    yaml_quote,
)
from services.alerting.rules_ops import (
    resolve_rule_org_id as resolve_rule_org_id_ops,
    sync_mimir_rules_for_org as sync_mimir_rules_for_org_ops,
)
from services.alerting.silence_metadata import (
    decode_silence_comment as decode_silence_comment_ops,
    encode_silence_comment as encode_silence_comment_ops,
    normalize_visibility as normalize_visibility_ops,
)
from services.alerting.silences_ops import (
    apply_silence_metadata as apply_silence_metadata_ops,
    create_silence as create_silence_ops,
    delete_silence as delete_silence_ops,
    get_silence as get_silence_ops,
    get_silences as get_silences_ops,
    silence_accessible as silence_accessible_ops,
    update_silence as update_silence_ops,
)
from services.common.http_client import create_async_client

logger = logging.getLogger(__name__)

LABELS_JSON_ERROR = "Invalid filter_labels JSON"
MIMIR_RULES_NAMESPACE = "beobservant"
MIMIR_RULER_CONFIG_BASEPATH = "/prometheus/config/v1/rules"

class AlertManagerService:
    def __init__(self, alertmanager_url: str = config.ALERTMANAGER_URL):
        self.MIMIR_RULES_NAMESPACE = MIMIR_RULES_NAMESPACE
        self.MIMIR_RULER_CONFIG_BASEPATH = MIMIR_RULER_CONFIG_BASEPATH
        self.alertmanager_url = alertmanager_url.rstrip("/")
        self.timeout = config.DEFAULT_TIMEOUT
        self._client = create_async_client(self.timeout)
        self._mimir_client = create_async_client(self.timeout)

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

    def normalize_visibility(self, value: Optional[str]) -> str:
        return normalize_visibility_ops(value)

    def encode_silence_comment(self, comment: str, visibility: str, shared_group_ids: List[str]) -> str:
        return encode_silence_comment_ops(comment, visibility, shared_group_ids)

    def decode_silence_comment(self, comment: Optional[str]) -> Dict[str, object]:
        return decode_silence_comment_ops(comment)

    def apply_silence_metadata(self, silence: Silence) -> Silence:
        return apply_silence_metadata_ops(self, silence)

    def silence_accessible(self, silence: Silence, current_user: TokenData) -> bool:
        return silence_accessible_ops(silence, current_user)

    def resolve_rule_org_id(self, rule_org_id: Optional[str], current_user: TokenData) -> str:
        return resolve_rule_org_id_ops(rule_org_id, current_user)

    def _yaml_quote(self, value: object) -> str:
        return yaml_quote(value)

    def _group_enabled_rules(self, rules: List[AlertRule]) -> Dict[str, List[AlertRule]]:
        return group_enabled_rules(rules)

    def _build_ruler_group_yaml(self, group_name: str, rules: List[AlertRule]) -> str:
        return build_ruler_group_yaml(group_name, rules)

    def _extract_mimir_group_names(self, namespace_yaml: str) -> List[str]:
        return extract_mimir_group_names(namespace_yaml)

    async def notify_for_alerts(self, alerts_list, storage_service, notification_service) -> None:
        return await notify_for_alerts_ops(self, alerts_list, storage_service, notification_service)

    async def list_metric_names(self, org_id: str) -> List[str]:
        return await list_metric_names_ops(self, org_id)

    async def sync_mimir_rules_for_org(self, org_id: str, rules: List[AlertRule]) -> None:
        return await sync_mimir_rules_for_org_ops(self, org_id, rules)

    @with_retry()
    @with_timeout()
    async def get_alerts(
        self,
        filter_labels: Optional[Dict[str, str]] = None,
        active: Optional[bool] = None,
        silenced: Optional[bool] = None,
        inhibited: Optional[bool] = None,
    ) -> List[Alert]:
        return await get_alerts_ops(self, filter_labels, active, silenced, inhibited)

    async def get_alert_groups(self, filter_labels: Optional[Dict[str, str]] = None) -> List[AlertGroup]:
        return await get_alert_groups_ops(self, filter_labels)

    async def post_alerts(self, alerts: List[Alert]) -> bool:
        return await post_alerts_ops(self, alerts)

    async def delete_alerts(self, filter_labels: Optional[Dict[str, str]] = None) -> bool:
        return await delete_alerts_ops(self, filter_labels)

    async def get_silences(self, filter_labels: Optional[Dict[str, str]] = None) -> List[Silence]:
        return await get_silences_ops(self, filter_labels)

    async def get_silence(self, silence_id: str) -> Optional[Silence]:
        return await get_silence_ops(self, silence_id)

    async def create_silence(self, silence: SilenceCreate) -> Optional[str]:
        return await create_silence_ops(self, silence)

    async def update_silence(self, silence_id: str, silence: SilenceCreate) -> Optional[str]:
        return await update_silence_ops(self, silence_id, silence)

    async def delete_silence(self, silence_id: str) -> bool:
        if not await delete_silence_ops(self, silence_id):
            return False
        try:
            with get_db_session() as db:
                if not db.query(PurgedSilence).filter_by(id=silence_id).first():
                    db.add(PurgedSilence(id=silence_id, tenant_id=None))
                    db.commit()
                    logger.info("Purged silence %s persisted to DB", silence_id)
        except Exception as exc:
            logger.warning("Failed to persist purged silence %s: %s", silence_id, exc)
        return True

    async def get_status(self) -> Optional[AlertManagerStatus]:
        return await get_status_ops(self)

    async def get_receivers(self) -> List[str]:
        return await get_receivers_ops(self)