"""
Channel operations for alerting, including processing incoming alerts from Alertmanager, determining notification channels, and sending notifications based on alert status and configuration.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import logging

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import httpx

from custom_types.json import JSONDict
from models.alerting.alerts import Alert, AlertState, AlertStatus
from models.alerting.receivers import AlertManagerStatus
from services.notification_service import NotificationService
from services.storage_db_service import DatabaseStorageService
from services.alerting.suppression import is_suppressed_status

if TYPE_CHECKING:
    from services.alertmanager_service import AlertManagerService

logger = logging.getLogger(__name__)


def _is_suppressed(raw_status: object) -> bool:
    return is_suppressed_status(raw_status)


def _string_dict(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items() if item is not None}


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _optional_string(value: object) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


async def notify_for_alerts(
    service: AlertManagerService,
    tenant_id: str,
    alerts_list: list[JSONDict],
    storage_service: DatabaseStorageService,
    notification_service: NotificationService,
) -> None:
    for incoming_alert in alerts_list:
        labels = _string_dict(incoming_alert.get("labels") or {})
        alertname = labels.get("alertname")
        if not alertname:
            logger.debug("Alert without alertname label, skipping")
            continue

        org_id = (
            labels.get("org_id")
            or labels.get("orgId")
            or labels.get("tenant")
            or labels.get("product")
        )
        channels = storage_service.get_notification_channels_for_rule_name(
            tenant_id,
            alertname,
            org_id=org_id,
        )
        matched_rule = storage_service.get_alert_rule_by_name_for_delivery(
            tenant_id,
            alertname,
            org_id=org_id,
        )
        if not channels:
            logger.info(
                "No deliverable notification channels for rule=%s org=%s rule_id=%s visibility=%s configured_channel_ids=%s",
                alertname,
                org_id or "",
                getattr(matched_rule, "id", None) if matched_rule else None,
                getattr(matched_rule, "visibility", None) if matched_rule else None,
                getattr(matched_rule, "notification_channels", None) if matched_rule else None,
            )
            continue

        raw_status = incoming_alert.get("status") or {}
        if _is_suppressed(raw_status):
            logger.info("Skipping notification for suppressed alert=%s tenant=%s", alertname, tenant_id)
            continue
        silenced: list[str] = []
        inhibited: list[str] = []
        if isinstance(raw_status, dict):
            state_value = raw_status.get("state")
            silenced = _string_list(raw_status.get("silencedBy"))
            inhibited = _string_list(raw_status.get("inhibitedBy"))
        else:
            state_value = raw_status if isinstance(raw_status, str) else None

        is_active = state_value and str(state_value).lower() in {"active", "firing"}
        state_enum = AlertState.ACTIVE if is_active else AlertState.UNPROCESSED
        status_obj = AlertStatus(state=state_enum, silencedBy=silenced, inhibitedBy=inhibited)

        labels = _string_dict(incoming_alert.get("labels") or {})
        annotations = _string_dict(incoming_alert.get("annotations") or {})
        if matched_rule:
            enriched_annotations = dict(annotations)
            enriched_annotations.setdefault("beobservantCorrelationId", str(getattr(matched_rule, "group", "") or ""))
            enriched_annotations.setdefault("beobservantCreatedBy", str(getattr(matched_rule, "created_by", "") or ""))
            rule_annotations = _string_dict(getattr(matched_rule, "annotations", {}) or {})
            created_by_username = (
                rule_annotations.get("beobservantCreatedByUsername")
                or rule_annotations.get("createdByUsername")
                or rule_annotations.get("created_by_username")
            )
            if created_by_username:
                enriched_annotations.setdefault("beobservantCreatedByUsername", str(created_by_username))
            enriched_annotations.setdefault("beobservantRuleName", str(getattr(matched_rule, "name", "") or ""))
            product_name = (
                rule_annotations.get("beobservantProductName")
                or rule_annotations.get("productName")
                or rule_annotations.get("product_name")
                or labels.get("product")
            )
            if product_name:
                enriched_annotations.setdefault("beobservantProductName", str(product_name))
            annotations = enriched_annotations

        alert_model = Alert(
            labels=labels,
            annotations=annotations,
            startsAt=_optional_string(incoming_alert.get("startsAt") or incoming_alert.get("starts_at")) or datetime.now(timezone.utc).isoformat(),
            endsAt=_optional_string(incoming_alert.get("endsAt") or incoming_alert.get("ends_at")),
            generatorURL=_optional_string(incoming_alert.get("generatorURL")),
            status=status_obj,
            fingerprint=_optional_string(incoming_alert.get("fingerprint") or incoming_alert.get("fingerPrint")),
        )

        action = "firing" if is_active else "resolved"
        for channel in channels:
            sent = await notification_service.send_notification(channel, alert_model, action)
            logger.info("Sent notification to channel %s ok=%s", channel.name, sent)

async def get_status(service: AlertManagerService) -> AlertManagerStatus | None:
    try:
        response = await service._client.get(f"{service.alertmanager_url}/api/v2/status")
        response.raise_for_status()
        return AlertManagerStatus.model_validate(response.json())
    except (httpx.HTTPError, TypeError, ValueError) as exc:
        logger.error("Error fetching status: %s", exc)
        return None


async def get_receivers(service: AlertManagerService) -> list[str]:
    status = await get_status(service)
    if status and status.config:
        raw_receivers = status.config.get("receivers")
        if isinstance(raw_receivers, list):
            names: list[str] = []
            for receiver in raw_receivers:
                if not isinstance(receiver, dict):
                    continue
                name = _optional_string(receiver.get("name"))
                if name:
                    names.append(name)
            return names
    return []
