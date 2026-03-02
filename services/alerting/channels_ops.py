"""
Channel operations for alerting, including processing incoming alerts from Alertmanager, determining notification channels, and sending notifications based on alert status and configuration.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from datetime import datetime, timezone
from models.alerting.alerts import Alert, AlertState, AlertStatus
import logging

logger = logging.getLogger(__name__)

async def notify_for_alerts(service, alerts_list, storage_service, notification_service) -> None:
    for incoming_alert in alerts_list:
        alertname = incoming_alert.get("labels", {}).get("alertname")
        if not alertname:
            logger.debug("Alert without alertname label, skipping")
            continue

        channels = storage_service.get_notification_channels_for_rule_name(alertname)
        if not channels:
            logger.info("No notification channels configured for rule %s", alertname)
            continue

        raw_status = incoming_alert.get("status") or {}
        silenced: list[str] = []
        inhibited: list[str] = []
        if isinstance(raw_status, dict):
            state_value = raw_status.get("state")
            silenced = raw_status.get("silencedBy") or []
            inhibited = raw_status.get("inhibitedBy") or []
        else:
            state_value = raw_status if isinstance(raw_status, str) else None

        is_active = state_value and str(state_value).lower() in {"active", "firing"}
        state_enum = AlertState.ACTIVE if is_active else AlertState.UNPROCESSED
        status_obj = AlertStatus(state=state_enum, silencedBy=silenced, inhibitedBy=inhibited)

        alert_model = Alert(
            labels=incoming_alert.get("labels", {}),
            annotations=incoming_alert.get("annotations", {}),
            startsAt=incoming_alert.get("startsAt") or incoming_alert.get("starts_at") or datetime.now(timezone.utc).isoformat(),
            endsAt=incoming_alert.get("endsAt") or incoming_alert.get("ends_at"),
            generatorURL=incoming_alert.get("generatorURL"),
            status=status_obj,
            fingerprint=incoming_alert.get("fingerprint") or incoming_alert.get("fingerPrint"),
        )

        action = "firing" if is_active else "resolved"
        for channel in channels:
            try:
                sent = await notification_service.send_notification(channel, alert_model, action)
                logger.info("Sent notification to channel %s ok=%s", channel.name, sent)
            except Exception as exc:
                logger.exception(
                    "Failed to send notification for rule %s to channel %s: %s",
                    alertname,
                    getattr(channel, "name", "unknown"),
                    exc,
                )

async def get_status(service):
    try:
        response = await service._client.get(f"{service.alertmanager_url}/api/v2/status")
        response.raise_for_status()
        return service.status_model(**response.json())
    except Exception as exc:
        logger.error("Error fetching status: %s", exc)
        return None


async def get_receivers(service):
    status = await get_status(service)
    if status and status.config:
        return [r.get("name") for r in status.config.get("receivers", []) if r.get("name")]
    return []
