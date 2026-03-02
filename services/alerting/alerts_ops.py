"""
Alerting-related operations for interacting with Alertmanager and Mimir, including fetching metrics, listing alerts and groups, posting new alerts, and deleting alerts via silences.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from models.alerting.alerts import Alert, AlertGroup
from models.alerting.silences import Matcher, SilenceCreate
import httpx
from config import config

async def list_metric_names(service, org_id: str) -> List[str]:
    response = await service._mimir_client.get(
        f"{config.MIMIR_URL.rstrip('/')}/prometheus/api/v1/label/__name__/values",
        headers={"X-Scope-OrgID": org_id},
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("status") != "success":
        raise httpx.HTTPStatusError(
            "Mimir returned non-success status",
            request=response.request,
            response=response,
        )
    metrics = payload.get("data") or []
    return metrics if isinstance(metrics, list) else []


async def get_alerts(
    service,
    filter_labels: Optional[Dict[str, str]] = None,
    active: Optional[bool] = None,
    silenced: Optional[bool] = None,
    inhibited: Optional[bool] = None,
) -> List[Alert]:
    params: Dict = {}

    if filter_labels:
        params["filter"] = [f'{k}="{v}"' for k, v in filter_labels.items()]
    if active is not None:
        params["active"] = str(active).lower()
    if silenced is not None:
        params["silenced"] = str(silenced).lower()
    if inhibited is not None:
        params["inhibited"] = str(inhibited).lower()

    try:
        response = await service._client.get(
            f"{service.alertmanager_url}/api/v2/alerts",
            params=params,
        )
        response.raise_for_status()
        return [Alert(**alert) for alert in response.json()]
    except httpx.HTTPError as exc:
        service.logger.error("Error fetching alerts: %s", exc)
        return []


async def get_alert_groups(service, filter_labels: Optional[Dict[str, str]] = None) -> List[AlertGroup]:
    params = {}
    if filter_labels:
        params["filter"] = [f'{k}="{v}"' for k, v in filter_labels.items()]

    try:
        response = await service._client.get(
            f"{service.alertmanager_url}/api/v2/alerts/groups",
            params=params,
        )
        response.raise_for_status()
        return [AlertGroup(**group) for group in response.json()]
    except httpx.HTTPError as exc:
        service.logger.error("Error fetching alert groups: %s", exc)
        return []

async def post_alerts(service, alerts: List[Alert]) -> bool:
    try:
        response = await service._client.post(
            f"{service.alertmanager_url}/api/v2/alerts",
            json=[alert.model_dump(by_alias=True) for alert in alerts],
        )
        response.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        service.logger.error("Error posting alerts: %s", exc)
        return False


async def delete_alerts(service, filter_labels: Optional[Dict[str, str]] = None) -> bool:
    if not filter_labels:
        service.logger.warning("Cannot delete all alerts without filter")
        return False

    matchers = [
        Matcher(name=key, value=value, isRegex=False, isEqual=True)
        for key, value in filter_labels.items()
    ]

    now = datetime.now(timezone.utc)
    end = now + timedelta(seconds=60)
    silence = SilenceCreate(
        matchers=matchers,
        startsAt=now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        endsAt=end.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        createdBy="beobservant",
        comment="Alert deletion via API",
    )

    silence_id = await service.create_silence(silence)
    return silence_id is not None
