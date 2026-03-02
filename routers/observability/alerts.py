"""
Alert management API endpoints for creating, updating, deleting, and querying alerts, silences, alert rules, notification channels, and related resources. Integrates with AlertManager and supports incident synchronization and Jira integration.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.concurrency import run_in_threadpool

from config import config, constants
from database import get_db_session
from db_models import Tenant
from middleware.dependencies import (
    enforce_public_endpoint_security,
    require_any_permission_with_scope,
    require_permission_with_scope,
)
from middleware.error_handlers import handle_route_errors
from models.access.auth_models import Permission, TokenData
from models.alerting.alerts import Alert, AlertGroup, AlertState, AlertStatus
from models.alerting.channels import NotificationChannel, NotificationChannelCreate
from models.alerting.receivers import AlertManagerStatus
from models.alerting.requests import (
    AlertWebhookRequest,
    RuleImportRequest,
)
from models.alerting.rules import AlertRule, AlertRuleCreate
from models.alerting.silences import Silence, SilenceCreate, SilenceCreateRequest, Visibility
from services.alerting.integration_security_service import (
    allowed_channel_types,
    tenant_id_from_scope_header,
)
from services.alerting.rule_import_service import RuleImportError, parse_rules_yaml
from services.alertmanager_service import AlertManagerService
from services.notification_service import NotificationService
from services.storage_db_service import DatabaseStorageService

logger = logging.getLogger(__name__)

INVALID_FILTER_LABELS_JSON = "Invalid filter_labels JSON"

router = APIRouter(prefix="/api/alertmanager", tags=["alertmanager"])
webhook_router = APIRouter(tags=["alertmanager-webhooks"])

alertmanager_service = AlertManagerService()
notification_service = NotificationService()
storage_service = DatabaseStorageService()


def _scope_header(request: Request) -> str:
    return request.headers.get("x-scope-orgid") or request.headers.get("X-Scope-OrgID") or ""


async def _sync_incidents(tenant_id: str, alerts, *, log_context: str) -> None:
    try:
        await run_in_threadpool(storage_service.sync_incidents_from_alerts, tenant_id, alerts, False)
    except Exception as exc:
        logger.warning("Incident sync skipped (%s): %s", log_context, exc)


def _build_silence_payload(silence: SilenceCreateRequest, current_user: TokenData) -> SilenceCreate:
    visibility = alertmanager_service.normalize_visibility(silence.visibility)
    shared_group_ids = silence.shared_group_ids if visibility == Visibility.GROUP.value else []
    return SilenceCreate.parse_obj(
        {
            "matchers": silence.matchers,
            "startsAt": silence.starts_at,
            "endsAt": silence.ends_at,
            "createdBy": current_user.username or current_user.user_id,
            "comment": alertmanager_service.encode_silence_comment(silence.comment, visibility, shared_group_ids),
        }
    )


def _validate_channel(channel, notification_service: NotificationService) -> str:
    requested_type = str(channel.type or "").strip().lower()
    if requested_type not in allowed_channel_types():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Channel type '{requested_type}' is disabled by organization policy",
        )
    errors = notification_service.validate_channel_config(requested_type, channel.config)
    if errors:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"errors": errors, "status": "error"})
    return requested_type


@webhook_router.post("/alerts/webhook")
@handle_route_errors()
async def alert_webhook(request: Request, payload: AlertWebhookRequest = Body(...)) -> dict:
    alertmanager_service.enforce_webhook_security(request, scope="alertmanager_webhook")
    logger.info("Received webhook payload with %d alerts", len(payload.alerts))
    tenant_id = tenant_id_from_scope_header(_scope_header(request))
    await _sync_incidents(tenant_id, payload.alerts, log_context="webhook")
    await alertmanager_service.notify_for_alerts(payload.alerts, storage_service, notification_service)
    return {"status": constants.STATUS_SUCCESS, "count": len(payload.alerts)}


@webhook_router.post("/alerts/critical")
@handle_route_errors()
async def alert_critical(request: Request, payload: AlertWebhookRequest = Body(...)) -> dict:
    alertmanager_service.enforce_webhook_security(request, scope="alertmanager_critical")
    logger.warning("Received %d critical alerts", len(payload.alerts))
    tenant_id = tenant_id_from_scope_header(_scope_header(request))
    await _sync_incidents(tenant_id, payload.alerts, log_context="critical webhook")
    await alertmanager_service.notify_for_alerts(payload.alerts, storage_service, notification_service)
    return {"status": constants.STATUS_SUCCESS, "severity": "critical", "count": len(payload.alerts)}


@webhook_router.post("/alerts/warning")
@handle_route_errors()
async def alert_warning(request: Request, payload: AlertWebhookRequest = Body(...)) -> dict:
    alertmanager_service.enforce_webhook_security(request, scope="alertmanager_warning")
    logger.info("Received warning alerts payload with %d alerts", len(payload.alerts))
    tenant_id = tenant_id_from_scope_header(_scope_header(request))
    await _sync_incidents(tenant_id, payload.alerts, log_context="warning webhook")
    await alertmanager_service.notify_for_alerts(payload.alerts, storage_service, notification_service)
    return {"status": constants.STATUS_SUCCESS, "severity": "warning", "count": len(payload.alerts)}


@router.get("/alerts", response_model=List[Alert])
@handle_route_errors(bad_request_detail=INVALID_FILTER_LABELS_JSON)
async def get_alerts(
    active: Optional[bool] = Query(None),
    silenced: Optional[bool] = Query(None),
    inhibited: Optional[bool] = Query(None),
    filter_labels: Optional[str] = Query(None),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_ALERTS, "alertmanager")),
):
    labels = alertmanager_service.parse_filter_labels(filter_labels)
    alerts = await alertmanager_service.get_alerts(filter_labels=labels, active=active, silenced=silenced, inhibited=inhibited)
    alert_dicts = [alert.model_dump(by_alias=True) for alert in alerts]
    await _sync_incidents(current_user.tenant_id, alert_dicts, log_context="get_alerts")

    filtered = await run_in_threadpool(
        storage_service.filter_alerts_for_user,
        current_user.tenant_id,
        current_user.user_id,
        getattr(current_user, "group_ids", []) or [],
        alert_dicts,
    )
    return [Alert(**d) for d in filtered]


@router.get("/alerts/groups", response_model=List[AlertGroup])
@handle_route_errors(bad_request_detail=INVALID_FILTER_LABELS_JSON)
async def get_alert_groups(
    filter_labels: Optional[str] = Query(None),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_ALERTS, "alertmanager")),
):
    return await alertmanager_service.get_alert_groups(filter_labels=alertmanager_service.parse_filter_labels(filter_labels))


@router.post("/alerts")
async def post_alerts(
    alerts: List[Alert] = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.CREATE_ALERTS, Permission.WRITE_ALERTS], "alertmanager")
    ),
):
    if not await alertmanager_service.post_alerts(alerts):
        raise HTTPException(status_code=500, detail="Failed to post alerts")
    return {"status": "success", "count": len(alerts)}


@router.delete("/alerts")
@handle_route_errors(bad_request_detail=INVALID_FILTER_LABELS_JSON)
async def delete_alerts(
    filter_labels: str = Query(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.DELETE_ALERTS, "alertmanager")),
):
    labels = alertmanager_service.parse_filter_labels(filter_labels)
    if not labels:
        raise HTTPException(status_code=400, detail="filter_labels cannot be empty")
    if not await alertmanager_service.delete_alerts(filter_labels=labels):
        raise HTTPException(status_code=500, detail="Failed to delete alerts")
    return {"status": "success", "message": "Alerts silenced"}


@router.post("/rules/import")
@handle_route_errors()
async def import_alert_rules(
    payload: RuleImportRequest = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.CREATE_RULES, Permission.WRITE_ALERTS], "alertmanager")
    ),
):
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    try:
        parsed_rules = parse_rules_yaml(payload.yamlContent, payload.defaults)
    except RuleImportError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    if payload.dryRun:
        return {"status": "preview", "count": len(parsed_rules), "rules": [r.model_dump(by_alias=True) for r in parsed_rules]}

    existing_rules = await run_in_threadpool(storage_service.get_alert_rules, tenant_id, user_id, group_ids)
    existing_index = {(r.name, r.group, r.org_id or ""): r for r in existing_rules}
    created = updated = 0
    imported_rules: List[AlertRule] = []

    for rule in parsed_rules:
        key = (rule.name, rule.group, rule.org_id or "")
        current = existing_index.get(key)
        if current:
            updated_rule = await run_in_threadpool(
                storage_service.update_alert_rule, current.id, rule, tenant_id, user_id, group_ids
            )
            if updated_rule:
                updated += 1
                imported_rules.append(updated_rule)
        else:
            new_rule = await run_in_threadpool(storage_service.create_alert_rule, rule, tenant_id, user_id, group_ids)
            created += 1
            imported_rules.append(new_rule)
            existing_index[(new_rule.name, new_rule.group, new_rule.org_id or "")] = new_rule

    for org_id in {str(r.org_id) for r in imported_rules if r.org_id}:
        await alertmanager_service.sync_mimir_rules_for_org(
            org_id, await run_in_threadpool(storage_service.get_alert_rules_for_org, tenant_id, org_id)
        )

    return {
        "status": "success",
        "count": len(imported_rules),
        "created": created,
        "updated": updated,
        "rules": [r.model_dump(by_alias=True) for r in imported_rules],
    }


@router.get("/silences", response_model=List[Silence])
@handle_route_errors(bad_request_detail=INVALID_FILTER_LABELS_JSON)
async def get_silences(
    filter_labels: Optional[str] = Query(None),
    include_expired: bool = Query(False),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_SILENCES, "alertmanager")),
):
    silences = await alertmanager_service.get_silences(filter_labels=alertmanager_service.parse_filter_labels(filter_labels))
    result = []
    for silence in silences:
        silence = alertmanager_service.apply_silence_metadata(silence)
        if not include_expired:
            state = (silence.status or {}).get("state") if silence.status else None
            if state and str(state).lower() == "expired":
                continue
        if alertmanager_service.silence_accessible(silence, current_user):
            result.append(silence)
    return result


@router.get("/silences/{silence_id}", response_model=Silence)
async def get_silence(
    silence_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_SILENCES, "alertmanager")),
):
    silence = await alertmanager_service.get_silence(silence_id)
    if not silence:
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    silence = alertmanager_service.apply_silence_metadata(silence)
    if not alertmanager_service.silence_accessible(silence, current_user):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    return silence


@router.post("/silences", response_model=Dict[str, str])
@handle_route_errors()
async def create_silence(
    silence: SilenceCreateRequest = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.CREATE_SILENCES, Permission.WRITE_ALERTS], "alertmanager")
    ),
):
    silence_id = await alertmanager_service.create_silence(_build_silence_payload(silence, current_user))
    if not silence_id:
        raise HTTPException(status_code=500, detail="Failed to create silence")
    return {"silenceID": silence_id, "status": "success"}


@router.put("/silences/{silence_id}", response_model=Dict[str, str])
@handle_route_errors()
async def update_silence(
    silence_id: str,
    silence: SilenceCreateRequest = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.UPDATE_SILENCES, Permission.WRITE_ALERTS], "alertmanager")
    ),
):
    existing = await alertmanager_service.get_silence(silence_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    existing = alertmanager_service.apply_silence_metadata(existing)
    if not alertmanager_service.silence_accessible(existing, current_user):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    new_id = await alertmanager_service.update_silence(silence_id, _build_silence_payload(silence, current_user))
    if not new_id:
        raise HTTPException(status_code=500, detail="Failed to update silence")
    return {"silenceID": new_id, "status": "success", "message": "Silence updated"}


@router.delete("/silences/{silence_id}")
async def delete_silence(
    silence_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.DELETE_SILENCES, "alertmanager")),
):
    existing = await alertmanager_service.get_silence(silence_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found or already deleted")
    existing = alertmanager_service.apply_silence_metadata(existing)
    if not alertmanager_service.silence_accessible(existing, current_user):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found or already deleted")
    if not await alertmanager_service.delete_silence(silence_id):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found or already deleted")
    return {"status": "success", "message": f"Silence {silence_id} deleted", "purged": True}


@router.get("/status", response_model=AlertManagerStatus)
async def get_status(
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_ALERTS, "alertmanager")),
):
    result = await alertmanager_service.get_status()
    if not result:
        raise HTTPException(status_code=500, detail="Failed to fetch AlertManager status")
    return result


@router.get("/receivers", response_model=List[str])
async def get_receivers(
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_ALERTS, "alertmanager")),
):
    return await alertmanager_service.get_receivers()


@router.get("/rules", response_model=List[AlertRule])
async def get_alert_rules(
    limit: int = Query(config.DEFAULT_QUERY_LIMIT, ge=1, le=config.MAX_QUERY_LIMIT),
    offset: int = Query(0, ge=0),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_RULES, "alertmanager")),
):
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    rules_with_owner = await run_in_threadpool(storage_service.get_alert_rules_with_owner, tenant_id, user_id, group_ids, limit, offset)
    result: List[AlertRule] = []
    for rule, owner in rules_with_owner:
        if owner != current_user.user_id and not getattr(current_user, "is_superuser", False):
            rule.org_id = None
        result.append(rule)
    return result


@router.get("/public/rules", response_model=List[AlertRule])
async def get_public_alert_rules(request: Request):
    enforce_public_endpoint_security(
        request,
        scope="alertmanager_public_rules",
        limit=config.RATE_LIMIT_PUBLIC_PER_MINUTE,
        window_seconds=60,
        allowlist=config.AUTH_PUBLIC_IP_ALLOWLIST,
    )

    def _resolve_default_tenant_id() -> Optional[str]:
        with get_db_session() as db:
            tenant = db.query(Tenant).filter_by(name=config.DEFAULT_ADMIN_TENANT).first()
            return tenant.id if tenant else None

    tenant_id = await run_in_threadpool(_resolve_default_tenant_id)
    if not tenant_id:
        return []
    return await run_in_threadpool(storage_service.get_public_alert_rules, tenant_id)


@router.get("/metrics/names")
@handle_route_errors(bad_gateway_detail="Failed to fetch metrics from Mimir")
async def list_metric_names(
    org_id: Optional[str] = Query(None, alias="orgId"),
    current_user: TokenData = Depends(
        require_any_permission_with_scope(
            [Permission.READ_METRICS, Permission.CREATE_RULES, Permission.UPDATE_RULES, Permission.WRITE_ALERTS],
            "alertmanager",
        )
    ),
):
    tenant_org_id = org_id or getattr(current_user, "org_id", None)
    if not tenant_org_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No org_id available to query metrics. Set a product / API key first.")
    return {"orgId": tenant_org_id, "metrics": await alertmanager_service.list_metric_names(tenant_org_id)}


@router.get("/rules/{rule_id}", response_model=AlertRule)
async def get_alert_rule(
    rule_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_RULES, "alertmanager")),
):
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    rule = await run_in_threadpool(storage_service.get_alert_rule, rule_id, tenant_id, user_id, group_ids)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found")
    raw = await run_in_threadpool(storage_service.get_alert_rule_raw, rule_id, tenant_id)
    if raw and raw.created_by != current_user.user_id and not getattr(current_user, "is_superuser", False):
        rule.org_id = None
    return rule


@router.post("/rules", response_model=AlertRule, status_code=status.HTTP_201_CREATED)
async def create_alert_rule(
    rule: AlertRuleCreate = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.CREATE_RULES, Permission.WRITE_ALERTS], "alertmanager")
    ),
):
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    resolved_org_id = alertmanager_service.resolve_rule_org_id(rule.org_id, current_user)
    if rule.org_id != resolved_org_id:
        rule = rule.model_copy(update={"org_id": resolved_org_id})
    created_rule = await run_in_threadpool(storage_service.create_alert_rule, rule, tenant_id, user_id, group_ids)
    org_to_sync = created_rule.org_id or resolved_org_id
    await alertmanager_service.sync_mimir_rules_for_org(
        org_to_sync, await run_in_threadpool(storage_service.get_alert_rules_for_org, tenant_id, org_to_sync)
    )
    return created_rule


@router.put("/rules/{rule_id}", response_model=AlertRule)
async def update_alert_rule(
    rule_id: str,
    rule: AlertRuleCreate = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.UPDATE_RULES, Permission.WRITE_ALERTS], "alertmanager")
    ),
):
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    existing_rule = await run_in_threadpool(storage_service.get_alert_rule, rule_id, tenant_id, user_id, group_ids)
    if not existing_rule:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found or access denied")
    resolved_org_id = alertmanager_service.resolve_rule_org_id(rule.org_id, current_user)
    if rule.org_id != resolved_org_id:
        rule = rule.model_copy(update={"org_id": resolved_org_id})
    updated_rule = await run_in_threadpool(storage_service.update_alert_rule, rule_id, rule, tenant_id, user_id, group_ids)
    if not updated_rule:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found or access denied")
    updated_org_id = updated_rule.org_id or resolved_org_id
    await alertmanager_service.sync_mimir_rules_for_org(
        updated_org_id, await run_in_threadpool(storage_service.get_alert_rules_for_org, tenant_id, updated_org_id)
    )
    if existing_rule.org_id and existing_rule.org_id != updated_rule.org_id:
        await alertmanager_service.sync_mimir_rules_for_org(
            existing_rule.org_id,
            await run_in_threadpool(storage_service.get_alert_rules_for_org, tenant_id, existing_rule.org_id),
        )
    return updated_rule


@router.post("/rules/{rule_id}/test")
async def test_alert_rule(
    rule_id: str,
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.TEST_RULES, Permission.WRITE_ALERTS], "alertmanager")
    ),
):
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    rule = await run_in_threadpool(storage_service.get_alert_rule, rule_id, tenant_id, user_id, group_ids)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found")

    channels = await run_in_threadpool(storage_service.get_notification_channels, tenant_id, user_id, group_ids)
    if rule.notification_channels:
        channels = [c for c in channels if c.id in rule.notification_channels]
    if not channels:
        raise HTTPException(status_code=400, detail="No notification channels configured for this rule")

    alert = Alert(
        labels={"alertname": rule.name, "severity": rule.severity, **(rule.labels or {})},
        annotations={
            "summary": rule.annotations.get("summary", f"Test alert for {rule.name}"),
            "description": rule.annotations.get("description", rule.expr),
            **(rule.annotations or {}),
        },
        startsAt=datetime.now(timezone.utc).isoformat(),
        status=AlertStatus(state=AlertState.ACTIVE, silencedBy=[], inhibitedBy=[]),
        fingerprint=f"test-{rule.id}",
    )

    results = []
    success_count = 0
    for channel in channels:
        try:
            ok = await notification_service.send_notification(channel, alert, "firing")
            results.append({"channel": channel.name, "ok": ok})
            if ok:
                success_count += 1
        except Exception as exc:
            logger.warning("Test notification failed for channel %s on rule %s: %s", channel.name, rule_id, exc)
            results.append({"channel": channel.name, "ok": False, "error": "delivery_error"})

    return {
        "status": "success" if success_count else "failed",
        "message": f"Test alert sent to {success_count}/{len(channels)} channels",
        "results": results,
    }


@router.delete("/rules/{rule_id}")
@handle_route_errors()
async def delete_alert_rule(
    rule_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.DELETE_RULES, "alertmanager")),
):
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    existing_rule = await run_in_threadpool(storage_service.get_alert_rule, rule_id, tenant_id, user_id, group_ids)
    if not existing_rule:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found or access denied")
    if not await run_in_threadpool(storage_service.delete_alert_rule, rule_id, tenant_id, user_id, group_ids):
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found or access denied")
    resolved_org_id = alertmanager_service.resolve_rule_org_id(existing_rule.org_id, current_user)
    await alertmanager_service.sync_mimir_rules_for_org(
        resolved_org_id, await run_in_threadpool(storage_service.get_alert_rules_for_org, tenant_id, resolved_org_id)
    )
    return {"status": "success", "message": f"Alert rule {rule_id} deleted"}



@router.get("/channels", response_model=List[NotificationChannel])
async def get_notification_channels(
    limit: int = Query(config.DEFAULT_QUERY_LIMIT, ge=1, le=config.MAX_QUERY_LIMIT),
    offset: int = Query(0, ge=0),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_CHANNELS, "alertmanager")),
):
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    return await run_in_threadpool(storage_service.get_notification_channels, tenant_id, user_id, group_ids, limit, offset)


@router.get("/channels/{channel_id}", response_model=NotificationChannel)
async def get_notification_channel(
    channel_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_CHANNELS, "alertmanager")),
):
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    channel = await run_in_threadpool(storage_service.get_notification_channel, channel_id, tenant_id, user_id, group_ids)
    if not channel:
        raise HTTPException(status_code=404, detail=f"Notification channel {channel_id} not found")
    return channel


@router.post("/channels", response_model=NotificationChannel, status_code=status.HTTP_201_CREATED)
async def create_notification_channel(
    channel: NotificationChannelCreate = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.CREATE_CHANNELS, Permission.WRITE_CHANNELS], "alertmanager")
    ),
):
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    _validate_channel(channel, notification_service)
    return await run_in_threadpool(storage_service.create_notification_channel, channel, tenant_id, user_id, group_ids)


@router.put("/channels/{channel_id}", response_model=NotificationChannel)
async def update_notification_channel(
    channel_id: str,
    channel: NotificationChannelCreate = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.UPDATE_CHANNELS, Permission.WRITE_ALERTS], "alertmanager")
    ),
):
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    _validate_channel(channel, notification_service)
    updated_channel = await run_in_threadpool(storage_service.update_notification_channel, channel_id, channel, tenant_id, user_id, group_ids)
    if not updated_channel:
        raise HTTPException(status_code=404, detail=f"Notification channel {channel_id} not found or access denied")
    return updated_channel


@router.delete("/channels/{channel_id}")
@handle_route_errors()
async def delete_notification_channel(
    channel_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.DELETE_CHANNELS, "alertmanager")),
):
    tenant_id, user_id, _ = alertmanager_service.user_scope(current_user)
    if not await run_in_threadpool(storage_service.delete_notification_channel, channel_id, tenant_id, user_id):
        raise HTTPException(status_code=404, detail=f"Notification channel {channel_id} not found or access denied")
    return {"status": "success", "message": f"Notification channel {channel_id} deleted"}


@router.post("/channels/{channel_id}/test")
@handle_route_errors(internal_detail="Failed to send test notification")
async def test_notification_channel(
    channel_id: str,
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.TEST_CHANNELS, Permission.WRITE_CHANNELS], "alertmanager")
    ),
):
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    if not await run_in_threadpool(storage_service.is_notification_channel_owner, channel_id, tenant_id, user_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only channel owner can test this channel")

    channel = await run_in_threadpool(storage_service.get_notification_channel, channel_id, tenant_id, user_id, group_ids)
    if not channel:
        raise HTTPException(status_code=404, detail=f"Notification channel {channel_id} not found")

    test_alert = Alert(
        labels={"alertname": "InvokableTestAlert", "severity": "INFO"},
        annotations={
            "summary": "You have invoked a test alert",
            "description": "This is a test notification from BeObservant. Please ignore this alert if you didn't expect it.",
        },
        startsAt=datetime.now(timezone.utc).isoformat(),
        status={"state": "active", "silencedBy": [], "inhibitedBy": []},
        fingerprint="test",
    )

    if await notification_service.send_notification(channel, test_alert, "firing"):
        return {"status": "success", "message": f"Test notification sent to {channel.name}"}
    raise HTTPException(status_code=500, detail="Failed to send test notification")