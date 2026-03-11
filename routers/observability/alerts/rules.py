import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.concurrency import run_in_threadpool

from config import config
from custom_types.json import JSONDict
from database import get_db_session
from db_models import Tenant
from middleware.dependencies import (
    enforce_public_endpoint_security,
    require_any_permission_with_scope,
    require_permission_with_scope,
)
from middleware.error_handlers import handle_route_errors
from models.access.auth_models import Permission, TokenData
from models.alerting.alerts import Alert
from models.alerting.requests import RuleImportRequest
from models.alerting.rules import AlertRule, AlertRuleCreate
from services.alerting.rule_import_service import RuleImportError, parse_rules_yaml

from .shared import HideTogglePayload, alertmanager_service, notification_service, storage_service

logger = logging.getLogger(__name__)

router = APIRouter()


def _with_creator_username(rule: AlertRuleCreate, current_user: TokenData) -> AlertRuleCreate:
    annotations = dict(rule.annotations or {})
    creator_username = str(getattr(current_user, "username", "") or getattr(current_user, "user_id", "") or "").strip()
    if creator_username:
        annotations["beobservantCreatedByUsername"] = creator_username
    return rule.model_copy(update={"annotations": annotations})


@router.post("/rules/import")
@handle_route_errors()
async def import_alert_rules(
    payload: RuleImportRequest = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.CREATE_RULES, Permission.WRITE_ALERTS], "alertmanager")
    ),
) -> JSONDict:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    try:
        parsed_rules = parse_rules_yaml(payload.yamlContent or "", payload.defaults)
    except RuleImportError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if payload.dryRun:
        return {"status": "preview", "count": len(parsed_rules), "rules": [item.model_dump(by_alias=True) for item in parsed_rules]}

    existing_rules = await run_in_threadpool(storage_service.get_alert_rules, tenant_id, user_id, group_ids)
    existing_index = {(item.name, item.group, item.org_id or ""): item for item in existing_rules}
    created = updated = 0
    imported_rules: List[AlertRule] = []

    for rule in parsed_rules:
        rule = _with_creator_username(rule, current_user)
        key = (rule.name, rule.group, rule.org_id or "")
        current = existing_index.get(key)
        if current:
            current_id = current.id
            if current_id is None:
                continue
            updated_rule = await run_in_threadpool(storage_service.update_alert_rule, current_id, rule, tenant_id, user_id, group_ids)
            if updated_rule:
                updated += 1
                imported_rules.append(updated_rule)
        else:
            new_rule = await run_in_threadpool(storage_service.create_alert_rule, rule, tenant_id, user_id, group_ids)
            created += 1
            imported_rules.append(new_rule)
            existing_index[(new_rule.name, new_rule.group, new_rule.org_id or "")] = new_rule

    for org_id in {str(item.org_id) for item in imported_rules if item.org_id}:
        await alertmanager_service.sync_mimir_rules_for_org(
            org_id, await run_in_threadpool(storage_service.get_alert_rules_for_org, tenant_id, org_id)
        )

    return {
        "status": "success",
        "count": len(imported_rules),
        "created": created,
        "updated": updated,
        "rules": [item.model_dump(by_alias=True) for item in imported_rules],
    }


@router.get("/rules", response_model=List[AlertRule])
async def get_alert_rules(
    limit: int = Query(config.DEFAULT_QUERY_LIMIT, ge=1, le=config.MAX_QUERY_LIMIT),
    offset: int = Query(0, ge=0),
    show_hidden: bool = Query(False),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_RULES, "alertmanager")),
) -> List[AlertRule]:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    hidden_ids = set(
        await run_in_threadpool(
            storage_service.get_hidden_rule_ids,
            tenant_id,
            user_id,
        )
    )
    rules_with_owner = await run_in_threadpool(storage_service.get_alert_rules_with_owner, tenant_id, user_id, group_ids, limit, offset)
    result: List[AlertRule] = []
    for rule, owner in rules_with_owner:
        rule.is_hidden = bool(rule.id and rule.id in hidden_ids)
        if rule.is_hidden and not show_hidden:
            continue
        if owner != current_user.user_id and not getattr(current_user, "is_superuser", False):
            rule.org_id = None
        result.append(rule)
    return result


@router.get("/public/rules", response_model=List[AlertRule])
async def get_public_alert_rules(request: Request) -> List[AlertRule]:
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
) -> JSONDict:
    tenant_org_id = org_id or getattr(current_user, "org_id", None)
    if not tenant_org_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No org_id available to query metrics. Set a product / API key first.")
    return {"orgId": tenant_org_id, "metrics": await alertmanager_service.list_metric_names(tenant_org_id)}


@router.get("/rules/{rule_id}", response_model=AlertRule)
async def get_alert_rule(
    rule_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_RULES, "alertmanager")),
) -> AlertRule:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    rule = await run_in_threadpool(storage_service.get_alert_rule, rule_id, tenant_id, user_id, group_ids)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found")
    hidden_ids = set(
        await run_in_threadpool(
            storage_service.get_hidden_rule_ids,
            tenant_id,
            user_id,
        )
    )
    rule.is_hidden = bool(rule.id and rule.id in hidden_ids)
    raw = await run_in_threadpool(storage_service.get_alert_rule_raw, rule_id, tenant_id)
    if raw and raw.created_by != current_user.user_id and not getattr(current_user, "is_superuser", False):
        rule.org_id = None
    return rule


@router.post("/rules/{rule_id}/hide")
@handle_route_errors()
async def hide_alert_rule(
    rule_id: str,
    payload: HideTogglePayload = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_RULES, "alertmanager")),
) -> JSONDict:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    rule = await run_in_threadpool(storage_service.get_alert_rule, rule_id, tenant_id, user_id, group_ids)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found")

    raw = await run_in_threadpool(storage_service.get_alert_rule_raw, rule_id, tenant_id)
    if raw and str(getattr(raw, "created_by", "") or "") == user_id:
        raise HTTPException(status_code=403, detail="You cannot hide your own alert rule")

    ok = await run_in_threadpool(storage_service.toggle_rule_hidden, tenant_id, user_id, rule_id, bool(payload.hidden))
    if not ok:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found")
    return {"status": "success", "hidden": bool(payload.hidden)}


@router.post("/rules", response_model=AlertRule, status_code=status.HTTP_201_CREATED)
async def create_alert_rule(
    rule: AlertRuleCreate = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.CREATE_RULES, Permission.WRITE_ALERTS], "alertmanager")
    ),
) -> AlertRule:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    rule = _with_creator_username(rule, current_user)
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
) -> AlertRule:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    rule = _with_creator_username(rule, current_user)
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
) -> JSONDict:
    tenant_id, user_id, group_ids = alertmanager_service.user_scope(current_user)
    rule = await run_in_threadpool(storage_service.get_alert_rule, rule_id, tenant_id, user_id, group_ids)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Alert rule {rule_id} not found")

    channels = await run_in_threadpool(
        storage_service.get_notification_channels_for_rule_name,
        tenant_id,
        rule.name,
        rule.org_id,
    )
    if not channels:
        raise HTTPException(status_code=400, detail="No notification channels configured for this rule")

    alert = Alert.model_validate(
        {
            "labels": {"alertname": rule.name, "severity": rule.severity, **(rule.labels or {})},
            "annotations": {
                "summary": rule.annotations.get("summary", f"Test alert for {rule.name}"),
                "description": rule.annotations.get("description", rule.expr),
                "beobservantCorrelationId": str(getattr(rule, "group", "") or ""),
                "beobservantCreatedBy": str(getattr(rule, "created_by", "") or ""),
                "beobservantCreatedByUsername": str(
                    (rule.annotations or {}).get("beobservantCreatedByUsername")
                    or getattr(current_user, "username", "")
                    or getattr(rule, "created_by", "")
                    or ""
                ),
                "beobservantRuleName": str(getattr(rule, "name", "") or ""),
                "beobservantProductName": str(
                    rule.annotations.get("beobservantProductName")
                    or rule.annotations.get("productName")
                    or rule.annotations.get("product_name")
                    or (rule.labels or {}).get("product")
                    or ""
                ),
                **(rule.annotations or {}),
            },
            "startsAt": datetime.now(timezone.utc).isoformat(),
            "endsAt": None,
            "generatorURL": None,
            "status": {"state": "active", "silencedBy": [], "inhibitedBy": []},
            "fingerprint": f"test-{rule.id}",
        }
    )

    results: list[JSONDict] = []
    success_count = 0
    for channel in channels:
        ok = await notification_service.send_notification(channel, alert, "test")
        results.append({"channel": channel.name, "ok": ok})
        if ok:
            success_count += 1

    return {
        "status": "success" if success_count else "failed",
        "message": f"Test alert sent to {success_count}/{len(channels)} channels",
        "results": results,
    }


@router.delete("/rules/{rule_id}")
async def delete_alert_rule(
    rule_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.DELETE_RULES, "alertmanager")),
) -> JSONDict:
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
