from typing import List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool

from middleware.dependencies import require_any_permission_with_scope, require_permission_with_scope
from middleware.error_handlers import handle_route_errors
from models.access.auth_models import Permission, TokenData
from models.alerting.alerts import Alert, AlertGroup
from custom_types.json import JSONDict

from .shared import INVALID_FILTER_LABELS_JSON, alertmanager_service, storage_service, sync_incidents

router = APIRouter()


def _json_dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


@router.get("/alerts", response_model=List[Alert])
@handle_route_errors(bad_request_detail=INVALID_FILTER_LABELS_JSON)
async def get_alerts(
    active: Optional[bool] = Query(None),
    silenced: Optional[bool] = Query(None),
    inhibited: Optional[bool] = Query(None),
    filter_labels: Optional[str] = Query(None),
    show_hidden: bool = Query(False),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_ALERTS, "alertmanager")),
) -> List[Alert]:
    labels = alertmanager_service.parse_filter_labels(filter_labels)
    alerts = await alertmanager_service.get_alerts(filter_labels=labels, active=active, silenced=silenced, inhibited=inhibited)
    alert_dicts = [alert.model_dump(by_alias=True) for alert in alerts]
    await sync_incidents(current_user.tenant_id, alert_dicts, log_context="get_alerts")

    filtered = await run_in_threadpool(
        storage_service.filter_alerts_for_user,
        current_user.tenant_id,
        current_user.user_id,
        getattr(current_user, "group_ids", []) or [],
        alert_dicts,
    )
    if not show_hidden:
        hidden_rule_names = set(
            await run_in_threadpool(
                storage_service.get_hidden_rule_names,
                current_user.tenant_id,
                current_user.user_id,
            )
        )
        if hidden_rule_names:
            filtered = [
                alert
                for alert in filtered
                if str(_json_dict(alert).get("labels") and _json_dict(_json_dict(alert).get("labels")).get("alertname") or "") not in hidden_rule_names
            ]
    return [Alert.model_validate(_json_dict(item)) for item in filtered]


@router.get("/alerts/groups", response_model=List[AlertGroup])
@handle_route_errors(bad_request_detail=INVALID_FILTER_LABELS_JSON)
async def get_alert_groups(
    filter_labels: Optional[str] = Query(None),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_ALERTS, "alertmanager")),
) -> List[AlertGroup]:
    return await alertmanager_service.get_alert_groups(filter_labels=alertmanager_service.parse_filter_labels(filter_labels))


@router.post("/alerts")
async def post_alerts(
    alerts: List[Alert] = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.CREATE_ALERTS, Permission.WRITE_ALERTS], "alertmanager")
    ),
) -> JSONDict:
    if not await alertmanager_service.post_alerts(alerts):
        raise HTTPException(status_code=500, detail="Failed to post alerts")
    return {"status": "success", "count": len(alerts)}


@router.delete("/alerts")
@handle_route_errors(bad_request_detail=INVALID_FILTER_LABELS_JSON)
async def delete_alerts(
    filter_labels: str = Query(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.DELETE_ALERTS, "alertmanager")),
) -> JSONDict:
    labels = alertmanager_service.parse_filter_labels(filter_labels)
    if not labels:
        raise HTTPException(status_code=400, detail="filter_labels cannot be empty")
    if not await alertmanager_service.delete_alerts(filter_labels=labels):
        raise HTTPException(status_code=500, detail="Failed to delete alerts")
    return {"status": "success", "message": "Alerts silenced"}
