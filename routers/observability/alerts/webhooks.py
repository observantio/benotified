import logging

from fastapi import APIRouter, Body, Request

from config import constants
from custom_types.json import JSONDict
from middleware.error_handlers import handle_route_errors
from models.alerting.requests import AlertWebhookRequest
from services.alerting.integration_security_service import infer_tenant_id_from_alerts

from .shared import alertmanager_service, notification_service, scope_header, storage_service, sync_incidents

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/alerts/webhook")
@handle_route_errors()
async def alert_webhook(request: Request, payload: AlertWebhookRequest = Body(...)) -> JSONDict:
    alertmanager_service.enforce_webhook_security(request, scope="alertmanager_webhook")
    logger.info("Received webhook payload with %d alerts", len(payload.alerts))
    tenant_id = infer_tenant_id_from_alerts(scope_header(request), payload.alerts)
    await sync_incidents(tenant_id, payload.alerts, log_context="webhook")
    await alertmanager_service.notify_for_alerts(tenant_id, payload.alerts, storage_service, notification_service)
    return {"status": constants.STATUS_SUCCESS, "count": len(payload.alerts)}


@router.post("/alerts/critical")
@handle_route_errors()
async def alert_critical(request: Request, payload: AlertWebhookRequest = Body(...)) -> JSONDict:
    alertmanager_service.enforce_webhook_security(request, scope="alertmanager_critical")
    logger.warning("Received %d critical alerts", len(payload.alerts))
    tenant_id = infer_tenant_id_from_alerts(scope_header(request), payload.alerts)
    await sync_incidents(tenant_id, payload.alerts, log_context="critical webhook")
    await alertmanager_service.notify_for_alerts(tenant_id, payload.alerts, storage_service, notification_service)
    return {"status": constants.STATUS_SUCCESS, "severity": "critical", "count": len(payload.alerts)}


@router.post("/alerts/warning")
@handle_route_errors()
async def alert_warning(request: Request, payload: AlertWebhookRequest = Body(...)) -> JSONDict:
    alertmanager_service.enforce_webhook_security(request, scope="alertmanager_warning")
    logger.info("Received warning alerts payload with %d alerts", len(payload.alerts))
    tenant_id = infer_tenant_id_from_alerts(scope_header(request), payload.alerts)
    await sync_incidents(tenant_id, payload.alerts, log_context="warning webhook")
    await alertmanager_service.notify_for_alerts(tenant_id, payload.alerts, storage_service, notification_service)
    return {"status": constants.STATUS_SUCCESS, "severity": "warning", "count": len(payload.alerts)}
