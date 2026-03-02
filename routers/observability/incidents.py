"""
Incident management API endpoints for querying and updating alert incidents, including status updates, assignee changes, and integration with AlertManager for active alert checks.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.concurrency import run_in_threadpool

from middleware.dependencies import require_permission_with_scope
from middleware.error_handlers import handle_route_errors
from models.access.auth_models import Permission, TokenData
from models.alerting.incidents import AlertIncident, AlertIncidentUpdateRequest
from services.alertmanager_service import AlertManagerService
from services.storage_db_service import DatabaseStorageService
from services.notification_service import NotificationService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/alertmanager", tags=["alertmanager-incidents"])

alertmanager_service = AlertManagerService()
storage_service = DatabaseStorageService()
notification_service = NotificationService()

@router.get("/incidents", response_model=List[AlertIncident])
async def get_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    visibility_filter: Optional[str] = Query(None, alias="visibility"),
    group_id_filter: Optional[str] = Query(None, alias="group_id"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_INCIDENTS, "alertmanager")),
):
    return await run_in_threadpool(
        storage_service.list_incidents,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        group_ids=getattr(current_user, "group_ids", []) or [],
        status=status_filter,
        visibility=visibility_filter,
        group_id=group_id_filter,
        limit=limit,
        offset=offset,
    )


@router.patch("/incidents/{incident_id}", response_model=AlertIncident)
@handle_route_errors()
async def patch_incident(
    incident_id: str,
    payload: AlertIncidentUpdateRequest,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
):
    group_ids = getattr(current_user, "group_ids", []) or []
    existing = await run_in_threadpool(
        storage_service.get_incident_for_user,
        incident_id,
        current_user.tenant_id,
        current_user.user_id,
        group_ids,
    )
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if payload.status is not None:
        status_str = payload.status.value if hasattr(payload.status, "value") else str(payload.status)
        if status_str.lower() == "resolved":
            try:
                active_alerts = await alertmanager_service.get_alerts(
                    filter_labels={"fingerprint": existing.fingerprint},
                    active=True,
                )
            except Exception:
                active_alerts = []
            if active_alerts:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot mark resolved: underlying alert is still active",
                )

    updated = await run_in_threadpool(
        storage_service.update_incident,
        incident_id,
        current_user.tenant_id,
        current_user.user_id,
        payload,
    )
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if updated.assignee and updated.assignee != existing.assignee:
        try:
            await run_in_threadpool(
                storage_service.update_incident,
                incident_id,
                current_user.tenant_id,
                current_user.user_id,
                AlertIncidentUpdateRequest(note=f"Assigned to {updated.assignee} by {current_user.username or current_user.user_id}"),
            )
        except Exception:
            logger.exception("Failed to record assignment note for incident %s", incident_id)

        try:
            await notification_service.send_incident_assignment_email(
                recipient_email=updated.assignee,
                incident_title=updated.alert_name,
                incident_status=updated.status,
                incident_severity=updated.severity,
                actor=current_user.username or current_user.user_id,
            )
        except Exception:
            logger.exception("Failed to send assignment email for incident %s", incident_id)

    return updated