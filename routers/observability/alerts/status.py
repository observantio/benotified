from typing import List

from fastapi import APIRouter, Depends, HTTPException

from middleware.dependencies import require_permission_with_scope
from models.access.auth_models import Permission, TokenData
from models.alerting.receivers import AlertManagerStatus

from .shared import alertmanager_service

router = APIRouter()


@router.get("/status", response_model=AlertManagerStatus)
async def get_status(
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_ALERTS, "alertmanager")),
) -> AlertManagerStatus:
    result = await alertmanager_service.get_status()
    if not result:
        raise HTTPException(status_code=500, detail="Failed to fetch AlertManager status")
    return result


@router.get("/receivers", response_model=List[str])
async def get_receivers(
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_ALERTS, "alertmanager")),
) -> List[str]:
    return await alertmanager_service.get_receivers()
