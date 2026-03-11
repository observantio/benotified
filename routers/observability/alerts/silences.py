from typing import Dict, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool

from custom_types.json import JSONDict
from middleware.dependencies import require_any_permission_with_scope, require_permission_with_scope
from middleware.error_handlers import handle_route_errors
from models.access.auth_models import Permission, TokenData
from models.alerting.silences import Silence, SilenceCreateRequest

from .shared import (
    INVALID_FILTER_LABELS_JSON,
    HideTogglePayload,
    alertmanager_service,
    build_silence_payload,
    storage_service,
)

router = APIRouter()


@router.get("/silences", response_model=List[Silence])
@handle_route_errors(bad_request_detail=INVALID_FILTER_LABELS_JSON)
async def get_silences(
    filter_labels: Optional[str] = Query(None),
    include_expired: bool = Query(False),
    show_hidden: bool = Query(False),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_SILENCES, "alertmanager")),
) -> List[Silence]:
    silences = await alertmanager_service.get_silences(filter_labels=alertmanager_service.parse_filter_labels(filter_labels))
    hidden_ids = set(
        await run_in_threadpool(
            storage_service.get_hidden_silence_ids,
            current_user.tenant_id,
            current_user.user_id,
        )
    )
    result = []
    for silence in silences:
        silence = alertmanager_service.apply_silence_metadata(silence)
        if not include_expired:
            state = (silence.status or {}).get("state") if silence.status else None
            if state and str(state).lower() == "expired":
                continue
        if alertmanager_service.silence_accessible(silence, current_user):
            silence.is_hidden = bool(silence.id and silence.id in hidden_ids)
            if silence.is_hidden and not show_hidden:
                continue
            result.append(silence)
    return result


@router.get("/silences/{silence_id}", response_model=Silence)
async def get_silence(
    silence_id: str,
    show_hidden: bool = Query(False),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_SILENCES, "alertmanager")),
) -> Silence:
    silence = await alertmanager_service.get_silence(silence_id)
    if not silence:
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    silence = alertmanager_service.apply_silence_metadata(silence)
    if not alertmanager_service.silence_accessible(silence, current_user):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    hidden_ids = set(
        await run_in_threadpool(
            storage_service.get_hidden_silence_ids,
            current_user.tenant_id,
            current_user.user_id,
        )
    )
    silence.is_hidden = bool(silence.id and silence.id in hidden_ids)
    if silence.is_hidden and not show_hidden:
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    return silence


@router.post("/silences", response_model=Dict[str, str])
@handle_route_errors()
async def create_silence(
    silence: SilenceCreateRequest = Body(...),
    current_user: TokenData = Depends(
        require_any_permission_with_scope([Permission.CREATE_SILENCES, Permission.WRITE_ALERTS], "alertmanager")
    ),
) -> Dict[str, str]:
    silence_id = await alertmanager_service.create_silence(build_silence_payload(silence, current_user))
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
) -> Dict[str, str]:
    existing = await alertmanager_service.get_silence(silence_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    existing = alertmanager_service.apply_silence_metadata(existing)
    if not alertmanager_service.silence_accessible(existing, current_user):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    if not alertmanager_service.silence_owned_by(existing, current_user):
        raise HTTPException(status_code=403, detail="Only silence owner can update this silence")
    new_id = await alertmanager_service.update_silence(silence_id, build_silence_payload(silence, current_user))
    if not new_id:
        raise HTTPException(status_code=500, detail="Failed to update silence")
    return {"silenceID": new_id, "status": "success", "message": "Silence updated"}


@router.delete("/silences/{silence_id}")
async def delete_silence(
    silence_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.DELETE_SILENCES, "alertmanager")),
) -> JSONDict:
    existing = await alertmanager_service.get_silence(silence_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found or already deleted")
    existing = alertmanager_service.apply_silence_metadata(existing)
    if not alertmanager_service.silence_accessible(existing, current_user):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found or already deleted")
    if not alertmanager_service.silence_owned_by(existing, current_user):
        raise HTTPException(status_code=403, detail="Only silence owner can delete this silence")
    if not await alertmanager_service.delete_silence(silence_id):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found or already deleted")
    return {"status": "success", "message": f"Silence {silence_id} deleted", "purged": True}


@router.post("/silences/{silence_id}/hide")
@handle_route_errors()
async def hide_silence(
    silence_id: str,
    payload: HideTogglePayload = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_SILENCES, "alertmanager")),
) -> JSONDict:
    silence = await alertmanager_service.get_silence(silence_id)
    if not silence:
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")
    silence = alertmanager_service.apply_silence_metadata(silence)
    if not alertmanager_service.silence_accessible(silence, current_user):
        raise HTTPException(status_code=404, detail=f"Silence {silence_id} not found")

    owner = str(getattr(silence, "created_by", "") or "")
    if owner and owner == str(current_user.user_id or ""):
        raise HTTPException(status_code=403, detail="You cannot hide your own silence")

    ok = await run_in_threadpool(
        storage_service.toggle_silence_hidden,
        current_user.tenant_id,
        current_user.user_id,
        silence_id,
        bool(payload.hidden),
    )
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to update silence visibility")
    return {"status": "success", "hidden": bool(payload.hidden)}
