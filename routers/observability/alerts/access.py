from fastapi import APIRouter, Body
from fastapi.concurrency import run_in_threadpool

from custom_types.json import JSONDict
from models.alerting.requests import GroupSharePruneRequest

from .shared import alertmanager_service, storage_service

router = APIRouter()


@router.post("/access/group-shares/prune")
async def prune_removed_member_group_shares(
    payload: GroupSharePruneRequest = Body(...),
) -> JSONDict:
    updated = await run_in_threadpool(
        storage_service.prune_removed_member_group_shares,
        payload.tenant_id,
        payload.group_id,
        payload.removed_user_ids,
        payload.removed_usernames,
    )
    silences_updated = await alertmanager_service.prune_removed_member_group_silences(
        group_id=payload.group_id,
        removed_user_ids=payload.removed_user_ids,
        removed_usernames=payload.removed_usernames,
    )
    return {"status": "success", "updated": {**updated, "silences": silences_updated}}
