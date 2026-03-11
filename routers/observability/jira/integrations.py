import uuid

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from fastapi.concurrency import run_in_threadpool

from custom_types.json import JSONDict
from middleware.dependencies import require_permission_with_scope
from middleware.error_handlers import handle_route_errors
from models.access.auth_models import Permission, TokenData
from models.alerting.requests import JiraIntegrationCreateRequest, JiraIntegrationUpdateRequest
from services.alerting.integration_security_service import (
    decrypt_tenant_secret,
    encrypt_tenant_secret,
    jira_integration_has_access,
    load_tenant_jira_integrations,
    mask_jira_integration,
    normalize_jira_auth_mode,
    normalize_visibility,
    save_tenant_jira_integrations,
    validate_jira_credentials,
    validate_shared_group_ids_for_user,
)

from .shared import HideTogglePayload, storage_service

router = APIRouter()


@router.get("/integrations/jira")
async def list_jira_integrations(
    show_hidden: bool = Query(False),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_INCIDENTS, "alertmanager")),
) -> JSONDict:
    integrations = load_tenant_jira_integrations(current_user.tenant_id)
    hidden_ids = set(
        await run_in_threadpool(
            storage_service.get_hidden_jira_integration_ids,
            current_user.tenant_id,
            current_user.user_id,
        )
    )
    visible_items: list[JSONDict] = []
    for item in integrations:
        if not jira_integration_has_access(item, current_user, write=False):
            continue
        masked = mask_jira_integration(item, current_user)
        masked["isHidden"] = str(masked.get("id") or "") in hidden_ids
        if not show_hidden and masked["isHidden"]:
            continue
        visible_items.append(masked)
    return {"items": visible_items}


@router.post("/integrations/jira")
@handle_route_errors()
async def create_jira_integration(
    payload: JiraIntegrationCreateRequest = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
) -> JSONDict:
    integrations = load_tenant_jira_integrations(current_user.tenant_id)
    visibility = normalize_visibility(payload.visibility, "private")
    shared_group_ids = (
        validate_shared_group_ids_for_user(current_user.tenant_id, payload.sharedGroupIds or [], current_user)
        if visibility == "group"
        else []
    )
    auth_mode = normalize_jira_auth_mode(payload.authMode)

    validate_jira_credentials(
        base_url=payload.baseUrl,
        auth_mode=auth_mode,
        email=payload.email,
        api_token=payload.apiToken,
        bearer_token=payload.bearerToken,
    )

    item: JSONDict = {
        "id": str(uuid.uuid4()),
        "name": (payload.name or "Jira").strip() or "Jira",
        "createdBy": current_user.user_id,
        "enabled": bool(payload.enabled),
        "visibility": visibility,
        "sharedGroupIds": [str(group_id).strip() for group_id in shared_group_ids if str(group_id).strip()],
        "baseUrl": (payload.baseUrl or "").strip() or None,
        "email": (payload.email or "").strip() or None,
        "apiToken": encrypt_tenant_secret((payload.apiToken or "").strip() or None),
        "bearerToken": encrypt_tenant_secret((payload.bearerToken or "").strip() or None),
        "authMode": auth_mode,
        "supportsSso": auth_mode == "sso",
    }
    integrations.append(item)
    save_tenant_jira_integrations(current_user.tenant_id, integrations)
    return mask_jira_integration(item, current_user)


@router.put("/integrations/jira/{integration_id}")
@handle_route_errors()
async def update_jira_integration(
    integration_id: str,
    payload: JiraIntegrationUpdateRequest = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
) -> JSONDict:
    integrations = load_tenant_jira_integrations(current_user.tenant_id)
    index = next((i for i, item in enumerate(integrations) if str(item.get("id")) == integration_id), None)
    if index is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Jira integration not found")

    current: JSONDict = integrations[index]
    if str(current.get("createdBy") or "") != current_user.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only integration owner can update this integration")

    fields = payload.model_fields_set
    if "name" in fields:
        current["name"] = (payload.name or "").strip() or current.get("name") or "Jira"
    if "enabled" in fields:
        current["enabled"] = bool(payload.enabled)
    if "visibility" in fields:
        current["visibility"] = normalize_visibility(payload.visibility, "private")
    if "sharedGroupIds" in fields:
        current["sharedGroupIds"] = [str(group_id).strip() for group_id in (payload.sharedGroupIds or []) if str(group_id).strip()]

    if current.get("visibility") != "group":
        current["sharedGroupIds"] = []
    else:
        current_shared_group_ids = current.get("sharedGroupIds")
        current["sharedGroupIds"] = validate_shared_group_ids_for_user(
            current_user.tenant_id,
            current_shared_group_ids if isinstance(current_shared_group_ids, list) else [],
            current_user,
        )

    if "baseUrl" in fields:
        current["baseUrl"] = (payload.baseUrl or "").strip() or None
    if "email" in fields:
        current["email"] = (payload.email or "").strip() or None
    if "apiToken" in fields:
        current["apiToken"] = encrypt_tenant_secret((payload.apiToken or "").strip() or None)
    if "bearerToken" in fields:
        current["bearerToken"] = encrypt_tenant_secret((payload.bearerToken or "").strip() or None)
    if "authMode" in fields:
        current["authMode"] = (payload.authMode or "api_token").strip() or "api_token"
    if "supportsSso" in fields:
        current["supportsSso"] = bool(payload.supportsSso)

    auth_mode_raw = current.get("authMode")
    base_url_raw = current.get("baseUrl")
    email_raw = current.get("email")
    api_token_raw = current.get("apiToken")
    bearer_token_raw = current.get("bearerToken")
    next_auth_mode = normalize_jira_auth_mode(str(auth_mode_raw) if auth_mode_raw is not None else None)
    validate_jira_credentials(
        base_url=str(base_url_raw) if base_url_raw is not None else None,
        auth_mode=next_auth_mode,
        email=str(email_raw) if email_raw is not None else None,
        api_token=decrypt_tenant_secret(str(api_token_raw) if api_token_raw is not None else None) if api_token_raw else None,
        bearer_token=decrypt_tenant_secret(str(bearer_token_raw) if bearer_token_raw is not None else None) if bearer_token_raw else None,
    )
    current["authMode"] = next_auth_mode
    current["supportsSso"] = next_auth_mode == "sso"

    integrations[index] = current
    save_tenant_jira_integrations(current_user.tenant_id, integrations)
    return mask_jira_integration(current, current_user)


@router.delete("/integrations/jira/{integration_id}")
@handle_route_errors()
async def delete_jira_integration(
    integration_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
) -> JSONDict:
    integrations = load_tenant_jira_integrations(current_user.tenant_id)
    index = next((i for i, item in enumerate(integrations) if str(item.get("id")) == integration_id), None)
    if index is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Jira integration not found")
    if str(integrations[index].get("createdBy") or "") != current_user.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only integration owner can delete this integration")
    integrations.pop(index)
    save_tenant_jira_integrations(current_user.tenant_id, integrations)
    unlinked = await run_in_threadpool(
        storage_service.unlink_jira_integration_from_incidents,
        current_user.tenant_id,
        integration_id,
    )
    return {"status": "success", "incidentsUnlinked": unlinked}


@router.post("/integrations/jira/{integration_id}/hide")
@handle_route_errors()
async def hide_jira_integration(
    integration_id: str,
    payload: HideTogglePayload = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_INCIDENTS, "alertmanager")),
) -> JSONDict:
    integrations = load_tenant_jira_integrations(current_user.tenant_id)
    match = next((item for item in integrations if str(item.get("id")) == integration_id), None)
    if not match or not jira_integration_has_access(match, current_user, write=False):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Jira integration not found")
    if str(match.get("createdBy") or "") == current_user.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You cannot hide your own Jira integration")
    if normalize_visibility(str(match.get("visibility") or "private"), "private") == "private":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only shared Jira integrations can be hidden")

    hidden = bool(payload.hidden)
    ok = await run_in_threadpool(
        storage_service.toggle_jira_integration_hidden,
        current_user.tenant_id,
        current_user.user_id,
        integration_id,
        hidden,
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update Jira integration visibility")
    return {"status": "success", "hidden": hidden}
