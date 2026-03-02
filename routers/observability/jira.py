"""
Jira integration API endpoints for managing tenant-level Jira configuration, Jira integrations, and synchronizing incidents with Jira issues. Supports creating Jira issues from incidents, listing Jira projects and issue types, and adding comments to Jira issues from incident notes.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import uuid
import logging
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from fastapi.concurrency import run_in_threadpool

from middleware.dependencies import require_permission_with_scope
from middleware.error_handlers import handle_route_errors
from models.access.auth_models import Permission, TokenData
from models.alerting.incidents import AlertIncident, AlertIncidentUpdateRequest
from models.alerting.requests import (
    IncidentJiraCommentRequest,
    IncidentJiraCreateRequest,
    JiraConfigUpdateRequest,
    JiraIntegrationCreateRequest,
    JiraIntegrationUpdateRequest,
)
from services.alerting.integration_security_service import (
    decrypt_tenant_secret,
    encrypt_tenant_secret,
    get_effective_jira_credentials,
    integration_is_usable,
    jira_integration_credentials,
    jira_integration_has_access,
    jira_is_enabled_for_tenant,
    load_tenant_jira_config,
    load_tenant_jira_integrations,
    mask_jira_integration,
    normalize_jira_auth_mode,
    normalize_visibility,
    resolve_jira_integration,
    save_tenant_jira_config,
    save_tenant_jira_integrations,
    sync_jira_comments_to_incident_notes,
    validate_jira_credentials,
    validate_shared_group_ids_for_user,
)
from services.jira_service import JiraError, jira_service
from services.storage_db_service import DatabaseStorageService
from services.jira.helpers import jira_issue_types_via_integration, jira_projects_via_integration, resolve_incident_jira_credentials

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/alertmanager", tags=["alertmanager-jira"])

storage_service = DatabaseStorageService()

@router.get("/jira/config")
async def get_jira_config(
    current_user: TokenData = Depends(require_permission_with_scope(Permission.MANAGE_TENANTS, "alertmanager")),
):
    cfg = load_tenant_jira_config(current_user.tenant_id)
    return {
        "enabled": bool(cfg.get("enabled")),
        "baseUrl": cfg.get("base_url"),
        "email": cfg.get("email"),
        "hasApiToken": bool(cfg.get("api_token")),
        "hasBearerToken": bool(cfg.get("bearer")),
    }


@router.put("/jira/config")
@handle_route_errors()
async def put_jira_config(
    payload: JiraConfigUpdateRequest = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.MANAGE_TENANTS, "alertmanager")),
):
    return save_tenant_jira_config(
        current_user.tenant_id,
        enabled=payload.enabled,
        base_url=payload.baseUrl,
        email=payload.email,
        api_token=payload.apiToken,
        bearer=payload.bearerToken,
    )

@router.get("/jira/projects")
async def list_jira_projects(
    integration_id: Optional[str] = Query(None, alias="integrationId"),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
):
    if integration_id:
        return await jira_projects_via_integration(current_user.tenant_id, integration_id, current_user)
    if not jira_is_enabled_for_tenant(current_user.tenant_id):
        return {"enabled": False, "projects": []}
    try:
        projects = await jira_service.list_projects(credentials=get_effective_jira_credentials(current_user.tenant_id))
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
    return {"enabled": True, "projects": projects}


@router.get("/jira/projects/{project_key}/issue-types")
async def list_jira_issue_types(
    project_key: str,
    integration_id: Optional[str] = Query(None, alias="integrationId"),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
):
    if integration_id:
        return await jira_issue_types_via_integration(current_user.tenant_id, integration_id, project_key, current_user)
    if not jira_is_enabled_for_tenant(current_user.tenant_id):
        return {"enabled": False, "issueTypes": []}
    try:
        issue_types = await jira_service.list_issue_types(
            project_key=project_key,
            credentials=get_effective_jira_credentials(current_user.tenant_id),
        )
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
    return {"enabled": True, "issueTypes": issue_types}


@router.get("/integrations/jira")
async def list_jira_integrations(
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_INCIDENTS, "alertmanager")),
):
    integrations = load_tenant_jira_integrations(current_user.tenant_id)
    return {
        "items": [
            mask_jira_integration(item, current_user)
            for item in integrations
            if jira_integration_has_access(item, current_user, write=False)
        ]
    }


@router.get("/integrations/jira/{integration_id}/projects")
async def list_jira_projects_by_integration(
    integration_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
):
    return await jira_projects_via_integration(current_user.tenant_id, integration_id, current_user)


@router.get("/integrations/jira/{integration_id}/projects/{project_key}/issue-types")
async def list_jira_issue_types_by_integration(
    integration_id: str,
    project_key: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
):
    return await jira_issue_types_via_integration(current_user.tenant_id, integration_id, project_key, current_user)


@router.post("/integrations/jira")
@handle_route_errors()
async def create_jira_integration(
    payload: JiraIntegrationCreateRequest = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
):
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

    item = {
        "id": str(uuid.uuid4()),
        "name": (payload.name or "Jira").strip() or "Jira",
        "createdBy": current_user.user_id,
        "enabled": bool(payload.enabled),
        "visibility": visibility,
        "sharedGroupIds": [str(g).strip() for g in shared_group_ids if str(g).strip()],
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
):
    integrations = load_tenant_jira_integrations(current_user.tenant_id)
    index = next((i for i, item in enumerate(integrations) if str(item.get("id")) == integration_id), None)
    if index is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Jira integration not found")

    current = integrations[index]
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
        current["sharedGroupIds"] = [str(g).strip() for g in (payload.sharedGroupIds or []) if str(g).strip()]

    if current.get("visibility") != "group":
        current["sharedGroupIds"] = []
    else:
        current["sharedGroupIds"] = validate_shared_group_ids_for_user(
            current_user.tenant_id,
            current.get("sharedGroupIds") or [],
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

    next_auth_mode = normalize_jira_auth_mode(current.get("authMode"))
    validate_jira_credentials(
        base_url=current.get("baseUrl"),
        auth_mode=next_auth_mode,
        email=current.get("email"),
        api_token=decrypt_tenant_secret(current["apiToken"]) if current.get("apiToken") else None,
        bearer_token=decrypt_tenant_secret(current["bearerToken"]) if current.get("bearerToken") else None,
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
):
    integrations = load_tenant_jira_integrations(current_user.tenant_id)
    index = next((i for i, item in enumerate(integrations) if str(item.get("id")) == integration_id), None)
    if index is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Jira integration not found")
    if str(integrations[index].get("createdBy") or "") != current_user.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only integration owner can delete this integration")
    integrations.pop(index)
    save_tenant_jira_integrations(current_user.tenant_id, integrations)
    return {"status": "success"}


@router.post("/incidents/{incident_id}/jira", response_model=AlertIncident)
@handle_route_errors()
async def create_incident_jira(
    incident_id: str,
    payload: IncidentJiraCreateRequest = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
):
    group_ids = getattr(current_user, "group_ids", []) or []
    incident = await run_in_threadpool(
        storage_service.get_incident_for_user,
        incident_id,
        current_user.tenant_id,
        current_user.user_id,
        group_ids,
    )
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    integration_id = (payload.integrationId or "").strip()
    if not integration_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="integrationId is required")

    integration = resolve_jira_integration(current_user.tenant_id, integration_id, current_user, require_write=True)
    if not integration_is_usable(integration):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Selected Jira integration is not enabled or incomplete")

    project = (payload.projectKey or "").strip()
    if not project:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="projectKey is required")

    try:
        res = await jira_service.create_issue(
            project_key=project,
            summary=(payload.summary or incident.alert_name or "Incident").strip(),
            description=payload.description
            or f"Incident: {incident.alert_name}\n\nLabels: {incident.labels or {}}\nAnnotations: {incident.annotations or {}}",
            issue_type=(payload.issueType or "Task").strip(),
            credentials=jira_integration_credentials(integration),
        )
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
    except Exception:
        logger.exception("Unexpected error creating Jira issue for incident %s", incident_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create Jira issue")

    updated = await run_in_threadpool(
        storage_service.update_incident,
        incident_id,
        current_user.tenant_id,
        current_user.user_id,
        AlertIncidentUpdateRequest(
            jiraTicketKey=res.get("key") or None,
            jiraTicketUrl=res.get("url") or None,
            jiraIntegrationId=integration_id,
        ),
    )
    if not updated:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to persist Jira metadata")

    logger.info("Created Jira issue %s for incident %s", res.get("key"), incident_id)
    return updated


@router.get("/incidents/{incident_id}/jira/comments")
async def list_incident_jira_comments(
    incident_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_INCIDENTS, "alertmanager")),
):
    group_ids = getattr(current_user, "group_ids", []) or []
    incident = await run_in_threadpool(
        storage_service.get_incident_for_user,
        incident_id,
        current_user.tenant_id,
        current_user.user_id,
        group_ids,
    )
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if not incident.jira_ticket_key:
        return {"comments": []}

    credentials = resolve_incident_jira_credentials(incident, current_user.tenant_id, current_user)
    if credentials is None:
        return {"comments": []}

    try:
        comments = await jira_service.list_comments(incident.jira_ticket_key, credentials=credentials)
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

    sync_jira_comments_to_incident_notes(incident_id, current_user.tenant_id, comments)
    return {"comments": comments}


@router.post("/incidents/{incident_id}/jira/sync-comments")
async def sync_incident_jira_comments(
    incident_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
):
    group_ids = getattr(current_user, "group_ids", []) or []
    incident = await run_in_threadpool(
        storage_service.get_incident_for_user,
        incident_id,
        current_user.tenant_id,
        current_user.user_id,
        group_ids,
    )
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if not incident.jira_ticket_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incident has no Jira ticket key")

    credentials = resolve_incident_jira_credentials(incident, current_user.tenant_id, current_user)
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Jira integration is not enabled or incomplete")

    try:
        comments = await jira_service.list_comments(incident.jira_ticket_key, credentials=credentials)
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

    appended = sync_jira_comments_to_incident_notes(incident_id, current_user.tenant_id, comments)
    return {"status": "success", "synced": appended, "count": len(comments)}


@router.post("/incidents/{incident_id}/jira/comments")
async def create_incident_jira_comment(
    incident_id: str,
    payload: IncidentJiraCommentRequest = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
):
    group_ids = getattr(current_user, "group_ids", []) or []
    incident = await run_in_threadpool(
        storage_service.get_incident_for_user,
        incident_id,
        current_user.tenant_id,
        current_user.user_id,
        group_ids,
    )
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if not incident.jira_ticket_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incident has no Jira ticket key")

    text = (payload.text or "").strip()
    if not text:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Comment text is required")

    credentials = resolve_incident_jira_credentials(incident, current_user.tenant_id, current_user)
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Jira integration is not enabled or incomplete")

    try:
        comment = await jira_service.add_comment(incident.jira_ticket_key, text, credentials=credentials)
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

    try:
        sync_jira_comments_to_incident_notes(incident_id, current_user.tenant_id, [comment])
    except Exception:
        logger.warning("Failed to persist Jira comment into incident notes for incident %s", incident_id)

    return {"status": "success", "comment": comment}