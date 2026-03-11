from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from custom_types.json import JSONDict
from middleware.dependencies import require_permission_with_scope
from models.access.auth_models import Permission, TokenData
from services.alerting.integration_security_service import (
    get_effective_jira_credentials,
    jira_is_enabled_for_tenant,
)
from services.jira.helpers import jira_issue_types_via_integration, jira_projects_via_integration
from services.jira_service import JiraError, jira_service

router = APIRouter()


@router.get("/jira/projects")
async def list_jira_projects(
    integration_id: Optional[str] = Query(None, alias="integrationId"),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
) -> JSONDict:
    if integration_id:
        return await jira_projects_via_integration(current_user.tenant_id, integration_id, current_user)
    if not jira_is_enabled_for_tenant(current_user.tenant_id):
        return {"enabled": False, "projects": []}
    try:
        projects = await jira_service.list_projects(credentials=get_effective_jira_credentials(current_user.tenant_id))
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    return {"enabled": True, "projects": projects}


@router.get("/jira/projects/{project_key}/issue-types")
async def list_jira_issue_types(
    project_key: str,
    integration_id: Optional[str] = Query(None, alias="integrationId"),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
) -> JSONDict:
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
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    return {"enabled": True, "issueTypes": issue_types}


@router.get("/integrations/jira/{integration_id}/projects")
async def list_jira_projects_by_integration(
    integration_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
) -> JSONDict:
    return await jira_projects_via_integration(current_user.tenant_id, integration_id, current_user)


@router.get("/integrations/jira/{integration_id}/projects/{project_key}/issue-types")
async def list_jira_issue_types_by_integration(
    integration_id: str,
    project_key: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
) -> JSONDict:
    return await jira_issue_types_via_integration(current_user.tenant_id, integration_id, project_key, current_user)
