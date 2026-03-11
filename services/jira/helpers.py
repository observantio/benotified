"""
Jira integration helper functions for resolving credentials, checking integration usability, and fetching Jira projects and issue types via integrations.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from urllib.parse import urlparse

from fastapi import  HTTPException, status
from models.access.auth_models import TokenData
from custom_types.json import JSONDict
from models.alerting.incidents import AlertIncident

from services.alerting.integration_security_service import (
    get_effective_jira_credentials,
    integration_is_usable,
    jira_integration_credentials,
    jira_is_enabled_for_tenant,
    load_tenant_jira_integrations,
    resolve_jira_integration,
)

from services.jira_service import JiraError, jira_service


def _find_integration(tenant_id: str, integration_id: str) -> JSONDict | None:
    for item in load_tenant_jira_integrations(tenant_id):
        if str(item.get("id") or "").strip() == str(integration_id or "").strip():
            return item
    return None

async def jira_projects_via_integration(tenant_id: str, integration_id: str, current_user: TokenData) -> JSONDict:
    integration: JSONDict | None
    try:
        integration = resolve_jira_integration(tenant_id, integration_id, current_user, require_write=False)
    except HTTPException as exc:
        integration = _find_integration(tenant_id, integration_id)
        if not integration:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Jira integration not found") from exc
    credentials = jira_integration_credentials(integration)
    base_url = str(credentials.get("base_url") or "").strip()
    host = (urlparse(base_url).hostname or "").strip().lower()
    if host.endswith(".atlassian.net") and credentials.get("auth_mode") in {"bearer", "sso"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Atlassian Cloud requires Email + API token (authMode=api_token)",
        )
    if not integration_is_usable(integration):
        return {"enabled": False, "projects": []}
    try:
        projects = await jira_service.list_projects(credentials=credentials)
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    return {"enabled": True, "projects": projects}


async def jira_issue_types_via_integration(tenant_id: str, integration_id: str, project_key: str, current_user: TokenData) -> JSONDict:
    integration: JSONDict | None
    try:
        integration = resolve_jira_integration(tenant_id, integration_id, current_user, require_write=False)
    except HTTPException as exc:
        integration = _find_integration(tenant_id, integration_id)
        if not integration:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Jira integration not found") from exc
    credentials = jira_integration_credentials(integration)
    base_url = str(credentials.get("base_url") or "").strip()
    host = (urlparse(base_url).hostname or "").strip().lower()
    if host.endswith(".atlassian.net") and credentials.get("auth_mode") in {"bearer", "sso"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Atlassian Cloud requires Email + API token (authMode=api_token)",
        )
    if not integration_is_usable(integration):
        return {"enabled": False, "issueTypes": []}
    try:
        issue_types = await jira_service.list_issue_types(
            project_key=project_key,
            credentials=credentials,
        )
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    return {"enabled": True, "issueTypes": issue_types}


def resolve_incident_jira_credentials(
    incident: AlertIncident,
    tenant_id: str,
    current_user: TokenData,
) -> JSONDict | None:
    integration_id = str(getattr(incident, "jira_integration_id", "") or "").strip()
    if integration_id:
        integration: JSONDict | None
        try:
            integration = resolve_jira_integration(
                tenant_id,
                integration_id,
                current_user,
                require_write=False,
            )
        except HTTPException:
            integration = _find_integration(tenant_id, integration_id)
        if not integration or not integration_is_usable(integration):
            return None
        try:
            credentials: JSONDict = dict(jira_integration_credentials(integration))
            return credentials
        except (TypeError, ValueError):
            return None

    if not jira_is_enabled_for_tenant(tenant_id):
        return None
    try:
        default_credentials: JSONDict = dict(get_effective_jira_credentials(tenant_id))
        return default_credentials
    except (TypeError, ValueError):
        return None
