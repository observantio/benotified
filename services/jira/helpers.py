"""
Jira integration helper functions for resolving credentials, checking integration usability, and fetching Jira projects and issue types via integrations.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from fastapi import  HTTPException, status
from models.access.auth_models import TokenData

from services.alerting.integration_security_service import (
    get_effective_jira_credentials,
    integration_is_usable,
    jira_integration_credentials,
    jira_is_enabled_for_tenant,
    resolve_jira_integration,
)

from services.jira_service import JiraError, jira_service

async def jira_projects_via_integration(tenant_id: str, integration_id: str, current_user: TokenData) -> dict:
    integration = resolve_jira_integration(tenant_id, integration_id, current_user, require_write=False)
    if not integration_is_usable(integration):
        return {"enabled": False, "projects": []}
    try:
        projects = await jira_service.list_projects(credentials=jira_integration_credentials(integration))
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
    return {"enabled": True, "projects": projects}


async def jira_issue_types_via_integration(tenant_id: str, integration_id: str, project_key: str, current_user: TokenData) -> dict:
    integration = resolve_jira_integration(tenant_id, integration_id, current_user, require_write=False)
    if not integration_is_usable(integration):
        return {"enabled": False, "issueTypes": []}
    try:
        issue_types = await jira_service.list_issue_types(
            project_key=project_key,
            credentials=jira_integration_credentials(integration),
        )
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
    return {"enabled": True, "issueTypes": issue_types}


def resolve_incident_jira_credentials(incident, tenant_id: str, current_user: TokenData):
    if incident.jira_integration_id:
        integration = resolve_jira_integration(tenant_id, incident.jira_integration_id, current_user, require_write=False)
        if not integration_is_usable(integration):
            return None
        return jira_integration_credentials(integration)
    if not jira_is_enabled_for_tenant(tenant_id):
        return None
    return get_effective_jira_credentials(tenant_id)
