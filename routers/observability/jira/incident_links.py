import logging

from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool

from custom_types.json import JSONDict
from middleware.dependencies import require_permission_with_scope
from middleware.error_handlers import handle_route_errors
from models.access.auth_models import Permission, TokenData
from models.alerting.incidents import AlertIncident, AlertIncidentUpdateRequest
from models.alerting.requests import IncidentJiraCreateRequest
from services.alerting.integration_security_service import (
    integration_is_usable,
    jira_integration_credentials,
    resolve_jira_integration,
)
from services.incidents.helpers import (
    build_formatted_incident_note_bodies,
    format_incident_description,
    map_severity_to_jira_priority,
)
from services.jira.helpers import resolve_incident_jira_credentials
from services.jira_service import JiraError, jira_service

from .shared import SUPPORTED_INCIDENT_JIRA_ISSUE_TYPES, storage_service

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/incidents/{incident_id}/jira", response_model=AlertIncident)
@handle_route_errors()
async def create_incident_jira(
    incident_id: str,
    payload: IncidentJiraCreateRequest = Body(...),
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
) -> AlertIncident:
    group_ids = getattr(current_user, "group_ids", []) or []
    incident = await run_in_threadpool(
        storage_service.get_incident_for_user,
        incident_id,
        current_user.tenant_id,
        current_user.user_id,
        group_ids,
        True,
    )
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    has_existing_link = bool(str(getattr(incident, "jira_ticket_key", "") or "").strip())
    if has_existing_link and not bool(getattr(payload, "replaceExisting", False)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Incident already linked to Jira ticket {incident.jira_ticket_key}",
        )

    integration_id = (payload.integrationId or "").strip()
    if not integration_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="integrationId is required")

    integration = resolve_jira_integration(current_user.tenant_id, integration_id, current_user, require_write=True)
    if not integration_is_usable(integration):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Selected Jira integration is not enabled or incomplete")

    project = (payload.projectKey or "").strip()
    if not project:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="projectKey is required")
    requested_issue_type = str(payload.issueType or "Task").strip()
    if requested_issue_type.lower() not in SUPPORTED_INCIDENT_JIRA_ISSUE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only Jira issue types Task and Bug are supported",
        )

    try:
        response = await jira_service.create_issue(
            project_key=project,
            summary=(payload.summary or incident.alert_name or "Incident").strip(),
            description=format_incident_description(incident, payload.description),
            issue_type="Bug" if requested_issue_type.lower() == "bug" else "Task",
            priority=map_severity_to_jira_priority(getattr(incident, "severity", None)),
            credentials=jira_integration_credentials(integration),
        )
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    issue_key = str(response.get("key") or "").strip()
    if issue_key:
        try:
            await jira_service.transition_issue_to_todo(
                issue_key=issue_key,
                credentials=jira_integration_credentials(integration),
            )
        except JiraError as exc:
            logger.warning("Failed to move newly created Jira issue %s to To Do: %s", issue_key, exc)

    updated = await run_in_threadpool(
        storage_service.update_incident,
        incident_id,
        current_user.tenant_id,
        current_user.user_id,
        AlertIncidentUpdateRequest.model_validate(
            {
                "jiraTicketKey": response.get("key") or None,
                "jiraTicketUrl": response.get("url") or None,
                "jiraIntegrationId": integration_id,
            }
        ),
        group_ids,
    )
    if not updated:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to persist Jira metadata")

    try:
        for formatted_text in build_formatted_incident_note_bodies(updated, current_user):
            issue_key = str(response.get("key") or "").strip()
            if not issue_key:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Missing Jira issue key")
            await jira_service.add_comment(
                issue_key=issue_key,
                text=formatted_text,
                credentials=jira_integration_credentials(integration),
            )
    except JiraError as exc:
        logger.warning("Failed to backfill incident notes to Jira issue %s: %s", response.get("key"), exc)

    logger.info("Created Jira issue %s for incident %s", response.get("key"), incident_id)
    return updated


@router.post("/incidents/{incident_id}/jira/sync-notes")
@handle_route_errors()
async def sync_incident_jira_notes(
    incident_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.UPDATE_INCIDENTS, "alertmanager")),
) -> JSONDict:
    group_ids = getattr(current_user, "group_ids", []) or []
    incident = await run_in_threadpool(
        storage_service.get_incident_for_user,
        incident_id,
        current_user.tenant_id,
        current_user.user_id,
        group_ids,
        True,
    )
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if not incident.jira_ticket_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incident is not linked to Jira")

    credentials = resolve_incident_jira_credentials(incident, current_user.tenant_id, current_user)
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No usable Jira credentials found for this incident")

    note_bodies = build_formatted_incident_note_bodies(incident, current_user)
    if not note_bodies:
        return {"synced": 0, "skipped": 0, "totalNotes": 0}

    try:
        existing_comments = await jira_service.list_comments(incident.jira_ticket_key, credentials=credentials)
    except JiraError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    existing_bodies = {
        str(item.get("body") or "").strip()
        for item in (existing_comments or [])
        if isinstance(item, dict)
    }

    synced = 0
    skipped = 0
    for body in note_bodies:
        if body in existing_bodies:
            skipped += 1
            continue
        try:
            await jira_service.add_comment(incident.jira_ticket_key, body, credentials=credentials)
            existing_bodies.add(body)
            synced += 1
        except JiraError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    return {"synced": synced, "skipped": skipped, "totalNotes": len(note_bodies)}


@router.get("/incidents/{incident_id}/jira/comments")
async def list_incident_jira_comments(
    incident_id: str,
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_INCIDENTS, "alertmanager")),
) -> JSONDict:
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
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    return {"comments": comments}
