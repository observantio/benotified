"""
Incident helper functions for BeNotified service - formatting descriptions, mapping severities, syncing notes to Jira, etc.
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""


from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Optional

from models.access.auth_models import TokenData
from models.alerting.incidents import AlertIncident
from services.jira.helpers import resolve_incident_jira_credentials
from services.jira_service import JiraError, jira_service

logger = logging.getLogger(__name__)


def format_incident_description(incident: AlertIncident, fallback: Optional[str]) -> str:
    if fallback and fallback.strip():
        return fallback.strip()

    annotations = incident.annotations or {}
    summary = str(annotations.get("summary") or "").strip()
    details = str(annotations.get("description") or "").strip()
    if details and summary:
        return f"{details} -> {summary}"
    if details:
        return details
    if summary:
        return summary
    return str(incident.alert_name or "Incident").strip()


def map_severity_to_jira_priority(severity: Optional[str]) -> str:
    normalized = str(severity or "").strip().lower()
    if normalized == "critical":
        return "High"
    if normalized == "warning":
        return "Medium"
    return "Low"


def format_note_for_jira_comment(
    note_text: str,
    author_label: str,
    created_at: Optional[str] = None,
) -> str:
    raw_text = str(note_text or "").strip()
    if not raw_text:
        return ""
    when = created_at or datetime.now(timezone.utc).isoformat()
    try:
        dt = datetime.fromisoformat(str(when).replace("Z", "+00:00"))
        when_label = dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        when_label = str(when)
    return f"{author_label} · {when_label}\n{raw_text}"


def resolve_note_author_display(author: str, current_user: TokenData) -> str:
    raw = str(author or "").strip()
    if not raw:
        return "Unknown user"
    current_user_id = str(current_user.user_id or "").strip()
    if current_user_id and raw == current_user_id:
        return str(current_user.username or current_user.user_id).strip()
    looks_like_uuid = re.match(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        raw,
        flags=re.IGNORECASE,
    )
    if looks_like_uuid:
        return "Unknown user"
    return raw


def rewrite_note_text_for_author(note_text: str, author_id: str, author_label: str) -> str:
    text = str(note_text or "").strip()
    author_id = str(author_id or "").strip()
    author_label = str(author_label or "").strip()
    if not text or not author_id or not author_label or author_label == "Unknown user":
        return text
    pattern = re.compile(rf"\b{re.escape(author_id)}\b")
    return pattern.sub(author_label, text)


def rewrite_note_text_for_actor(note_text: str, actor_id: str, actor_label: str) -> str:
    return rewrite_note_text_for_author(note_text, actor_id, actor_label)


def build_formatted_incident_note_bodies(
    incident: AlertIncident,
    current_user: TokenData,
) -> list[str]:
    items: list[str] = []
    for note in list(getattr(incident, "notes", []) or []):
        if not note:
            continue
        author = str(getattr(note, "author", "") or "").strip()
        if author.startswith("jira:"):
            continue
        text = str(getattr(note, "text", "") or "").strip()
        if not text:
            continue
        created_at = str(getattr(note, "created_at", "") or getattr(note, "createdAt", "") or "").strip() or None
        author_label = resolve_note_author_display(author, current_user)
        normalized_text = rewrite_note_text_for_author(text, author, author_label)
        body = format_note_for_jira_comment(normalized_text, author_label, created_at)
        if body:
            items.append(body)
    return items


async def sync_note_to_jira_comment(
    incident: AlertIncident,
    *,
    tenant_id: str,
    current_user: TokenData,
    note_text: Optional[str],
) -> None:
    text = str(note_text or "").strip()
    if not text or not incident.jira_ticket_key:
        return
    try:
        author_label = str(
            getattr(current_user, "full_name", None)
            or getattr(current_user, "username", None)
            or current_user.user_id
        ).strip()
        normalized_text = rewrite_note_text_for_actor(text, current_user.user_id, author_label)
        formatted = format_note_for_jira_comment(normalized_text, author_label)
        credentials = resolve_incident_jira_credentials(incident, tenant_id, current_user)
        if credentials is None:
            return
        await jira_service.add_comment(incident.jira_ticket_key, formatted, credentials=credentials)
    except JiraError as exc:
        logger.warning("Failed to sync incident note to Jira for incident %s: %s", incident.id, exc)


async def move_incident_ticket_to_todo(
    incident: AlertIncident,
    *,
    tenant_id: str,
    current_user: TokenData,
) -> None:
    if not incident.jira_ticket_key:
        return
    try:
        credentials = resolve_incident_jira_credentials(incident, tenant_id, current_user)
        if credentials is None:
            return
        await jira_service.transition_issue_to_todo(incident.jira_ticket_key, credentials=credentials)
    except JiraError as exc:
        logger.warning(
            "Failed to move Jira issue %s to To Do for incident %s: %s",
            incident.jira_ticket_key,
            incident.id,
            exc,
        )


async def move_incident_ticket_to_in_progress(
    incident: AlertIncident,
    *,
    tenant_id: str,
    current_user: TokenData,
) -> None:
    if not incident.jira_ticket_key:
        return
    try:
        credentials = resolve_incident_jira_credentials(incident, tenant_id, current_user)
        if credentials is None:
            return
        await jira_service.transition_issue_to_in_progress(incident.jira_ticket_key, credentials=credentials)
    except JiraError as exc:
        logger.warning(
            "Failed to move Jira issue %s to In Progress for incident %s: %s",
            incident.jira_ticket_key,
            incident.id,
            exc,
        )


async def move_incident_ticket_to_done(
    incident: AlertIncident,
    *,
    tenant_id: str,
    current_user: TokenData,
) -> None:
    if not incident.jira_ticket_key:
        return
    try:
        credentials = resolve_incident_jira_credentials(incident, tenant_id, current_user)
        if credentials is None:
            return
        await jira_service.transition_issue_to_done(incident.jira_ticket_key, credentials=credentials)
    except JiraError as exc:
        logger.warning(
            "Failed to move Jira issue %s to Done for incident %s: %s",
            incident.jira_ticket_key,
            incident.id,
            exc,
        )

