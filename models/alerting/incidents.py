"""
Module defines Pydantic models for alerting-related data structures used in the API layer.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class IncidentStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"


class IncidentVisibility(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    GROUP = "group"


class IncidentNote(BaseModel):
    author: str
    text: str
    created_at: datetime = Field(..., alias="createdAt")

    model_config = ConfigDict(populate_by_name=True)


class AlertIncident(BaseModel):
    id: str
    fingerprint: str
    alert_name: str = Field(..., alias="alertName")
    severity: str
    status: IncidentStatus
    assignee: Optional[str] = None
    notes: List[IncidentNote] = Field(default_factory=list)
    labels: Dict[str, str] = Field(default_factory=dict)
    annotations: Dict[str, str] = Field(default_factory=dict)
    visibility: IncidentVisibility = IncidentVisibility.PUBLIC
    shared_group_ids: List[str] = Field(default_factory=list, alias="sharedGroupIds")
    jira_ticket_key: Optional[str] = Field(None, alias="jiraTicketKey")
    jira_ticket_url: Optional[str] = Field(None, alias="jiraTicketUrl")
    jira_integration_id: Optional[str] = Field(None, alias="jiraIntegrationId")
    starts_at: Optional[datetime] = Field(None, alias="startsAt")
    last_seen_at: datetime = Field(..., alias="lastSeenAt")
    resolved_at: Optional[datetime] = Field(None, alias="resolvedAt")
    created_at: datetime = Field(..., alias="createdAt")
    updated_at: datetime = Field(..., alias="updatedAt")
    # Indicates the incident has been manually reopened / marked for investigation
    user_managed: bool = Field(False, alias="userManaged")
    # When true the incident will be hidden from default listings once resolved
    hide_when_resolved: bool = Field(False, alias="hideWhenResolved")

    model_config = ConfigDict(use_enum_values=True, populate_by_name=True)


class AlertIncidentUpdateRequest(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None
    note: Optional[str] = None
    visibility: Optional[IncidentVisibility] = None
    shared_group_ids: Optional[List[str]] = Field(default=None, alias="sharedGroupIds")
    jira_ticket_key: Optional[str] = Field(None, alias="jiraTicketKey")
    jira_ticket_url: Optional[str] = Field(None, alias="jiraTicketUrl")
    jira_integration_id: Optional[str] = Field(None, alias="jiraIntegrationId")
    hide_when_resolved: Optional[bool] = Field(None, alias="hideWhenResolved")
