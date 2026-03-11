"""
Request models for alerting-related API endpoints.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from custom_types.json import JSONDict


class AlertWebhookRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    alerts: List[JSONDict] = Field(default_factory=list)


class RuleImportRequest(BaseModel):
    yamlContent: Optional[str] = None
    defaults: JSONDict = Field(default_factory=dict)
    dryRun: bool = False


class JiraConfigUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    baseUrl: Optional[str] = None
    email: Optional[str] = None
    apiToken: Optional[str] = None
    bearerToken: Optional[str] = None


class JiraIntegrationCreateRequest(BaseModel):
    name: Optional[str] = None
    enabled: bool = True
    visibility: str = "private"
    sharedGroupIds: List[str] = Field(default_factory=list)
    baseUrl: Optional[str] = None
    email: Optional[str] = None
    apiToken: Optional[str] = None
    bearerToken: Optional[str] = None
    authMode: Optional[str] = None
    supportsSso: Optional[bool] = None


class JiraIntegrationUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = None
    enabled: Optional[bool] = None
    visibility: Optional[str] = None
    sharedGroupIds: Optional[List[str]] = None
    baseUrl: Optional[str] = None
    email: Optional[str] = None
    apiToken: Optional[str] = None
    bearerToken: Optional[str] = None
    authMode: Optional[str] = None
    supportsSso: Optional[bool] = None


class IncidentJiraCreateRequest(BaseModel):
    integrationId: str
    projectKey: str
    summary: Optional[str] = None
    description: Optional[str] = None
    issueType: Optional[str] = None
    replaceExisting: bool = False


class GroupSharePruneRequest(BaseModel):
    tenant_id: str = Field(..., alias="tenantId")
    group_id: str = Field(..., alias="groupId")
    removed_user_ids: List[str] = Field(default_factory=list, alias="removedUserIds")
    removed_usernames: List[str] = Field(default_factory=list, alias="removedUsernames")
