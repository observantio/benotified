"""
Module defines Pydantic models for alerting-related data structures used in the API layer.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from enum import Enum

from .silences import Visibility


DESC_UNIQUE_IDENTIFIER = "Unique identifier"
DESC_RULE_NAME = "Rule name"
DESC_RULE_EXPRESSION = "Prometheus expression for the alert rule"
DESC_RULE_SEVERITY = "Severity level of the alert rule"
DESC_RULE_DESCRIPTION = "Description of the alert rule"
DESC_RULE_ENABLED = "Whether the rule is enabled"
DESC_RULE_LABELS = "Labels to add to alerts from this rule"
DESC_RULE_ANNOTATIONS = "Annotations to add to alerts from this rule"
DESC_RULE_FOR_DURATION = "Duration to wait before firing the alert"
DESC_RULE_GROUP_NAME = "Name of the rule group this rule belongs to"
DESC_RULE_GROUP_INTERVAL = "Interval between evaluations of this rule group"
DESC_RULE_GROUP_RULES = "Rules in this group"
DESC_VISIBILITY_SCOPE = "Visibility scope"
DESC_GROUP_IDS_RULE_SHARED_WITH = "Group IDs this rule is shared with (when visibility=group)"
DESC_GROUP_IDS_SHARE_WITH = "Group IDs to share with"


class RuleSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertRule(BaseModel):
    id: Optional[str] = Field(None, description=DESC_UNIQUE_IDENTIFIER)
    org_id: Optional[str] = Field(None, alias="orgId", description="Organization ID / API key scoped to this rule")
    name: str = Field(..., description=DESC_RULE_NAME)
    expr: str = Field(..., alias="expression", description=DESC_RULE_EXPRESSION)
    severity: RuleSeverity = Field(..., description=DESC_RULE_SEVERITY)
    description: Optional[str] = Field(None, description=DESC_RULE_DESCRIPTION)
    enabled: bool = Field(True, description=DESC_RULE_ENABLED)
    labels: Dict[str, str] = Field(default_factory=dict, description=DESC_RULE_LABELS)
    annotations: Dict[str, str] = Field(default_factory=dict, description=DESC_RULE_ANNOTATIONS)
    duration: Optional[str] = Field(None, alias="for", description=DESC_RULE_FOR_DURATION)
    group: str = Field(..., alias="groupName", description=DESC_RULE_GROUP_NAME)
    group_interval: Optional[str] = Field(None, alias="groupInterval", description=DESC_RULE_GROUP_INTERVAL)
    notification_channels: List[str] = Field(default_factory=list, alias="notificationChannels", description="Notification channel IDs for this rule")
    visibility: Visibility = Field(Visibility.PRIVATE, description=DESC_VISIBILITY_SCOPE)
    shared_group_ids: List[str] = Field(default_factory=list, alias="sharedGroupIds", description=DESC_GROUP_IDS_RULE_SHARED_WITH)
    model_config = ConfigDict(use_enum_values=True, populate_by_name=True)


class AlertRuleCreate(BaseModel):
    org_id: Optional[str] = Field(None, alias="orgId", description="Optional org_id (API key) to scope this rule to")
    name: str = Field(..., min_length=1, max_length=100, description=DESC_RULE_NAME)
    expr: str = Field(..., alias="expression", description=DESC_RULE_EXPRESSION)
    severity: RuleSeverity = Field(..., description=DESC_RULE_SEVERITY)
    description: Optional[str] = Field(None, description=DESC_RULE_DESCRIPTION)
    enabled: bool = Field(True, description=DESC_RULE_ENABLED)
    labels: Dict[str, str] = Field(default_factory=dict, description=DESC_RULE_LABELS)
    annotations: Dict[str, str] = Field(default_factory=dict, description=DESC_RULE_ANNOTATIONS)
    duration: Optional[str] = Field(None, alias="for", description=DESC_RULE_FOR_DURATION)
    group: str = Field(..., alias="groupName", description=DESC_RULE_GROUP_NAME)
    group_interval: Optional[str] = Field(None, alias="groupInterval", description=DESC_RULE_GROUP_INTERVAL)
    notification_channels: List[str] = Field(default_factory=list, alias="notificationChannels", description="Notification channel IDs for this rule")
    visibility: Visibility = Field(Visibility.PRIVATE, description=DESC_VISIBILITY_SCOPE)
    shared_group_ids: List[str] = Field(default_factory=list, alias="sharedGroupIds", description=DESC_GROUP_IDS_SHARE_WITH)
    model_config = ConfigDict(use_enum_values=True, populate_by_name=True)


class RuleGroup(BaseModel):
    name: str = Field(..., description=DESC_RULE_GROUP_NAME)
    interval: Optional[str] = Field(None, description=DESC_RULE_GROUP_INTERVAL)
    rules: List[AlertRule] = Field(default_factory=list, description=DESC_RULE_GROUP_RULES)
