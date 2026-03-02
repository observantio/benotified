"""
Module defines Pydantic models for alerting-related data structures used in the API layer.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from typing import Dict, List, Any
from pydantic import BaseModel, ConfigDict, Field

DESC_RECEIVER_NAME = "Receiver name"
DESC_RECEIVER_EMAIL_CONFIGS = "Email configurations for this receiver"
DESC_RECEIVER_SLACK_CONFIGS = "Slack configurations for this receiver"
DESC_RECEIVER_WEBHOOK_CONFIGS = "Webhook configurations for this receiver"
DESC_RECEIVER_PAGERDUTY_CONFIGS = "PagerDuty configurations for this receiver"
DESC_RECEIVER_TEAMS_CONFIGS = "Teams configurations for this receiver"
DESC_ALERTMANAGER_VERSION = "AlertManager version"
DESC_ALERTMANAGER_UPTIME = "AlertManager uptime"
DESC_ALERTMANAGER_CONFIG_HASH = "Configuration hash"
DESC_ALERTMANAGER_CLUSTER_STATUS = "Cluster status information"

class Receiver(BaseModel):
    name: str = Field(..., description=DESC_RECEIVER_NAME)
    email_configs: List[Dict[str, Any]] = Field(default_factory=list, alias="emailConfigs", description=DESC_RECEIVER_EMAIL_CONFIGS)
    slack_configs: List[Dict[str, Any]] = Field(default_factory=list, alias="slackConfigs", description=DESC_RECEIVER_SLACK_CONFIGS)
    webhook_configs: List[Dict[str, Any]] = Field(default_factory=list, alias="webhookConfigs", description=DESC_RECEIVER_WEBHOOK_CONFIGS)
    pagerduty_configs: List[Dict[str, Any]] = Field(default_factory=list, alias="pagerdutyConfigs", description=DESC_RECEIVER_PAGERDUTY_CONFIGS)
    msteams_configs: List[Dict[str, Any]] = Field(default_factory=list, alias="msteamsConfigs", description=DESC_RECEIVER_TEAMS_CONFIGS)
    model_config = ConfigDict(use_enum_values=True, populate_by_name=True)


class AlertManagerStatus(BaseModel):
    version: str = Field(..., description=DESC_ALERTMANAGER_VERSION)
    uptime: str = Field(..., description=DESC_ALERTMANAGER_UPTIME)
    config_hash: str = Field(..., alias="configHash", description=DESC_ALERTMANAGER_CONFIG_HASH)
    cluster: Dict[str, Any] = Field(..., description=DESC_ALERTMANAGER_CLUSTER_STATUS)
    model_config = ConfigDict(use_enum_values=True, populate_by_name=True)
