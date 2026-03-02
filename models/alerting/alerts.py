"""
Module defines Pydantic models for alerting-related data structures used in the API layer.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, ConfigDict, Field
from enum import Enum

DESC_CURRENT_STATE_ALERT = "Current state of the alert"
DESC_LIST_SILENCES_SILENCE_ALERT = "List of silences that silence this alert"
DESC_LIST_ALERTS_INHIBIT_ALERT = "List of alerts that inhibit this alert"
DESC_KEY_VALUE_PAIRS_IDENTIFY_ALERT = "Key-value pairs that identify the alert"
DESC_ADDITIONAL_INFO_ALERT = "Additional information about the alert"
DESC_TIME_ALERT_STARTED_FIRING = "Time when the alert started firing"
DESC_TIME_ALERT_STOPPED_FIRING = "Time when the alert stopped firing"
DESC_URL_ALERT_GENERATOR = "URL of the alert generator"
DESC_CURRENT_STATUS_ALERT = "Current status of the alert"
DESC_LIST_RECEIVERS_ALERT = "List of receivers for this alert"
DESC_UNIQUE_IDENTIFIER_ALERT = "Unique identifier for the alert"
DESC_COMMON_LABELS_GROUP = "Common labels for the group"
DESC_RECEIVER_HANDLE_ALERTS = "Receiver that will handle these alerts"
DESC_LIST_ALERTS_GROUP = "List of alerts in this group"

class AlertState(str, Enum):
    UNPROCESSED = "unprocessed"
    ACTIVE = "active"
    SUPPRESSED = "suppressed"


class AlertStatus(BaseModel):
    state: AlertState = Field(..., description=DESC_CURRENT_STATE_ALERT)
    silenced_by: List[str] = Field(default_factory=list, alias="silencedBy", description=DESC_LIST_SILENCES_SILENCE_ALERT)
    inhibited_by: List[str] = Field(default_factory=list, alias="inhibitedBy", description=DESC_LIST_ALERTS_INHIBIT_ALERT)

    model_config = ConfigDict(populate_by_name=True)


class Alert(BaseModel):
    labels: Dict[str, str] = Field(..., description=DESC_KEY_VALUE_PAIRS_IDENTIFY_ALERT)
    annotations: Dict[str, str] = Field(default_factory=dict, description=DESC_ADDITIONAL_INFO_ALERT)
    starts_at: str = Field(..., alias="startsAt", description=DESC_TIME_ALERT_STARTED_FIRING)
    ends_at: Optional[str] = Field(None, alias="endsAt", description=DESC_TIME_ALERT_STOPPED_FIRING)
    generator_url: Optional[str] = Field(None, alias="generatorURL", description=DESC_URL_ALERT_GENERATOR)
    status: AlertStatus = Field(..., description=DESC_CURRENT_STATUS_ALERT)
    receivers: Optional[List[Union[str, Dict[str, Any]]]] = Field(default_factory=list, description=DESC_LIST_RECEIVERS_ALERT)
    fingerprint: Optional[str] = Field(None, description=DESC_UNIQUE_IDENTIFIER_ALERT)

    model_config = ConfigDict(populate_by_name=True)


class AlertGroup(BaseModel):
    labels: Dict[str, str] = Field(..., description=DESC_COMMON_LABELS_GROUP)
    receiver: str = Field(..., description=DESC_RECEIVER_HANDLE_ALERTS)
    alerts: List[Alert] = Field(..., description=DESC_LIST_ALERTS_GROUP)
