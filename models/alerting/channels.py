"""
Module defines Pydantic models for notification channel-related data structures used in the API layer.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from enum import Enum

from .silences import Visibility

# Description constants
DESC_UNIQUE_IDENTIFIER = "Unique identifier"
DESC_CHANNEL_NAME = "Channel name"
DESC_CHANNEL_TYPE = "Channel type"
DESC_CHANNEL_ENABLED = "Whether the channel is enabled"
DESC_CHANNEL_SPECIFIC_CONFIG = "Channel-specific configuration"
DESC_GROUP_IDS_CHANNEL_SHARED_WITH = "Group IDs this channel is shared with (when visibility=group)"
DESC_GROUP_IDS_SHARE_WITH = "Group IDs to share with"
DESC_VISIBILITY_SCOPE = "Visibility scope"


class ChannelType(str, Enum):
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    PAGERDUTY = "pagerduty"


class NotificationChannel(BaseModel):
    id: Optional[str] = Field(None, description=DESC_UNIQUE_IDENTIFIER)
    name: str = Field(..., description=DESC_CHANNEL_NAME)
    type: ChannelType = Field(..., description=DESC_CHANNEL_TYPE)
    enabled: bool = Field(True, description=DESC_CHANNEL_ENABLED)
    config: Dict[str, Any] = Field(..., description=DESC_CHANNEL_SPECIFIC_CONFIG)
    created_by: Optional[str] = Field(None, alias="createdBy", description="Owner user id")
    visibility: Visibility = Field(Visibility.PRIVATE, description=DESC_VISIBILITY_SCOPE)  # Using str for now, can import Visibility if needed
    shared_group_ids: List[str] = Field(default_factory=list, alias="sharedGroupIds", description=DESC_GROUP_IDS_CHANNEL_SHARED_WITH)

    class Config:
        use_enum_values = True
        populate_by_name = True


class NotificationChannelCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description=DESC_CHANNEL_NAME)
    type: ChannelType = Field(..., description=DESC_CHANNEL_TYPE)
    enabled: bool = Field(True, description=DESC_CHANNEL_ENABLED)
    config: Dict[str, Any] = Field(..., description=DESC_CHANNEL_SPECIFIC_CONFIG)
    visibility: Visibility = Field(Visibility.PRIVATE, description=DESC_VISIBILITY_SCOPE)
    shared_group_ids: List[str] = Field(default_factory=list, alias="sharedGroupIds", description=DESC_GROUP_IDS_SHARE_WITH)

    class Config:
        use_enum_values = True
        populate_by_name = True
