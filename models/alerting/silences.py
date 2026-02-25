"""
Module defines Pydantic models for alerting-related data structures used in the API layer.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from enum import Enum

from config import config

# Description constants
DESC_LABEL_NAME_MATCH = "Label name to match"
DESC_VALUE_MATCH_AGAINST = "Value to match against"
DESC_VALUE_IS_REGEX = "Whether the value is a regular expression"
DESC_MATCH_EQUAL_VALUES = "Whether to match equal values"
DESC_UNIQUE_IDENTIFIER_SILENCE = "Unique identifier for the silence"
DESC_MATCHERS_DEFINE_SILENCE = "Matchers that define which alerts to silence"
DESC_TIME_SILENCE_STARTS = "Time when the silence starts"
DESC_TIME_SILENCE_ENDS = "Time when the silence ends"
DESC_USER_CREATED_SILENCE = "User who created the silence"
DESC_COMMENT_EXPLAINING_SILENCE = "Comment explaining the silence"
DESC_CURRENT_STATUS_SILENCE = "Current status of the silence"
DESC_VISIBILITY_SCOPE = "Visibility scope"
DESC_GROUP_IDS_SILENCE_SHARED_WITH = "Group IDs this silence is shared with"
DESC_GROUP_IDS_SHARE_WITH = "Group IDs to share with"


class Visibility(str, Enum):
    PRIVATE = "private"  # Only visible to creator
    GROUP = "group"      # Visible to specified groups
    TENANT = "tenant"    # Visible to all users in tenant
    PUBLIC = "public"    # Visible to everyone


class Matcher(BaseModel):
    name: str = Field(..., description=DESC_LABEL_NAME_MATCH)
    value: str = Field(..., description=DESC_VALUE_MATCH_AGAINST)
    is_regex: bool = Field(False, alias="isRegex", description=DESC_VALUE_IS_REGEX)
    is_equal: bool = Field(True, alias="isEqual", description=DESC_MATCH_EQUAL_VALUES)

    class Config:
        populate_by_name = True


class Silence(BaseModel):
    id: Optional[str] = Field(None, description=DESC_UNIQUE_IDENTIFIER_SILENCE)
    matchers: List[Matcher] = Field(..., description=DESC_MATCHERS_DEFINE_SILENCE)
    starts_at: str = Field(..., alias="startsAt", description=DESC_TIME_SILENCE_STARTS)
    ends_at: str = Field(..., alias="endsAt", description=DESC_TIME_SILENCE_ENDS)
    created_by: str = Field(..., alias="createdBy", description=DESC_USER_CREATED_SILENCE)
    comment: str = Field(..., description=DESC_COMMENT_EXPLAINING_SILENCE)
    status: Optional[Dict[str, str]] = Field(None, description=DESC_CURRENT_STATUS_SILENCE)
    visibility: Optional[Visibility] = Field(None, description=DESC_VISIBILITY_SCOPE)
    shared_group_ids: List[str] = Field(default_factory=list, alias="sharedGroupIds", description=DESC_GROUP_IDS_SILENCE_SHARED_WITH)

    class Config:
        populate_by_name = True
        use_enum_values = True


class SilenceCreate(BaseModel):
    matchers: List[Matcher] = Field(..., description=DESC_MATCHERS_DEFINE_SILENCE)
    starts_at: str = Field(..., alias="startsAt", description=DESC_TIME_SILENCE_STARTS)
    ends_at: str = Field(..., alias="endsAt", description=DESC_TIME_SILENCE_ENDS)
    created_by: str = Field(..., alias="createdBy", description=DESC_USER_CREATED_SILENCE)
    comment: str = Field(..., description=DESC_COMMENT_EXPLAINING_SILENCE)

    class Config:
        populate_by_name = True


class SilenceCreateRequest(BaseModel):
    matchers: List[Matcher] = Field(..., description=DESC_MATCHERS_DEFINE_SILENCE)
    starts_at: str = Field(..., alias="startsAt", description=DESC_TIME_SILENCE_STARTS)
    ends_at: str = Field(..., alias="endsAt", description=DESC_TIME_SILENCE_ENDS)
    comment: str = Field(..., description=DESC_COMMENT_EXPLAINING_SILENCE)
    visibility: Visibility = Field(Visibility.PRIVATE, description=DESC_VISIBILITY_SCOPE)
    shared_group_ids: List[str] = Field(default_factory=list, alias="sharedGroupIds", description=DESC_GROUP_IDS_SHARE_WITH)

    class Config:
        populate_by_name = True
        use_enum_values = True
