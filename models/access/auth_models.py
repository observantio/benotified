"""
This module defines Pydantic models for authentication and authorization data structures used in the API layer.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""
from enum import Enum
from typing import List
from pydantic import BaseModel, Field

class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"

class Permission(str, Enum):
    READ_AUDIT_LOGS = "read:audit_logs"
    READ_ALERTS = "read:alerts"
    CREATE_ALERTS = "create:alerts"
    UPDATE_ALERTS = "update:alerts"
    WRITE_ALERTS = "write:alerts"
    DELETE_ALERTS = "delete:alerts"
    READ_SILENCES = "read:silences"
    CREATE_SILENCES = "create:silences"
    UPDATE_SILENCES = "update:silences"
    DELETE_SILENCES = "delete:silences"
    READ_RULES = "read:rules"
    CREATE_RULES = "create:rules"
    UPDATE_RULES = "update:rules"
    DELETE_RULES = "delete:rules"
    TEST_RULES = "test:rules"
    READ_METRICS = "read:metrics"
    READ_CHANNELS = "read:channels"
    CREATE_CHANNELS = "create:channels"
    UPDATE_CHANNELS = "update:channels"
    WRITE_CHANNELS = "write:channels"
    DELETE_CHANNELS = "delete:channels"
    TEST_CHANNELS = "test:channels"
    READ_INCIDENTS = "read:incidents"
    UPDATE_INCIDENTS = "update:incidents"
    READ_LOGS = "read:logs"
    READ_TRACES = "read:traces"
    READ_DASHBOARDS = "read:dashboards"
    CREATE_DASHBOARDS = "create:dashboards"
    UPDATE_DASHBOARDS = "update:dashboards"
    WRITE_DASHBOARDS = "write:dashboards"
    DELETE_DASHBOARDS = "delete:dashboards"
    READ_DATASOURCES = "read:datasources"
    CREATE_DATASOURCES = "create:datasources"
    UPDATE_DATASOURCES = "update:datasources"
    DELETE_DATASOURCES = "delete:datasources"
    QUERY_DATASOURCES = "query:datasources"
    READ_FOLDERS = "read:folders"
    CREATE_FOLDERS = "create:folders"
    DELETE_FOLDERS = "delete:folders"
    READ_AGENTS = "read:agents"
    READ_API_KEYS = "read:api_keys"
    CREATE_API_KEYS = "create:api_keys"
    UPDATE_API_KEYS = "update:api_keys"
    DELETE_API_KEYS = "delete:api_keys"
    CREATE_USERS = "create:users"
    UPDATE_USERS = "update:users"
    DELETE_USERS = "delete:users"
    UPDATE_USER_PERMISSIONS = "update:user_permissions"
    MANAGE_USERS = "manage:users"
    READ_USERS = "read:users"
    CREATE_GROUPS = "create:groups"
    UPDATE_GROUPS = "update:groups"
    DELETE_GROUPS = "delete:groups"
    UPDATE_GROUP_PERMISSIONS = "update:group_permissions"
    UPDATE_GROUP_MEMBERS = "update:group_members"
    MANAGE_GROUPS = "manage:groups"
    READ_GROUPS = "read:groups"
    MANAGE_TENANTS = "manage:tenants"


ROLE_PERMISSIONS = {
    Role.ADMIN: list(Permission),
    Role.USER: [
        Permission.READ_API_KEYS,
        Permission.CREATE_API_KEYS,
        Permission.UPDATE_API_KEYS,
        Permission.DELETE_API_KEYS,
        Permission.READ_ALERTS,
        Permission.READ_SILENCES,
        Permission.READ_RULES,
        Permission.READ_CHANNELS,
        Permission.READ_INCIDENTS,
        Permission.UPDATE_INCIDENTS,
        Permission.READ_LOGS,
        Permission.READ_TRACES,
        Permission.READ_DASHBOARDS,
        Permission.READ_DATASOURCES,
        Permission.QUERY_DATASOURCES,
        Permission.READ_FOLDERS,
        Permission.READ_AGENTS,
        Permission.READ_USERS,
        Permission.READ_GROUPS,
    ],
    Role.VIEWER: []
}


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    user_id: str
    username: str
    tenant_id: str
    org_id: str
    role: Role
    is_superuser: bool = False
    permissions: List[str]
    group_ids: List[str] = Field(default_factory=list)
    is_mfa_setup: bool = False  


class OIDCAuthURLRequest(BaseModel):
    redirect_uri: str
    state: str
    nonce: str


class OIDCCodeExchangeRequest(BaseModel):
    code: str
    redirect_uri: str


class OIDCAuthURLResponse(BaseModel):
    authorization_url: str


class AuthModeResponse(BaseModel):
    provider: str
    oidc_enabled: bool
    password_enabled: bool
    registration_enabled: bool
    oidc_scopes: str
