"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.access.auth_models import Role, TokenData
from services.jira import helpers as jira_helpers


def _user(**kwargs) -> TokenData:
    data = {
        "user_id": "u1",
        "username": "user",
        "tenant_id": "tenant",
        "org_id": "org",
        "role": Role.ADMIN,
        "permissions": ["read:incidents"],
        "group_ids": ["g1"],
        "is_superuser": True,
    }
    data.update(kwargs)
    return TokenData(**data)


def test_find_integration_matches_trimmed_ids(monkeypatch):
    monkeypatch.setattr(jira_helpers, "load_tenant_jira_integrations", lambda _tenant_id: [{"id": " abc "}, {"id": "def"}])
    assert jira_helpers._find_integration("tenant", "abc") == {"id": " abc "}
    assert jira_helpers._find_integration("tenant", "missing") is None


@pytest.mark.asyncio
async def test_jira_projects_and_issue_types_via_integration_paths(monkeypatch):
    current_user = _user()
    integration = {"id": "int-1"}

    monkeypatch.setattr(jira_helpers, "resolve_jira_integration", lambda *_args, **_kwargs: integration)
    monkeypatch.setattr(jira_helpers, "jira_integration_credentials", lambda _integration: {"base_url": "https://tenant.atlassian.net", "auth_mode": "bearer"})
    with pytest.raises(HTTPException) as exc:
        await jira_helpers.jira_projects_via_integration("tenant", "int-1", current_user)
    assert exc.value.status_code == 400

    monkeypatch.setattr(jira_helpers, "jira_integration_credentials", lambda _integration: {"base_url": "https://jira.example.com", "auth_mode": "api_token"})
    monkeypatch.setattr(jira_helpers, "integration_is_usable", lambda _integration: False)
    assert await jira_helpers.jira_projects_via_integration("tenant", "int-1", current_user) == {"enabled": False, "projects": []}
    assert await jira_helpers.jira_issue_types_via_integration("tenant", "int-1", "OPS", current_user) == {"enabled": False, "issueTypes": []}

    monkeypatch.setattr(jira_helpers, "integration_is_usable", lambda _integration: True)

    class JiraBoom(jira_helpers.JiraError):
        pass

    async def fail_projects(**_kwargs):
        raise JiraBoom("upstream failed")

    async def fail_issue_types(**_kwargs):
        raise JiraBoom("issue types failed")

    monkeypatch.setattr(jira_helpers.jira_service, "list_projects", fail_projects)
    with pytest.raises(HTTPException) as exc:
        await jira_helpers.jira_projects_via_integration("tenant", "int-1", current_user)
    assert exc.value.status_code == 502

    monkeypatch.setattr(jira_helpers.jira_service, "list_issue_types", fail_issue_types)
    with pytest.raises(HTTPException) as exc:
        await jira_helpers.jira_issue_types_via_integration("tenant", "int-1", "OPS", current_user)
    assert exc.value.status_code == 502

    async def ok_projects(**_kwargs):
        return [{"key": "OPS"}]

    async def ok_issue_types(**_kwargs):
        return [{"id": "10001", "name": "Bug"}]

    monkeypatch.setattr(jira_helpers.jira_service, "list_projects", ok_projects)
    monkeypatch.setattr(jira_helpers.jira_service, "list_issue_types", ok_issue_types)
    assert await jira_helpers.jira_projects_via_integration("tenant", "int-1", current_user) == {"enabled": True, "projects": [{"key": "OPS"}]}
    assert await jira_helpers.jira_issue_types_via_integration("tenant", "int-1", "OPS", current_user) == {"enabled": True, "issueTypes": [{"id": "10001", "name": "Bug"}]}


def test_resolve_incident_jira_credentials_paths(monkeypatch):
    current_user = _user()
    incident = SimpleNamespace(jira_integration_id="int-1")

    monkeypatch.setattr(jira_helpers, "resolve_jira_integration", lambda *_args, **_kwargs: {"id": "int-1"})
    monkeypatch.setattr(jira_helpers, "integration_is_usable", lambda _integration: True)
    monkeypatch.setattr(jira_helpers, "jira_integration_credentials", lambda _integration: {"base_url": "https://jira.example.com", "token": "abc"})
    assert jira_helpers.resolve_incident_jira_credentials(incident, "tenant", current_user) == {
        "base_url": "https://jira.example.com",
        "token": "abc",
    }

    monkeypatch.setattr(jira_helpers, "resolve_jira_integration", lambda *_args, **_kwargs: (_ for _ in ()).throw(HTTPException(status_code=403, detail="forbidden")))
    monkeypatch.setattr(jira_helpers, "_find_integration", lambda *_args: None)
    assert jira_helpers.resolve_incident_jira_credentials(incident, "tenant", current_user) is None

    monkeypatch.setattr(jira_helpers, "_find_integration", lambda *_args: {"id": "int-1"})
    monkeypatch.setattr(jira_helpers, "integration_is_usable", lambda _integration: False)
    assert jira_helpers.resolve_incident_jira_credentials(incident, "tenant", current_user) is None

    monkeypatch.setattr(jira_helpers, "integration_is_usable", lambda _integration: True)
    monkeypatch.setattr(jira_helpers, "jira_integration_credentials", lambda _integration: (_ for _ in ()).throw(ValueError("bad")))
    assert jira_helpers.resolve_incident_jira_credentials(incident, "tenant", current_user) is None

    no_link_incident = SimpleNamespace(jira_integration_id="")
    monkeypatch.setattr(jira_helpers, "jira_is_enabled_for_tenant", lambda _tenant_id: False)
    assert jira_helpers.resolve_incident_jira_credentials(no_link_incident, "tenant", current_user) is None

    monkeypatch.setattr(jira_helpers, "jira_is_enabled_for_tenant", lambda _tenant_id: True)
    monkeypatch.setattr(jira_helpers, "get_effective_jira_credentials", lambda _tenant_id: {"base_url": "https://jira.example.com", "email": "user@example.com"})
    assert jira_helpers.resolve_incident_jira_credentials(no_link_incident, "tenant", current_user) == {
        "base_url": "https://jira.example.com",
        "email": "user@example.com",
    }

    monkeypatch.setattr(jira_helpers, "get_effective_jira_credentials", lambda _tenant_id: (_ for _ in ()).throw(TypeError("bad")))
    assert jira_helpers.resolve_incident_jira_credentials(no_link_incident, "tenant", current_user) is None