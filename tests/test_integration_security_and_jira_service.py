"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.access.auth_models import Role, TokenData
from services.alerting import integration_security_service as sec_mod
from services.jira_service import JiraError, JiraService, _extract_display_name


class FakeQuery:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *_args, **_kwargs):
        return self

    def filter_by(self, **_kwargs):
        return self

    def first(self):
        if isinstance(self.rows, list):
            return self.rows[0] if self.rows else None
        return self.rows

    def all(self):
        if self.rows is None:
            return []
        if isinstance(self.rows, list):
            return self.rows
        return [self.rows]


class FakeDB:
    def __init__(self, *results):
        self.results = list(results)
        self.executed = []
        self.flushed = 0

    def execute(self, stmt):
        self.executed.append(stmt)

    def query(self, *_args, **_kwargs):
        rows = self.results.pop(0) if self.results else None
        return FakeQuery(rows)

    def flush(self):
        self.flushed += 1


class FakeCtx:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        return self.db

    def __exit__(self, exc_type, exc, tb):
        return False


def _user(**kwargs) -> TokenData:
    payload = {
        "user_id": "u1",
        "username": "user",
        "tenant_id": "tenant-a",
        "org_id": "org-a",
        "role": Role.USER,
        "permissions": ["read:alerts"],
        "group_ids": ["g1"],
        "is_superuser": False,
    }
    payload.update(kwargs)
    return TokenData(**payload)


def test_integration_security_core_helpers(monkeypatch):
    tenant = SimpleNamespace(settings={"jira": {"enabled": True}})
    changed = []
    monkeypatch.setattr(sec_mod, "flag_modified", lambda obj, name: changed.append((obj, name)))

    assert sec_mod._normalized_id(" x ") == "x"
    assert sec_mod._normalized_id_list(["a", " ", None, "b"]) == ["a", "b"]
    assert sec_mod._current_user_id(_user()) == "u1"
    assert sec_mod._tenant_settings_copy(tenant) == {"jira": {"enabled": True}}
    sec_mod._persist_tenant_settings(tenant, {"x": 1})
    assert tenant.settings == {"x": 1}
    assert changed[-1][1] == "settings"
    assert sec_mod._optional_string("  x ") == "x"
    assert sec_mod._optional_string(None) is None


def test_tenant_resolution_and_inference(monkeypatch):
    monkeypatch.setattr(sec_mod.config, "DEFAULT_ADMIN_TENANT", "admin")
    monkeypatch.setattr(sec_mod.config, "DEFAULT_ORG_ID", "default-org")

    db = FakeDB(SimpleNamespace(id="admin-id"))
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: FakeCtx(db))
    assert sec_mod.ensure_default_tenant(db) == "admin-id"
    assert db.executed

    db = FakeDB(SimpleNamespace(id="admin-id"))
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: FakeCtx(db))
    assert sec_mod.tenant_id_from_scope_header(None) == "admin-id"

    db = FakeDB(SimpleNamespace(id="tenant-id"))
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: FakeCtx(db))
    assert sec_mod.tenant_id_from_scope_header("tenant-id|extra") == "tenant-id"

    db = FakeDB(None, SimpleNamespace(id="tenant-by-name"))
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: FakeCtx(db))
    assert sec_mod.tenant_id_from_scope_header("tenant-name") == "tenant-by-name"

    db = FakeDB(None, None)
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: FakeCtx(db))
    with pytest.raises(HTTPException) as exc:
        sec_mod.tenant_id_from_scope_header("missing")
    assert exc.value.status_code == 403

    assert sec_mod._alert_label_value({"a": "1", "b": "2"}, "x", "b") == "2"

    monkeypatch.setattr(sec_mod, "tenant_id_from_scope_header", lambda header: "base-tenant")
    assert sec_mod.infer_tenant_id_from_alerts("explicit", []) == "base-tenant"

    db = FakeDB([("tenant-a",)], [("tenant-b",), ("tenant-c",)])
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: FakeCtx(db))
    alerts = [{"labels": {"alertname": "CPUHigh", "org_id": "org-a"}}]
    assert sec_mod.infer_tenant_id_from_alerts(None, alerts) == "tenant-a"

    db = FakeDB([("tenant-a",), ("tenant-b",)])
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: FakeCtx(db))
    alerts = [{"labels": {"alertname": "CPUHigh"}}]
    assert sec_mod.infer_tenant_id_from_alerts(None, alerts) == "base-tenant"


def test_secret_storage_config_and_visibility_helpers(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setattr(sec_mod, "is_safe_http_url", lambda url: bool(url and str(url).startswith("https://")))
    monkeypatch.setattr(sec_mod, "flag_modified", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sec_mod.config, "DATA_ENCRYPTION_KEY", key)
    encrypted = sec_mod.encrypt_tenant_secret("secret")
    assert encrypted and encrypted.startswith("enc:")
    assert sec_mod.decrypt_tenant_secret(encrypted) == "secret"
    assert sec_mod.decrypt_tenant_secret("plain") == "plain"
    monkeypatch.setattr(sec_mod.config, "DATA_ENCRYPTION_KEY", None)
    with pytest.raises(HTTPException):
        sec_mod.encrypt_tenant_secret("secret")
    assert sec_mod.decrypt_tenant_secret(encrypted) is None

    tenant = SimpleNamespace(settings={"jira": {"enabled": True, "base_url": "https://jira", "email": "a@b.c", "api_token": encrypted, "bearer": None}})
    db = FakeDB(tenant)
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: FakeCtx(db))
    monkeypatch.setattr(sec_mod.config, "DATA_ENCRYPTION_KEY", key)
    loaded = sec_mod.load_tenant_jira_config("tenant-a")
    assert loaded["api_token"] == "secret"

    tenant = SimpleNamespace(settings={})
    db = FakeDB(tenant)
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: FakeCtx(db))
    result = sec_mod.save_tenant_jira_config("tenant-a", enabled=True, base_url="https://jira", email="a@b.c", api_token="secret", bearer=None)
    assert result["hasApiToken"] is True
    assert db.flushed == 1

    db = FakeDB(None)
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: FakeCtx(db))
    with pytest.raises(HTTPException):
        sec_mod.save_tenant_jira_config("missing", enabled=False, base_url=None, email=None, api_token=None, bearer=None)

    monkeypatch.setattr(sec_mod, "load_tenant_jira_config", lambda tenant_id: {"enabled": True, "base_url": "https://jira", "email": "a@b.c", "api_token": "tok", "bearer": None})
    creds = sec_mod.get_effective_jira_credentials("tenant-a")
    assert creds["base_url"] == "https://jira"
    assert sec_mod.jira_is_enabled_for_tenant("tenant-a") is True
    assert sec_mod.allowed_channel_types() == [t.lower() for t in (sec_mod.config.ENABLED_NOTIFICATION_CHANNEL_TYPES or [])]
    assert sec_mod.normalize_visibility("public") == "tenant"

    monkeypatch.setattr(sec_mod, "os", SimpleNamespace(getenv=lambda name, default=None: {"AUTH_PROVIDER": "oidc", "OIDC_ISSUER_URL": "https://issuer", "OIDC_CLIENT_ID": "client"}.get(name, default)))
    monkeypatch.setattr(sec_mod.config, "AUTH_PROVIDER", "oidc", raising=False)
    monkeypatch.setattr(sec_mod.config, "OIDC_ISSUER_URL", "https://issuer", raising=False)
    monkeypatch.setattr(sec_mod.config, "OIDC_CLIENT_ID", "client", raising=False)
    assert sec_mod.is_jira_sso_available() is True
    assert sec_mod.normalize_jira_auth_mode("api_token") == "api_token"
    assert sec_mod.normalize_jira_auth_mode("bearer") == "bearer"
    assert sec_mod.normalize_jira_auth_mode("sso") == "sso"
    with pytest.raises(HTTPException):
        sec_mod.normalize_jira_auth_mode("bad")


def test_integration_validation_access_and_masking(monkeypatch):
    monkeypatch.setattr(sec_mod, "is_safe_http_url", lambda url: bool(url and str(url).startswith("https://")))
    monkeypatch.setattr(sec_mod, "flag_modified", lambda *_args, **_kwargs: None)
    sec_mod.validate_jira_credentials(base_url="https://jira", auth_mode="api_token", email="a@b.c", api_token="tok", bearer_token=None)
    sec_mod.validate_jira_credentials(base_url="https://jira.local", auth_mode="bearer", email=None, api_token=None, bearer_token="bear")
    with pytest.raises(HTTPException):
        sec_mod.validate_jira_credentials(base_url="https://foo.atlassian.net", auth_mode="bearer", email=None, api_token=None, bearer_token="bear")
    with pytest.raises(HTTPException):
        sec_mod.validate_jira_credentials(base_url="https://jira", auth_mode="api_token", email=None, api_token="tok", bearer_token=None)

    items = [{"id": "i1"}, "bad"]
    tenant = SimpleNamespace(settings={"jira_integrations": items})
    db = FakeDB(tenant)
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: FakeCtx(db))
    assert sec_mod.load_tenant_jira_integrations("tenant-a") == [{"id": "i1"}]

    tenant = SimpleNamespace(settings={})
    db = FakeDB(tenant)
    monkeypatch.setattr(sec_mod, "get_db_session", lambda: FakeCtx(db))
    sec_mod.save_tenant_jira_integrations("tenant-a", [{"id": "i1"}])
    assert tenant.settings["jira_integrations"] == [{"id": "i1"}]

    with pytest.raises(HTTPException):
        sec_mod.validate_shared_group_ids_for_user("tenant-a", ["g2"], _user())
    assert sec_mod.validate_shared_group_ids_for_user("tenant-a", ["g1", ""], _user()) == ["g1"]
    assert sec_mod.validate_shared_group_ids_for_user("tenant-a", ["g9"], _user(role=Role.ADMIN)) == ["g9"]

    item = {"createdBy": "u2", "visibility": "group", "sharedGroupIds": ["g1"]}
    assert sec_mod.jira_integration_has_access(item, _user()) is True
    assert sec_mod.jira_integration_has_access(item, _user(), write=True) is False
    assert sec_mod.jira_integration_has_access({"createdBy": "u1"}, _user(), write=True) is True
    assert sec_mod.jira_integration_has_access({"createdBy": "u2", "visibility": "tenant"}, _user()) is True

    masked_owner = sec_mod.mask_jira_integration({"id": "i1", "name": "Jira", "createdBy": "u1", "baseUrl": "https://jira", "email": "a@b.c", "apiToken": "enc", "authMode": "api_token", "sharedGroupIds": ["g1"]}, _user())
    masked_other = sec_mod.mask_jira_integration({"id": "i1", "createdBy": "u2", "baseUrl": "https://jira", "email": "a@b.c"}, _user())
    assert masked_owner["baseUrl"] == "https://jira"
    assert masked_other["baseUrl"] is None

    monkeypatch.setattr(sec_mod, "load_tenant_jira_integrations", lambda tenant_id: [{"id": "i1", "createdBy": "u1"}])
    assert sec_mod.resolve_jira_integration("tenant-a", "i1", _user())["id"] == "i1"
    with pytest.raises(HTTPException):
        sec_mod.resolve_jira_integration("tenant-a", "missing", _user())

    monkeypatch.setattr(sec_mod, "decrypt_tenant_secret", lambda value: "secret" if value else None)
    monkeypatch.setattr(sec_mod, "normalize_jira_auth_mode", lambda value: str(value or "api_token"))
    creds = sec_mod.jira_integration_credentials({"authMode": "api_token", "baseUrl": "https://jira", "email": "a@b.c", "apiToken": "enc"})
    assert creds["api_token"] == "secret"
    monkeypatch.setattr(sec_mod, "is_safe_http_url", lambda url: bool(url and url.startswith("https://")))
    assert sec_mod.integration_is_usable({"enabled": True, "authMode": "api_token", "baseUrl": "https://jira", "email": "a@b.c", "apiToken": "enc"}) is True
    assert sec_mod.integration_is_usable({"enabled": False}) is False


class DummyResponse:
    def __init__(self, status_code=200, *, payload=None, text="", content=b"{}"):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text
        self.content = content

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("bad", request=httpx.Request("GET", "https://jira"), response=httpx.Response(self.status_code, request=httpx.Request("GET", "https://jira"), text=self.text))


@pytest.mark.asyncio
async def test_jira_service_auth_headers_and_request_paths(monkeypatch):
    service = JiraService(timeout=1)
    service.base_url = "https://jira"
    service.email = "a@b.c"
    service.api_token = "tok"
    service.bearer = "bear"

    assert service._resolve_base_url({"baseUrl": "https://jira.local/"}) == "https://jira.local"
    assert service._auth_headers({"authMode": "bearer", "bearer": "abc"})["Authorization"] == "Bearer abc"
    assert service._auth_headers({"authMode": "sso", "bearer": "abc"})["Authorization"] == "Bearer abc"
    assert service._auth_headers({"authMode": "api_token", "email": "a@b.c", "api_token": "tok"})["Authorization"].startswith("Basic ")
    service.email = None
    service.api_token = None
    service.bearer = None
    with pytest.raises(JiraError):
        service._auth_headers({"authMode": "api_token", "email": None, "api_token": None})
    assert service._headers({"authMode": "bearer", "bearer": "abc"})["Content-Type"] == "application/json"
    monkeypatch.setattr("services.jira_service.is_safe_http_url", lambda url: True)
    assert service._build_url("/rest/api/2/project", {"base_url": "https://jira"}) == "https://jira/rest/api/2/project"

    monkeypatch.setattr("services.jira_service.is_safe_http_url", lambda url: bool(url and url.startswith("https://")))

    class Client:
        async def get(self, url, headers=None, params=None):
            return DummyResponse(payload=[{"key": "OPS", "name": "Ops"}], content=b"[]")

        async def post(self, url, json=None, headers=None):
            return DummyResponse(payload={"key": "OPS-1"}, content=b"{}")

    service._client = Client()
    assert await service._get("/rest/api/2/project", {"base_url": "https://jira", "authMode": "bearer", "bearer": "abc"}) == [{"key": "OPS", "name": "Ops"}]
    assert (await service._post("/rest/api/2/issue", {"x": 1}, {"base_url": "https://jira", "authMode": "bearer", "bearer": "abc"})) == {"key": "OPS-1"}
    created = await service.create_issue("OPS", "Summary", "Desc", credentials={"base_url": "https://jira", "authMode": "bearer", "bearer": "abc"})
    assert created["key"] == "OPS-1"


@pytest.mark.asyncio
async def test_jira_service_higher_level_helpers_and_errors(monkeypatch):
    service = JiraService(timeout=1)
    monkeypatch.setattr("services.jira_service.is_safe_http_url", lambda url: bool(url and url.startswith("https://")))
    service.base_url = "https://jira"

    async def fake_get(path, credentials=None, params=None):
        if path == "/rest/api/2/project":
            return [{"key": "OPS", "name": "Ops"}, {"bad": True}]
        if path == "/rest/api/2/project/OPS":
            return {"issueTypes": [{"name": "Task"}, {"name": "Bug"}, {"x": 1}]}
        if path.endswith("/transitions"):
            return {"transitions": [{"id": "1", "name": "Done", "to": {"name": "Done", "statusCategory": {"key": "done"}}}]}
        if path.endswith("/comment"):
            return {"comments": [{"id": 1, "author": {"displayName": "Alice"}, "body": "Hi", "created": "now"}]}
        return {}

    async def fake_post(path, payload, credentials=None):
        return {"ok": True}

    service._get = fake_get
    service._post = fake_post
    assert await service.list_projects() == [{"key": "OPS", "name": "Ops"}]
    assert await service.list_issue_types("OPS") == ["Task", "Bug"]
    assert await service.list_transitions("OPS-1") == [{"id": "1", "name": "Done", "to": {"name": "Done", "statusCategory": {"key": "done"}}}]
    assert await service.transition_issue("OPS-1", "1") == {"ok": True}
    assert await service.transition_issue_to_done("OPS-1") is True
    assert await service.transition_issue_to_todo("OPS-1") is False
    assert await service.transition_issue_to_in_progress("OPS-1") is False
    assert await service.add_comment("OPS-1", "hello") == {"ok": True}
    assert await service.list_comments("OPS-1") == [{"id": "1", "author": "Alice", "body": "Hi", "created": "now"}]
    assert _extract_display_name({"displayName": "Alice"}) == "Alice"
    assert _extract_display_name({"name": "Bob"}) == "Bob"
    assert _extract_display_name("bad") == "jira"

    class ErrClient:
        async def get(self, url, headers=None, params=None):
            raise httpx.TimeoutException("timeout")

        async def post(self, url, json=None, headers=None):
            raise RuntimeError("boom")

    service._client = ErrClient()
    with pytest.raises(JiraError):
        await service._request("GET", "/rest/api/2/project", {"base_url": "https://jira", "authMode": "bearer", "bearer": "abc"})
    with pytest.raises(JiraError):
        await service._request("POST", "/rest/api/2/project", {"base_url": "https://jira", "authMode": "bearer", "bearer": "abc"}, payload={})
