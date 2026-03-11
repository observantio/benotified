"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import types

import pytest
from sqlalchemy.exc import IntegrityError

from tests._env import ensure_test_env

ensure_test_env()

from custom_types import json as json_types
from middleware.rate_limit import observability as rate_observability
from services.common import meta as meta_helpers
from services.common import pagination as pagination_helpers
from services.common import tenants as tenant_helpers
from services.common import url_utils
from services.common import visibility as visibility_helpers
from services.secrets.provider import EnvSecretProvider


def test_json_type_guards_and_secret_provider(monkeypatch):
    monkeypatch.setenv("API_TOKEN", "secret")
    provider = EnvSecretProvider()

    assert provider.get("API_TOKEN") == "secret"
    assert provider.get("MISSING") is None
    assert provider.get_many(["API_TOKEN", "MISSING"]) == {"API_TOKEN": "secret", "MISSING": None}

    assert json_types.is_json_value({"items": [1, 2.5, None, {"ok": True}]}) is True
    assert json_types.is_json_value({1: "bad-key"}) is False
    assert json_types.is_json_value(b"bytes") is False
    assert json_types.is_json_object({"payload": ["x", 1]}) is True
    assert json_types.is_json_object(["not", "an", "object"]) is False


def test_meta_helpers_and_group_id_safety():
    assert meta_helpers.parse_meta(None) == {}
    assert meta_helpers.parse_meta({meta_helpers.INCIDENT_META_KEY: {"shared_group_ids": ["g1", "", 3]}}) == {
        "shared_group_ids": ["g1", "", 3]
    }
    assert meta_helpers.parse_meta({meta_helpers.INCIDENT_META_KEY: '{"shared_group_ids": ["g2", "g3"]}'}) == {
        "shared_group_ids": ["g2", "g3"]
    }
    assert meta_helpers.parse_meta({meta_helpers.INCIDENT_META_KEY: "{"}) == {}
    assert meta_helpers._safe_group_ids({"shared_group_ids": ["g1", " ", 2, "g2"]}) == ["g1", "g2"]
    assert meta_helpers._safe_group_ids({"shared_group_ids": "bad"}) == []


def test_cap_pagination_url_and_visibility_edges(monkeypatch):
    monkeypatch.setattr(pagination_helpers.app_config, "DEFAULT_QUERY_LIMIT", 25)
    monkeypatch.setattr(pagination_helpers.app_config, "MAX_QUERY_LIMIT", 100)

    assert pagination_helpers.cap_pagination(None, -5) == (25, 0)
    assert pagination_helpers.cap_pagination(500, 4) == (100, 4)
    assert pagination_helpers.cap_pagination(0, 9) == (1, 9)

    assert url_utils.is_safe_http_url(None) is False
    assert url_utils.is_safe_http_url("ftp://example.com") is False
    assert url_utils.is_safe_http_url("https://localhost/path") is False
    assert url_utils.is_safe_http_url("https://10.0.0.1/path") is False
    assert url_utils.is_safe_http_url("https://example.com/path") is True

    assert visibility_helpers.normalize_visibility(None) == "private"
    assert visibility_helpers.normalize_visibility("PUBLIC") == "tenant"
    assert visibility_helpers.normalize_visibility("group") == "group"
    with pytest.raises(ValueError):
        visibility_helpers.normalize_visibility("tenant", default_value="public")
    with pytest.raises(ValueError):
        visibility_helpers.normalize_visibility("tenant", public_alias="public")
    assert visibility_helpers.normalize_storage_visibility("tenant") == "public"
    assert visibility_helpers.normalize_storage_visibility("private") == "private"
    assert visibility_helpers.normalize_storage_visibility("weird") == "public"


def test_ensure_tenant_exists_and_rate_limit_observability(monkeypatch):
    class QueryChain:
        def __init__(self, session):
            self.session = session

        def filter(self, *_args, **_kwargs):
            return self

        def first(self):
            if self.session.first_results:
                return self.session.first_results.pop(0)
            return None

    class SessionStub:
        def __init__(self, first_results, flush_error=None):
            self.first_results = list(first_results)
            self.flush_error = flush_error
            self.added = []
            self.rolled_back = 0

        def query(self, _model):
            return QueryChain(self)

        def add(self, tenant):
            self.added.append(tenant)

        def flush(self):
            if self.flush_error:
                raise self.flush_error

        def rollback(self):
            self.rolled_back += 1

    existing = types.SimpleNamespace(id="tenant-a")
    assert tenant_helpers.ensure_tenant_exists(SessionStub([existing]), " tenant-a ") == "tenant-a"

    created_session = SessionStub([])
    assert tenant_helpers.ensure_tenant_exists(created_session, "tenant-b") == "tenant-b"
    assert created_session.added[0].id == "tenant-b"

    retried_session = SessionStub(
        [None, types.SimpleNamespace(id="tenant-c")],
        flush_error=IntegrityError("insert", {}, Exception("duplicate")),
    )
    assert tenant_helpers.ensure_tenant_exists(retried_session, "tenant-c") == "tenant-c"
    assert retried_session.rolled_back == 1

    failing_session = SessionStub([], flush_error=IntegrityError("insert", {}, Exception("duplicate")))
    with pytest.raises(IntegrityError):
        tenant_helpers.ensure_tenant_exists(failing_session, "tenant-d")

    with pytest.raises(ValueError):
        tenant_helpers.ensure_tenant_exists(SessionStub([]), "  ")

    calls = []
    monkeypatch.setattr(rate_observability.logger, "warning", lambda message, *args: calls.append((message, args)))
    monkeypatch.setattr(rate_observability, "_rate_limit_fallback_total", 0)
    monkeypatch.setattr(rate_observability, "_rate_limit_fallback_by_mode", {"memory": 0, "deny": 0, "allow": 0})

    rate_observability.record_fallback_event("memory", "redis-down")
    rate_observability.record_fallback_event("custom", "manual")

    assert rate_observability._rate_limit_fallback_total == 2
    assert rate_observability._rate_limit_fallback_by_mode == {
        "memory": 1,
        "deny": 0,
        "allow": 0,
        "custom": 1,
    }
    assert calls == [
        ("rate_limit_fallback_event total=%s mode=%s reason=%s", (1, "memory", "redis-down")),
        ("rate_limit_fallback_event total=%s mode=%s reason=%s", (2, "custom", "manual")),
    ]