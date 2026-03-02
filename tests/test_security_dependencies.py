"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException
from starlette.requests import Request

from tests._env import ensure_test_env

ensure_test_env()

from config import config
from middleware import dependencies
from models.access.auth_models import Role, TokenData


def _request(ip: str, headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/internal/v1/alertmanager/alerts/webhook",
        "headers": headers or [],
        "client": (ip, 12345),
        "scheme": "http",
        "query_string": b"",
    }
    return Request(scope)


@pytest.fixture(autouse=True)
def _reset_replay_cache():
    # the underlying implementation renamed the lock/cache variables
    with dependencies._jti_lock:
        dependencies._jti_cache.clear()


def test_verify_context_token_rejects_missing_jti(monkeypatch):
    key = "test-context-key"
    monkeypatch.setattr(config, "BENOTIFIED_CONTEXT_VERIFY_KEY", key)
    monkeypatch.setattr(config, "BENOTIFIED_CONTEXT_SIGNING_KEY", key)
    monkeypatch.setattr(config, "BENOTIFIED_CONTEXT_ALGORITHM", "HS256")
    monkeypatch.setattr(config, "BENOTIFIED_CONTEXT_AUDIENCE", "benotified")
    monkeypatch.setattr(config, "BENOTIFIED_CONTEXT_ISSUER", "beobservant-main")

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "iss": "beobservant-main",
            "aud": "benotified",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=60)).timestamp()),
            "user_id": "u1",
            "username": "user-1",
            "tenant_id": "t1",
            "permissions": [],
            "group_ids": [],
            "is_superuser": False,
        },
        key,
        algorithm="HS256",
    )
    with pytest.raises(HTTPException) as exc:
        dependencies._verify_context_token(token)
    assert exc.value.status_code == 401


def test_verify_context_token_replay_detection(monkeypatch):
    key = "test-context-key"
    monkeypatch.setattr(config, "BENOTIFIED_CONTEXT_VERIFY_KEY", key)
    monkeypatch.setattr(config, "BENOTIFIED_CONTEXT_SIGNING_KEY", key)
    monkeypatch.setattr(config, "BENOTIFIED_CONTEXT_ALGORITHM", "HS256")
    monkeypatch.setattr(config, "BENOTIFIED_CONTEXT_AUDIENCE", "benotified")
    setattr(config, "BENOTIFIED_CONTEXT_ISSUER", "beobservant-main")
    monkeypatch.setattr(config, "BENOTIFIED_CONTEXT_REPLAY_TTL_SECONDS", 120)

    now = datetime.now(timezone.utc)
    payload = {
        "iss": "beobservant-main",
        "aud": "benotified",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=60)).timestamp()),
        "jti": "replay-jti-1",
        "user_id": "u1",
        "username": "user-1",
        "tenant_id": "t1",
        "permissions": [],
        "group_ids": [],
        "is_superuser": False,
    }
    token = jwt.encode(payload, key, algorithm="HS256")
    claims = dependencies._verify_context_token(token)
    assert claims.user_id == "u1"
    with pytest.raises(HTTPException) as exc:
        dependencies._verify_context_token(token)
    assert exc.value.status_code == 401


def test_public_endpoint_security_enforces_allowlist(monkeypatch):
    monkeypatch.setattr(dependencies, "enforce_ip_rate_limit", lambda *args, **kwargs: None)
    monkeypatch.setattr(config, "ALLOWLIST_FAIL_OPEN", False)
    monkeypatch.setattr(config, "REQUIRE_CLIENT_IP_FOR_PUBLIC_ENDPOINTS", False)

    with pytest.raises(HTTPException) as exc:
        dependencies.enforce_public_endpoint_security(
            _request("198.51.100.1"),
            scope="test",
            limit=100,
            window_seconds=60,
            allowlist="203.0.113.10",
        )
    assert exc.value.status_code == 403


def test_public_endpoint_security_allows_allowlisted_ip(monkeypatch):
    monkeypatch.setattr(dependencies, "enforce_ip_rate_limit", lambda *args, **kwargs: None)
    monkeypatch.setattr(config, "ALLOWLIST_FAIL_OPEN", False)
    monkeypatch.setattr(config, "REQUIRE_CLIENT_IP_FOR_PUBLIC_ENDPOINTS", False)

    dependencies.enforce_public_endpoint_security(
        _request("203.0.113.10"),
        scope="test",
        limit=100,
        window_seconds=60,
        allowlist="203.0.113.10",
    )


def test_get_current_user_rejects_missing_service_token(monkeypatch):
    claims = TokenData(
        user_id="u1",
        username="user-1",
        tenant_id="t1",
        org_id="t1",
        role=Role.USER,
        is_superuser=False,
        permissions=[],
        group_ids=[],
    )
    monkeypatch.setattr(config, "get_secret", lambda *_args, **_kwargs: "expected-service-token")
    monkeypatch.setattr(dependencies, "_verify_context_token", lambda _token: claims)
    # shadow context no longer used; ignore

    request = _request(
        "203.0.113.10",
        headers=[(b"authorization", b"Bearer valid-context-token")],
    )

    with pytest.raises(HTTPException) as exc:
        dependencies.get_current_user(request=request, credentials=None)
    assert exc.value.status_code == 403


def test_get_current_user_rejects_invalid_context_with_valid_service_token(monkeypatch):
    monkeypatch.setattr(config, "get_secret", lambda *_args, **_kwargs: "expected-service-token")
    monkeypatch.setattr(
        dependencies,
        "_verify_context_token",
        lambda _token: (_ for _ in ()).throw(
            HTTPException(status_code=401, detail="Invalid context token")
        ),
    )
    # shadow context no longer used; ignore

    request = _request(
        "203.0.113.10",
        headers=[
            (b"x-service-token", b"expected-service-token"),
            (b"authorization", b"Bearer bad-context-token"),
        ],
    )

    with pytest.raises(HTTPException) as exc:
        dependencies.get_current_user(request=request, credentials=None)
    assert exc.value.status_code == 401
