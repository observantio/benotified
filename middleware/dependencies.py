"""
Dependency and authentication utilities for Be Notified Service, including context token verification and permission checks.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from ipaddress import ip_address, ip_network
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from config import config
from middleware.rate_limit import enforce_ip_rate_limit, client_ip
from models.access.auth_models import Permission, TokenData

logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)

_jti_lock = threading.Lock()
_jti_cache: dict[str, float] = {}

def _extract_bearer_token(request: Request, credentials: HTTPAuthorizationCredentials | None) -> Optional[str]:
    if credentials and getattr(credentials, "credentials", None):
        return credentials.credentials
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip() or None
    return None


def _compare_service_token(request: Request) -> None:
    expected = (
        config.get_secret("BENOTIFIED_EXPECTED_SERVICE_TOKEN")
        or config.get_secret("GATEWAY_INTERNAL_SERVICE_TOKEN")
    )
    if not expected:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Service token not configured")
    provided = request.headers.get("X-Service-Token")
    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def _verify_context_token(token: str) -> TokenData:
    key = (
        config.get_secret("BENOTIFIED_CONTEXT_VERIFY_KEY")
        or config.get_secret("BENOTIFIED_CONTEXT_SIGNING_KEY")
    )
    if not key:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Context verification key not configured")

    algorithm = str(getattr(config, "BENOTIFIED_CONTEXT_ALGORITHM", "HS256")).strip().upper()
    audience = config.get_secret("BENOTIFIED_CONTEXT_AUDIENCE") or "benotified"
    issuer = config.get_secret("BENOTIFIED_CONTEXT_ISSUER") or "beobservant-main"

    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "iat", "iss", "aud", "jti"]},
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid context token") from exc

    try:
        iat, exp = int(payload["iat"]), int(payload["exp"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid context token claims") from exc

    if exp <= iat:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid context token lifetime")

    jti = str(payload.get("jti") or "").strip()
    if not jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing context token jti")
    _assert_jti_not_replayed(jti)

    try:
        claims = TokenData(
            user_id=str(payload.get("user_id") or ""),
            username=str(payload.get("username") or ""),
            tenant_id=str(payload.get("tenant_id") or ""),
            org_id=str(payload.get("org_id") or payload.get("tenant_id") or ""),
            role=payload.get("role") or "user",
            is_superuser=bool(payload.get("is_superuser", False)),
            permissions=[str(p) for p in (payload.get("permissions") or [])],
            group_ids=[str(g) for g in (payload.get("group_ids") or [])],
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid context claims") from exc

    if not claims.user_id or not claims.tenant_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing required context claims")

    return claims


def _assert_jti_not_replayed(jti: str) -> None:
    now = time.monotonic()
    ttl = int(getattr(config, "BENOTIFIED_CONTEXT_REPLAY_TTL_SECONDS", 180) or 180)
    with _jti_lock:
        expired = [k for k, ts in _jti_cache.items() if now - ts > ttl]
        for k in expired:
            del _jti_cache[k]
        if jti in _jti_cache:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Replayed context token")
        _jti_cache[jti] = now


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> TokenData:
    _compare_service_token(request)
    token = _extract_bearer_token(request, credentials)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return _verify_context_token(token)


def apply_scoped_rate_limit(_current_user: TokenData, _scope: str) -> None:
    return None


def require_permission(permission: Permission | str):
    perm_value = permission.value if hasattr(permission, "value") else str(permission)

    def checker(current_user: TokenData = Depends(get_current_user)) -> TokenData:
        if current_user.is_superuser:
            return current_user
        if perm_value not in (current_user.permissions or []):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user

    return checker


def require_permission_with_scope(permission: Permission | str, scope: str):
    checker = require_permission(permission)

    def dependency(current_user: TokenData = Depends(checker)) -> TokenData:
        apply_scoped_rate_limit(current_user, scope)
        return current_user

    return dependency


def require_any_permission(permissions: list[Permission | str]):
    perm_values = {p.value if hasattr(p, "value") else str(p) for p in permissions}

    def checker(current_user: TokenData = Depends(get_current_user)) -> TokenData:
        if current_user.is_superuser:
            return current_user
        if perm_values & set(current_user.permissions or []):
            return current_user
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    return checker


def require_any_permission_with_scope(permissions: list[Permission | str], scope: str):
    checker = require_any_permission(permissions)

    def dependency(current_user: TokenData = Depends(checker)) -> TokenData:
        apply_scoped_rate_limit(current_user, scope)
        return current_user

    return dependency


def enforce_public_endpoint_security(
    request: Request,
    *,
    scope: str,
    limit: int,
    window_seconds: int,
    allowlist: str | None = None,
    fallback_mode: str | None = None,
) -> None:
    resolved_ip = client_ip(request)
    if config.REQUIRE_CLIENT_IP_FOR_PUBLIC_ENDPOINTS and resolved_ip == "unknown":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied for {scope}: client IP resolution failed",
        )
    enforce_ip_rate_limit(request, scope=scope, limit=limit, window_seconds=window_seconds, fallback_mode=fallback_mode)
    _enforce_ip_allowlist(request, allowlist, scope=scope)


def _enforce_ip_allowlist(request: Request, allowlist: str | None, *, scope: str) -> None:
    if allowlist is None:
        return

    networks = []
    for entry in (e.strip() for e in allowlist.split(",") if e.strip()):
        try:
            if "/" in entry:
                networks.append(ip_network(entry, strict=False))
            else:
                addr = ip_address(entry)
                networks.append(ip_network(f"{entry}/{'32' if addr.version == 4 else '128'}", strict=False))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied for {scope}: invalid allowlist configuration",
            )

    if not networks:
        if config.ALLOWLIST_FAIL_OPEN:
            return
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied for {scope}: source IP not allowed",
        )

    try:
        addr = ip_address(client_ip(request))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied for {scope}: invalid client IP",
        )

    if not any(addr in net for net in networks):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied for {scope}: source IP not allowed",
        )