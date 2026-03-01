"""
Dependency and authentication utilities for Be Notified Service, including context token verification, shadow user synchronization, and permission checks.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""
from __future__ import annotations

import logging
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.dialects.postgresql import insert as pg_insert

from config import config
from database import get_db_session
from db_models import Group, Tenant, User
from middleware.rate_limit import enforce_ip_rate_limit, client_ip
from models.access.auth_models import Permission, TokenData

logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=False)
_jti_seen_lock = threading.Lock()
_jti_seen_cache: dict[str, float] = {}


@dataclass
class _AuthServiceStub:

    def get_user_by_id(self, _user_id: str):
        return None


auth_service = _AuthServiceStub()


def _normalize_shadow_username(raw: str, user_id: str) -> str:
    value = re.sub(r"[^a-z0-9._-]+", "-", (raw or "").strip().lower()).strip("._-")
    if not value:
        value = "user"
    suffix = re.sub(r"[^a-z0-9]", "", user_id.lower())[:8] or "shadow"
    candidate = f"{value[:32]}-{suffix}"
    return candidate[:50]


def _shadow_password_placeholder(user_id: str) -> str:
    return f"external-context::{user_id}"


def _ensure_shadow_context(current_user: TokenData) -> None:
    tenant_id = str(current_user.tenant_id or "").strip()
    user_id = str(current_user.user_id or "").strip()
    if not tenant_id or not user_id:
        return

    role_val = getattr(getattr(current_user, "role", "user"), "value", getattr(current_user, "role", "user"))
    role_text = str(role_val or "user").lower()
    role_text = role_text if role_text in {"admin", "user", "viewer"} else "user"
    username = _normalize_shadow_username(current_user.username, user_id)
    email = f"{re.sub(r'[^a-z0-9]', '', user_id.lower())[:32] or 'user'}@benotified.local"
    now = datetime.now(timezone.utc)

    with get_db_session() as db:
        db.execute(
            pg_insert(Tenant)
            .values(
                id=tenant_id,
                name=(f"tenant-{tenant_id}"[:100] or tenant_id[:100]),
                display_name=f"Tenant {tenant_id[:8]}",
                is_active=True,
                settings={},
                created_at=now,
                updated_at=now,
            )
            .on_conflict_do_nothing(index_elements=[Tenant.id])
        )

        db.execute(
            pg_insert(User)
            .values(
                id=user_id,
                tenant_id=tenant_id,
                username=username,
                email=email,
                hashed_password=_shadow_password_placeholder(user_id),
                full_name=current_user.username or username,
                org_id=current_user.org_id or tenant_id,
                role=role_text if role_text in {"admin", "user", "viewer"} else "user",
                is_active=True,
                is_superuser=bool(current_user.is_superuser),
                auth_provider="external",
                created_at=now,
                updated_at=now,
            )
            .on_conflict_do_update(
                index_elements=[User.id],
                set_={
                    "tenant_id": tenant_id,
                    "org_id": current_user.org_id or tenant_id,
                    "role": role_text,
                    "is_active": True,
                    "is_superuser": bool(current_user.is_superuser),
                    "updated_at": now,
                },
            )
        )

        normalized_group_ids = [str(g).strip() for g in (current_user.group_ids or []) if str(g).strip()]
        for gid in normalized_group_ids:
            db.execute(
                pg_insert(Group)
                .values(
                    id=gid,
                    tenant_id=tenant_id,
                    name=(f"group-{gid}"[:100] or gid[:100]),
                    description="Shadow group from main-server context",
                    is_active=True,
                    created_at=now,
                    updated_at=now,
                )
                .on_conflict_do_nothing(index_elements=[Group.id])
            )

        user = db.query(User).filter(User.id == user_id, User.tenant_id == tenant_id).first()
        if not user:
            return

        if not normalized_group_ids:
            user.groups = []
            return

        group_models = (
            db.query(Group)
            .filter(Group.tenant_id == tenant_id, Group.id.in_(normalized_group_ids))
            .all()
        )
        by_id = {group.id: group for group in group_models}
        user.groups = [by_id[gid] for gid in normalized_group_ids if gid in by_id]


def _extract_bearer_token(request: Request, credentials: HTTPAuthorizationCredentials | None) -> Optional[str]:
    if credentials and getattr(credentials, "credentials", None):
        return credentials.credentials
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip() or None
    return None


def _compare_service_token(request: Request) -> None:
    expected = config.get_secret("BENOTIFIED_EXPECTED_SERVICE_TOKEN") or config.get_secret("GATEWAY_INTERNAL_SERVICE_TOKEN")
    if not expected:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Service token not configured")
    provided = request.headers.get("X-Service-Token")
    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def _verify_context_token(token: str) -> TokenData:
    key = config.get_secret("BENOTIFIED_CONTEXT_VERIFY_KEY") or config.get_secret("BENOTIFIED_CONTEXT_SIGNING_KEY")
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
        iat = int(payload.get("iat"))
        exp = int(payload.get("exp"))
    except Exception as exc:
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
    with _jti_seen_lock:
        stale = [token_id for token_id, ts in _jti_seen_cache.items() if now - ts > ttl]
        for token_id in stale:
            _jti_seen_cache.pop(token_id, None)
        if jti in _jti_seen_cache:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Replayed context token")
        _jti_seen_cache[jti] = now


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> TokenData:
    _compare_service_token(request)
    token = _extract_bearer_token(request, credentials)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    claims = _verify_context_token(token)
    try:
        _ensure_shadow_context(claims)
    except Exception as exc:
        logger.exception("Failed to sync shadow auth context: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to sync auth context")
    return claims


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
    perm_values = [p.value if hasattr(p, "value") else str(p) for p in permissions]

    def checker(current_user: TokenData = Depends(get_current_user)) -> TokenData:
        if current_user.is_superuser:
            return current_user
        if any(p in (current_user.permissions or []) for p in perm_values):
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
    for raw in allowlist.split(","):
        entry = raw.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                networks.append(ip_network(entry, strict=False))
            else:
                addr = ip_address(entry)
                suffix = "32" if addr.version == 4 else "128"
                networks.append(ip_network(f"{entry}/{suffix}", strict=False))
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
    ip = client_ip(request)
    try:
        addr = ip_address(ip)
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


def enforce_header_token(
    request: Request,
    *,
    header_name: str,
    expected_token: str | None,
    unauthorized_detail: str,
) -> None:
    if not expected_token:
        return
    provided = request.headers.get(header_name)
    if not provided or not secrets.compare_digest(provided, expected_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=unauthorized_detail)


def require_authenticated_with_scope(scope: str):
    def dependency(current_user: TokenData = Depends(get_current_user)) -> TokenData:
        apply_scoped_rate_limit(current_user, scope)
        return current_user

    return dependency


def resolve_tenant_id(_request: Request, current_user: TokenData) -> str:
    return current_user.tenant_id
