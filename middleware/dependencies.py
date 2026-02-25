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
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.dialects.postgresql import insert as pg_insert

from config import config
from database import get_db_session
from db_models import Group, Tenant, User
from middleware.rate_limit import enforce_ip_rate_limit
from models.access.auth_models import Permission, TokenData

logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=False)


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
                hashed_password="external-context",
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

    algorithms = [a.strip() for a in str(getattr(config, "BENOTIFIED_CONTEXT_ALGORITHMS", "HS256")).split(",") if a.strip()]
    audience = config.get_secret("BENOTIFIED_CONTEXT_AUDIENCE") or "benotified"
    issuer = config.get_secret("BENOTIFIED_CONTEXT_ISSUER") or "beobservant-main"

    try:
        payload = jwt.decode(token, key, algorithms=algorithms, audience=audience, issuer=issuer)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid context token") from exc

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
    # internal service only: still keep IP-based rate limiting for defense-in-depth.
    _ = allowlist
    enforce_ip_rate_limit(request, scope=scope, limit=limit, window_seconds=window_seconds, fallback_mode=fallback_mode)


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
