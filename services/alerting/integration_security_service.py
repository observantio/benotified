"""
Integration security service for managing Jira integration configurations, including credential storage, access control, and synchronization of Jira comments to incident notes.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional

from cryptography.fernet import Fernet
from fastapi import HTTPException, status

from config import config
from database import get_db_session
from db_models import Tenant, User, Group, UserApiKey, AlertIncident as AlertIncidentDB
from models.access.auth_models import TokenData, Role
from services.common.url_utils import is_safe_http_url
from services.common.visibility import normalize_visibility

ALLOWED_JIRA_AUTH_MODES = {"api_token", "bearer", "sso"}
logger = logging.getLogger(__name__)


def _tenant_id_from_scope_header(scoped_header: Optional[str]) -> str:
    candidate = (scoped_header.split("|")[0].strip() if scoped_header else "") or config.DEFAULT_ORG_ID

    with get_db_session() as db:
        default = db.query(Tenant).filter_by(name=config.DEFAULT_ADMIN_TENANT).first()
        default_tenant_id = default.id if default else config.DEFAULT_ADMIN_TENANT

        if not candidate:
            return default_tenant_id

        tenant_by_id = db.query(Tenant).filter(Tenant.id == candidate).first()
        if tenant_by_id:
            return tenant_by_id.id

        tenant_by_name = db.query(Tenant).filter(Tenant.name == candidate).first()
        if tenant_by_name:
            return tenant_by_name.id

        scope_tenants = {
            str(row[0])
            for row in (
                db.query(UserApiKey.tenant_id)
                .filter(UserApiKey.key == candidate, UserApiKey.is_enabled.is_(True))
                .distinct()
                .all()
            )
            if row and row[0]
        }
        if len(scope_tenants) > 1:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Ambiguous tenant scope header")
        if len(scope_tenants) == 1:
            return next(iter(scope_tenants))

        user_tenants = {
            str(row[0])
            for row in (
                db.query(User.tenant_id)
                .filter(User.org_id == candidate, User.is_active.is_(True))
                .distinct()
                .all()
            )
            if row and row[0]
        }
        if len(user_tenants) > 1:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Ambiguous tenant scope header")
        if len(user_tenants) == 1:
            return next(iter(user_tenants))

        if candidate == config.DEFAULT_ORG_ID:
            return default_tenant_id

        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unknown tenant scope header")


def _encrypt_tenant_secret(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    if not config.DATA_ENCRYPTION_KEY:
        logger.warning("DATA_ENCRYPTION_KEY is not configured; storing Jira secret without encryption")
        return value
    try:
        fernet = Fernet(config.DATA_ENCRYPTION_KEY)
        return f"enc:{fernet.encrypt(value.encode()).decode()}"
    except Exception as exc:
        logger.warning("Failed to encrypt Jira secret; storing plaintext fallback: %s", exc)
        return value


def _decrypt_tenant_secret(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    text = str(value)
    if not text.startswith("enc:"):
        return text
    if not config.DATA_ENCRYPTION_KEY:
        return None
    try:
        fernet = Fernet(config.DATA_ENCRYPTION_KEY)
        return fernet.decrypt(text[4:].encode()).decode()
    except Exception:
        return None


def _load_tenant_jira_config(tenant_id: str) -> Dict[str, Optional[str]]:
    with get_db_session() as db:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        settings = (tenant.settings or {}) if tenant else {}
        raw_jira = settings.get("jira") if isinstance(settings, dict) else {}
        if not isinstance(raw_jira, dict):
            raw_jira = {}
        return {
            "enabled": bool(raw_jira.get("enabled", False)),
            "base_url": str(raw_jira.get("base_url") or raw_jira.get("baseUrl") or "").strip() or None,
            "email": str(raw_jira.get("email") or "").strip() or None,
            "api_token": _decrypt_tenant_secret(raw_jira.get("api_token")) or None,
            "bearer": _decrypt_tenant_secret(raw_jira.get("bearer")) or None,
        }


def _save_tenant_jira_config(
    tenant_id: str,
    *,
    enabled: bool,
    base_url: Optional[str],
    email: Optional[str],
    api_token: Optional[str],
    bearer: Optional[str],
) -> Dict[str, object]:
    normalized_url = str(base_url or "").strip() or None
    normalized_email = str(email or "").strip() or None
    normalized_api_token = str(api_token or "").strip() or None
    normalized_bearer = str(bearer or "").strip() or None

    if enabled:
        if not is_safe_http_url(normalized_url):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Jira base URL is missing or invalid")
        if not (normalized_bearer or (normalized_email and normalized_api_token)):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Jira credentials are incomplete; provide bearer token or email + api token",
            )

    with get_db_session() as db:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
        settings = tenant.settings if isinstance(tenant.settings, dict) else {}

        jira_cfg = {
            "enabled": bool(enabled),
            "base_url": normalized_url,
            "email": normalized_email,
            "api_token": _encrypt_tenant_secret(normalized_api_token),
            "bearer": _encrypt_tenant_secret(normalized_bearer),
        }
        settings["jira"] = jira_cfg
        tenant.settings = settings
        db.flush()
        return {
            "enabled": jira_cfg["enabled"],
            "baseUrl": jira_cfg["base_url"],
            "email": jira_cfg["email"],
            "hasApiToken": bool(jira_cfg["api_token"]),
            "hasBearerToken": bool(jira_cfg["bearer"]),
        }


def _get_effective_jira_credentials(tenant_id: str) -> Dict[str, Optional[str]]:
    tenant_cfg = _load_tenant_jira_config(tenant_id)
    if (
        tenant_cfg.get("enabled")
        and is_safe_http_url(tenant_cfg.get("base_url"))
        and (tenant_cfg.get("bearer") or (tenant_cfg.get("email") and tenant_cfg.get("api_token")))
    ):
        return tenant_cfg
    return {}


def _jira_is_enabled_for_tenant(tenant_id: str) -> bool:
    credentials = _get_effective_jira_credentials(tenant_id)
    return bool(credentials.get("base_url") and (credentials.get("api_token") or credentials.get("bearer")))


def _allowed_channel_types() -> List[str]:
    return [t.lower() for t in (config.ENABLED_NOTIFICATION_CHANNEL_TYPES or [])]


def _normalize_visibility(value: Optional[str], default_value: str = "private") -> str:
    return normalize_visibility(
        value,
        default_value=default_value,
        public_alias="tenant",
        allowed={"tenant", "group", "private"},
    )


def _is_jira_sso_available() -> bool:
    return config.AUTH_PROVIDER == "keycloak" and bool(config.OIDC_ISSUER_URL and config.OIDC_CLIENT_ID)


def _normalize_jira_auth_mode(value: Optional[str]) -> str:
    mode = str(value or "api_token").strip().lower()
    if mode not in ALLOWED_JIRA_AUTH_MODES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported Jira authMode '{mode}'",
        )
    if mode == "sso" and not _is_jira_sso_available():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Jira SSO mode requires OIDC-enabled authentication",
        )
    return mode


def _validate_jira_credentials(
    *,
    base_url: Optional[str],
    auth_mode: str,
    email: Optional[str],
    api_token: Optional[str],
    bearer_token: Optional[str],
) -> None:
    if not is_safe_http_url(str(base_url or "").strip()):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Jira base URL is missing or invalid")

    if auth_mode == "api_token":
        if not str(email or "").strip():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Jira email is required for api_token auth mode")
        if not str(api_token or "").strip():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Jira apiToken is required for api_token auth mode")
    elif auth_mode in {"bearer", "sso"}:
        if not str(bearer_token or "").strip():
            detail = "Jira SSO mode requires a bearerToken" if auth_mode == "sso" else "Jira bearerToken is required for bearer auth mode"
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _load_tenant_jira_integrations(tenant_id: str) -> List[Dict[str, object]]:
    with get_db_session() as db:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        settings = (tenant.settings or {}) if tenant else {}
        raw_items = settings.get("jira_integrations", []) if isinstance(settings, dict) else []
        if not isinstance(raw_items, list):
            return []
        return [item for item in raw_items if isinstance(item, dict)]


def _save_tenant_jira_integrations(tenant_id: str, items: List[Dict[str, object]]) -> None:
    with get_db_session() as db:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
        settings = tenant.settings if isinstance(tenant.settings, dict) else {}
        settings["jira_integrations"] = items
        tenant.settings = settings
        db.flush()


def _validate_shared_group_ids_for_user(
    tenant_id: str,
    shared_group_ids: List[str],
    current_user: TokenData,
) -> List[str]:
    _ = tenant_id
    normalized = [str(gid).strip() for gid in (shared_group_ids or []) if str(gid).strip()]
    if not normalized:
        return []

    is_admin = getattr(current_user, "is_superuser", False) or getattr(current_user, "role", None) == Role.ADMIN
    if not is_admin:
        actor_groups = set(getattr(current_user, "group_ids", []) or [])
        unauthorized = sorted(gid for gid in normalized if gid not in actor_groups)
        if unauthorized:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"User not member of groups: {unauthorized}")

    return normalized


def _jira_integration_has_access(item: Dict[str, object], current_user: TokenData, *, write: bool = False) -> bool:
    created_by = str(item.get("createdBy") or "")
    if created_by and created_by == current_user.user_id:
        return True
    if write:
        return False
    visibility = _normalize_visibility(str(item.get("visibility") or "private"), "private")
    if visibility == "tenant":
        return True
    if visibility == "group":
        shared_group_ids = [
            str(gid) for gid in (item.get("sharedGroupIds") or [])
            if isinstance(gid, str) and gid.strip()
        ]
        user_groups = getattr(current_user, "group_ids", []) or []
        return bool(set(shared_group_ids) & set(user_groups))
    return False


def _mask_jira_integration(item: Dict[str, object], current_user: TokenData) -> Dict[str, object]:
    is_owner = str(item.get("createdBy") or "") == current_user.user_id
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "enabled": bool(item.get("enabled", True)),
        "visibility": _normalize_visibility(str(item.get("visibility") or "private"), "private"),
        "sharedGroupIds": item.get("sharedGroupIds") or [],
        "createdBy": item.get("createdBy"),
        "authMode": item.get("authMode") or "api_token",
        "baseUrl": item.get("baseUrl") if is_owner else None,
        "email": item.get("email") if is_owner else None,
        "hasApiToken": bool(item.get("apiToken")),
        "hasBearerToken": bool(item.get("bearerToken")),
        "supportsSso": bool(item.get("supportsSso", False)),
    }


def _resolve_jira_integration(
    tenant_id: str,
    integration_id: str,
    current_user: TokenData,
    *,
    require_write: bool = False,
) -> Dict[str, object]:
    integrations = _load_tenant_jira_integrations(tenant_id)
    match = next((item for item in integrations if str(item.get("id")) == integration_id), None)
    if not match or not _jira_integration_has_access(match, current_user, write=require_write):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Jira integration not found")
    return match


def _jira_integration_credentials(item: Dict[str, object]) -> Dict[str, Optional[str]]:
    return {
        "auth_mode": _normalize_jira_auth_mode(item.get("authMode")),
        "base_url": str(item.get("baseUrl") or "").strip() or None,
        "email": str(item.get("email") or "").strip() or None,
        "api_token": _decrypt_tenant_secret(item.get("apiToken")) or None,
        "bearer": _decrypt_tenant_secret(item.get("bearerToken")) or None,
    }


def _integration_is_usable(item: Dict[str, object]) -> bool:
    if not item.get("enabled", True):
        return False
    try:
        credentials = _jira_integration_credentials(item)
    except HTTPException:
        return False
    if not is_safe_http_url(credentials.get("base_url")):
        return False
    if credentials["auth_mode"] == "api_token":
        return bool(credentials.get("email") and credentials.get("api_token"))
    return bool(credentials.get("bearer"))


def _sync_jira_comments_to_incident_notes(incident_id: str, tenant_id: str, comments: List[Dict[str, object]]) -> int:
    if not comments:
        return 0
    with get_db_session() as db:
        incident = (
            db.query(AlertIncidentDB)
            .filter(AlertIncidentDB.id == incident_id, AlertIncidentDB.tenant_id == tenant_id)
            .first()
        )
        if not incident:
            return 0

        notes = list(incident.notes or [])
        existing_comment_ids = {
            str(note["jiraCommentId"])
            for note in notes
            if isinstance(note, dict) and note.get("jiraCommentId")
        }
        appended = 0
        for comment in comments:
            comment_id = str(comment.get("id") or "").strip()
            if not comment_id or comment_id in existing_comment_ids:
                continue
            notes.append({
                "author": f"jira:{comment.get('author') or 'jira'}",
                "text": str(comment.get("body") or ""),
                "createdAt": str(comment.get("created") or datetime.now(timezone.utc).isoformat()),
                "jiraCommentId": comment_id,
            })
            existing_comment_ids.add(comment_id)
            appended += 1

        if appended:
            incident.notes = notes
            db.flush()
        return appended
