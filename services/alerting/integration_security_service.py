"""
Integration security service for managing Jira integration configurations, including credential storage, access control, and synchronization of Jira comments to incident notes.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from cryptography.fernet import Fernet
from fastapi import HTTPException, status

from config import config
from database import get_db_session
from sqlalchemy.dialects.postgresql import insert as pg_insert

from db_models import AlertIncident as AlertIncidentDB, Tenant
from models.access.auth_models import Role, TokenData
from services.common.url_utils import is_safe_http_url
from services.common.visibility import normalize_visibility as _base_normalize_visibility

ALLOWED_JIRA_AUTH_MODES = {"api_token", "bearer", "sso"}
logger = logging.getLogger(__name__)


def ensure_default_tenant(db) -> str:
    db.execute(
        pg_insert(Tenant)
        .values(
            id=config.DEFAULT_ADMIN_TENANT,
            name=config.DEFAULT_ADMIN_TENANT,
            display_name=config.DEFAULT_ADMIN_TENANT,
            is_active=True,
            settings={},
        )
        .on_conflict_do_nothing(index_elements=["id"])
    )
    row = db.query(Tenant).filter_by(name=config.DEFAULT_ADMIN_TENANT).first()
    return row.id if row else config.DEFAULT_ADMIN_TENANT


def tenant_id_from_scope_header(scoped_header: Optional[str]) -> str:
    candidate = (scoped_header.split("|")[0].strip() if scoped_header else "") or config.DEFAULT_ORG_ID

    with get_db_session() as db:
        if not candidate or candidate == config.DEFAULT_ORG_ID:
            return ensure_default_tenant(db)

        tenant = db.query(Tenant).filter(Tenant.id == candidate).first()
        if tenant:
            return tenant.id

        tenant = db.query(Tenant).filter(Tenant.name == candidate).first()
        if tenant:
            return tenant.id

        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unknown tenant scope header")


def encrypt_tenant_secret(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    if not config.DATA_ENCRYPTION_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="DATA_ENCRYPTION_KEY is required to store Jira secrets",
        )
    try:
        fernet = Fernet(config.DATA_ENCRYPTION_KEY)
        return f"enc:{fernet.encrypt(value.encode()).decode()}"
    except Exception as exc:
        logger.exception("Failed to encrypt Jira secret")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to encrypt Jira secret",
        ) from exc


def decrypt_tenant_secret(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    text = str(value)
    if not text.startswith("enc:"):
        logger.warning("Encountered legacy plaintext Jira secret; migration is required")
        return text
    if not config.DATA_ENCRYPTION_KEY:
        return None
    try:
        fernet = Fernet(config.DATA_ENCRYPTION_KEY)
        return fernet.decrypt(text[4:].encode()).decode()
    except Exception:
        return None


def load_tenant_jira_config(tenant_id: str) -> Dict[str, Optional[str]]:
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
            "api_token": decrypt_tenant_secret(raw_jira.get("api_token")) or None,
            "bearer": decrypt_tenant_secret(raw_jira.get("bearer")) or None,
        }


def save_tenant_jira_config(
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
            "api_token": encrypt_tenant_secret(normalized_api_token),
            "bearer": encrypt_tenant_secret(normalized_bearer),
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


def get_effective_jira_credentials(tenant_id: str) -> Dict[str, Optional[str]]:
    tenant_cfg = load_tenant_jira_config(tenant_id)
    if (
        tenant_cfg.get("enabled")
        and is_safe_http_url(tenant_cfg.get("base_url"))
        and (tenant_cfg.get("bearer") or (tenant_cfg.get("email") and tenant_cfg.get("api_token")))
    ):
        return tenant_cfg
    return {}


def jira_is_enabled_for_tenant(tenant_id: str) -> bool:
    credentials = get_effective_jira_credentials(tenant_id)
    return bool(credentials.get("base_url") and (credentials.get("api_token") or credentials.get("bearer")))


def allowed_channel_types() -> List[str]:
    return [t.lower() for t in (config.ENABLED_NOTIFICATION_CHANNEL_TYPES or [])]


def normalize_visibility(value: Optional[str], default_value: str = "private") -> str:
    return _base_normalize_visibility(
        value,
        default_value=default_value,
        public_alias="tenant",
        allowed={"tenant", "group", "private"},
    )


def is_jira_sso_available() -> bool:
    return config.AUTH_PROVIDER == "keycloak" and bool(config.OIDC_ISSUER_URL and config.OIDC_CLIENT_ID)


def normalize_jira_auth_mode(value: Optional[str]) -> str:
    mode = str(value or "api_token").strip().lower()
    if mode not in ALLOWED_JIRA_AUTH_MODES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported Jira authMode '{mode}'",
        )
    if mode == "sso" and not is_jira_sso_available():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Jira SSO mode requires OIDC-enabled authentication",
        )
    return mode


def validate_jira_credentials(
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


def load_tenant_jira_integrations(tenant_id: str) -> List[Dict[str, object]]:
    with get_db_session() as db:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        settings = (tenant.settings or {}) if tenant else {}
        raw_items = settings.get("jira_integrations", []) if isinstance(settings, dict) else []
        if not isinstance(raw_items, list):
            return []
        return [item for item in raw_items if isinstance(item, dict)]


def save_tenant_jira_integrations(tenant_id: str, items: List[Dict[str, object]]) -> None:
    with get_db_session() as db:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
        settings = tenant.settings if isinstance(tenant.settings, dict) else {}
        settings["jira_integrations"] = items
        tenant.settings = settings
        db.flush()


def validate_shared_group_ids_for_user(
    tenant_id: str,
    shared_group_ids: List[str],
    current_user: TokenData,
) -> List[str]:
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


def jira_integration_has_access(item: Dict[str, object], current_user: TokenData, *, write: bool = False) -> bool:
    if str(item.get("createdBy") or "") == current_user.user_id:
        return True
    if write:
        return False
    visibility = normalize_visibility(str(item.get("visibility") or "private"), "private")
    if visibility == "tenant":
        return True
    if visibility == "group":
        shared_group_ids = [str(gid) for gid in (item.get("sharedGroupIds") or []) if isinstance(gid, str) and gid.strip()]
        user_groups = getattr(current_user, "group_ids", []) or []
        return bool(set(shared_group_ids) & set(user_groups))
    return False


def mask_jira_integration(item: Dict[str, object], current_user: TokenData) -> Dict[str, object]:
    is_owner = str(item.get("createdBy") or "") == current_user.user_id
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "enabled": bool(item.get("enabled", True)),
        "visibility": normalize_visibility(str(item.get("visibility") or "private"), "private"),
        "sharedGroupIds": item.get("sharedGroupIds") or [],
        "createdBy": item.get("createdBy"),
        "authMode": item.get("authMode") or "api_token",
        "baseUrl": item.get("baseUrl") if is_owner else None,
        "email": item.get("email") if is_owner else None,
        "hasApiToken": bool(item.get("apiToken")),
        "hasBearerToken": bool(item.get("bearerToken")),
        "supportsSso": bool(item.get("supportsSso", False)),
    }


def resolve_jira_integration(
    tenant_id: str,
    integration_id: str,
    current_user: TokenData,
    *,
    require_write: bool = False,
) -> Dict[str, object]:
    integrations = load_tenant_jira_integrations(tenant_id)
    match = next((item for item in integrations if str(item.get("id")) == integration_id), None)
    if not match or not jira_integration_has_access(match, current_user, write=require_write):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Jira integration not found")
    return match


def jira_integration_credentials(item: Dict[str, object]) -> Dict[str, Optional[str]]:
    return {
        "auth_mode": normalize_jira_auth_mode(item.get("authMode")),
        "base_url": str(item.get("baseUrl") or "").strip() or None,
        "email": str(item.get("email") or "").strip() or None,
        "api_token": decrypt_tenant_secret(item.get("apiToken")) or None,
        "bearer": decrypt_tenant_secret(item.get("bearerToken")) or None,
    }


def integration_is_usable(item: Dict[str, object]) -> bool:
    if not item.get("enabled", True):
        return False
    try:
        credentials = jira_integration_credentials(item)
    except HTTPException:
        return False
    if not is_safe_http_url(credentials.get("base_url")):
        return False
    if credentials["auth_mode"] == "api_token":
        return bool(credentials.get("email") and credentials.get("api_token"))
    return bool(credentials.get("bearer"))


def sync_jira_comments_to_incident_notes(incident_id: str, tenant_id: str, comments: List[Dict[str, object]]) -> int:
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