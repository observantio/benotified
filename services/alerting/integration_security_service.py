"""
Integration security service for managing Jira integration configurations, including credential storage, access control, and synchronization of Jira comments to incident notes.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
import os
from urllib.parse import urlparse
from collections.abc import Mapping, Sequence
from typing import Dict, List, Optional

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, status
from sqlalchemy import and_
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from config import config
from database import get_db_session
from sqlalchemy.dialects.postgresql import insert as pg_insert

from db_models import AlertRule, Tenant
from models.access.auth_models import Role, TokenData
from custom_types.json import JSONDict
from services.common.url_utils import is_safe_http_url
from services.common.visibility import normalize_visibility as _base_normalize_visibility

ALLOWED_JIRA_AUTH_MODES = {"api_token", "bearer", "sso"}
logger = logging.getLogger(__name__)


def _normalized_id(value: object) -> str:
    return str(value or "").strip()


def _normalized_id_list(values: Optional[List[object]]) -> List[str]:
    return [_normalized_id(v) for v in (values or []) if _normalized_id(v)]


def _current_user_id(current_user: TokenData) -> str:
    return _normalized_id(getattr(current_user, "user_id", ""))


def _tenant_settings_copy(tenant: Tenant) -> JSONDict:
    current: JSONDict = tenant.settings if isinstance(tenant.settings, dict) else {}
    return dict(current)


def _persist_tenant_settings(tenant: Tenant, settings: JSONDict) -> None:
    tenant.settings = dict(settings)
    flag_modified(tenant, "settings")


def _optional_string(value: object) -> Optional[str]:
    text = str(value or "").strip()
    return text or None


def ensure_default_tenant(db: Session) -> str:
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


def _alert_label_value(labels: Dict[str, object], *keys: str) -> str:
    for key in keys:
        value = str(labels.get(key) or "").strip()
        if value:
            return value
    return ""


def infer_tenant_id_from_alerts(
    scoped_header: Optional[str],
    alerts: Sequence[Mapping[str, object]] | None,
) -> str:
    base_tenant_id = tenant_id_from_scope_header(scoped_header)
    if scoped_header and str(scoped_header).strip():
        return base_tenant_id

    payload_alerts = alerts or []
    if not payload_alerts:
        return base_tenant_id

    candidates: set[str] = set()
    with get_db_session() as db:
        for alert in payload_alerts:
            labels = alert.get("labels") if isinstance(alert, dict) else {}
            if not isinstance(labels, dict):
                continue
            alertname = _alert_label_value(labels, "alertname")
            org_id = _alert_label_value(labels, "org_id", "orgId", "tenant", "product")

            if alertname and org_id:
                rows = (
                    db.query(AlertRule.tenant_id)
                    .filter(
                        and_(
                            AlertRule.enabled.is_(True),
                            AlertRule.name == alertname,
                            AlertRule.org_id == org_id,
                        )
                    )
                    .all()
                )
                candidates.update(str(tenant_id) for (tenant_id,) in rows if str(tenant_id).strip())
                continue

            if alertname:
                rows = (
                    db.query(AlertRule.tenant_id)
                    .filter(
                        and_(
                            AlertRule.enabled.is_(True),
                            AlertRule.name == alertname,
                        )
                    )
                    .all()
                )
                candidates.update(str(tenant_id) for (tenant_id,) in rows if str(tenant_id).strip())

    if len(candidates) == 1:
        inferred = next(iter(candidates))
        logger.info(
            "Inferred tenant %s from webhook alerts (base=%s, explicit_scope=%s)",
            inferred,
            base_tenant_id,
            bool(scoped_header and str(scoped_header).strip()),
        )
        return inferred

    if len(candidates) > 1:
        logger.warning(
            "Ambiguous tenant inference for webhook alerts; using base tenant %s candidates=%s",
            base_tenant_id,
            sorted(candidates),
        )
    return base_tenant_id


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
    except (TypeError, ValueError) as exc:
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
    except (InvalidToken, TypeError, ValueError):
        return None


def load_tenant_jira_config(tenant_id: str) -> Dict[str, object]:
    with get_db_session() as db:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        settings = (tenant.settings or {}) if tenant else {}
        raw_jira = settings.get("jira") if isinstance(settings, dict) else {}
        if not isinstance(raw_jira, dict):
            raw_jira = {}
        return {
            "enabled": bool(raw_jira.get("enabled", False)),
            "base_url": _optional_string(raw_jira.get("base_url") or raw_jira.get("baseUrl")),
            "email": _optional_string(raw_jira.get("email")),
            "api_token": decrypt_tenant_secret(_optional_string(raw_jira.get("api_token"))) or None,
            "bearer": decrypt_tenant_secret(_optional_string(raw_jira.get("bearer"))) or None,
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
        settings = _tenant_settings_copy(tenant)
        jira_cfg: JSONDict = {
            "enabled": bool(enabled),
            "base_url": normalized_url,
            "email": normalized_email,
            "api_token": encrypt_tenant_secret(normalized_api_token),
            "bearer": encrypt_tenant_secret(normalized_bearer),
        }
        settings["jira"] = jira_cfg
        _persist_tenant_settings(tenant, settings)
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
    base_url = tenant_cfg.get("base_url")
    email = tenant_cfg.get("email")
    api_token = tenant_cfg.get("api_token")
    bearer = tenant_cfg.get("bearer")
    base_url_str = base_url if isinstance(base_url, str) else None
    email_str = email if isinstance(email, str) else None
    api_token_str = api_token if isinstance(api_token, str) else None
    bearer_str = bearer if isinstance(bearer, str) else None
    if (
        tenant_cfg.get("enabled")
        and is_safe_http_url(base_url_str)
        and (bearer_str or (email_str and api_token_str))
    ):
        return {
            "base_url": base_url_str,
            "email": email_str,
            "api_token": api_token_str,
            "bearer": bearer_str,
        }
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
        allowed=frozenset({"tenant", "group", "private"}),
    )


def is_jira_sso_available() -> bool:
    auth_provider = str(
        getattr(config, "AUTH_PROVIDER", None) or os.getenv("AUTH_PROVIDER", "")
    ).strip().lower()
    oidc_issuer = str(
        getattr(config, "OIDC_ISSUER_URL", None) or os.getenv("OIDC_ISSUER_URL", "")
    ).strip()
    oidc_client_id = str(
        getattr(config, "OIDC_CLIENT_ID", None) or os.getenv("OIDC_CLIENT_ID", "")
    ).strip()
    return auth_provider in {"keycloak", "oidc"} and bool(oidc_issuer and oidc_client_id)


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
    normalized_base_url = str(base_url or "").strip()
    if not is_safe_http_url(normalized_base_url):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Jira base URL is missing or invalid")
    host = (urlparse(normalized_base_url).hostname or "").strip().lower()
    is_atlassian_cloud = host.endswith(".atlassian.net")
    if is_atlassian_cloud and auth_mode in {"bearer", "sso"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Atlassian Cloud requires Email + API token (authMode=api_token)",
        )
    if auth_mode == "api_token":
        if not str(email or "").strip():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Jira email is required for api_token auth mode")
        if not str(api_token or "").strip():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Jira apiToken is required for api_token auth mode")
    elif auth_mode in {"bearer", "sso"}:
        if not str(bearer_token or "").strip():
            detail = "Jira SSO mode requires a bearerToken" if auth_mode == "sso" else "Jira bearerToken is required for bearer auth mode"
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def load_tenant_jira_integrations(tenant_id: str) -> List[JSONDict]:
    with get_db_session() as db:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        settings = (tenant.settings or {}) if tenant else {}
        raw_items = settings.get("jira_integrations", []) if isinstance(settings, dict) else []
        if not isinstance(raw_items, list):
            return []
        return [item for item in raw_items if isinstance(item, dict)]


def save_tenant_jira_integrations(tenant_id: str, items: List[JSONDict]) -> None:
    with get_db_session() as db:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
        settings = _tenant_settings_copy(tenant)
        settings["jira_integrations"] = [dict(item) for item in (items or [])]
        _persist_tenant_settings(tenant, settings)
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


def jira_integration_has_access(item: Mapping[str, object], current_user: TokenData, *, write: bool = False) -> bool:
    if _normalized_id(item.get("createdBy")) == _current_user_id(current_user):
        return True
    if write:
        return False
    visibility = normalize_visibility(str(item.get("visibility") or "private"), "private")
    if visibility == "tenant":
        return True
    if visibility == "group":
        raw_shared_group_ids = item.get("sharedGroupIds")
        raw_user_groups = getattr(current_user, "group_ids", []) or []
        shared_group_ids = set(_normalized_id_list(raw_shared_group_ids if isinstance(raw_shared_group_ids, list) else []))
        user_groups = set(_normalized_id_list(raw_user_groups if isinstance(raw_user_groups, list) else []))
        return bool(set(shared_group_ids) & set(user_groups))
    return False


def mask_jira_integration(item: Mapping[str, object], current_user: TokenData) -> JSONDict:
    is_owner = _normalized_id(item.get("createdBy")) == _current_user_id(current_user)
    raw_shared_group_ids = item.get("sharedGroupIds")
    shared_group_ids = _normalized_id_list(raw_shared_group_ids if isinstance(raw_shared_group_ids, list) else None)
    return {
        "id": _optional_string(item.get("id")),
        "name": _optional_string(item.get("name")),
        "enabled": bool(item.get("enabled", True)),
        "visibility": normalize_visibility(str(item.get("visibility") or "private"), "private"),
        "sharedGroupIds": shared_group_ids,
        "createdBy": _optional_string(item.get("createdBy")),
        "authMode": _optional_string(item.get("authMode")) or "api_token",
        "baseUrl": _optional_string(item.get("baseUrl")) if is_owner else None,
        "email": _optional_string(item.get("email")) if is_owner else None,
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
) -> JSONDict:
    integrations = load_tenant_jira_integrations(tenant_id)
    match = next((item for item in integrations if str(item.get("id")) == integration_id), None)
    if not match or not jira_integration_has_access(match, current_user, write=require_write):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Jira integration not found")
    return match


def jira_integration_credentials(item: Mapping[str, object]) -> Dict[str, Optional[str]]:
    auth_mode_raw = item.get("authMode")
    api_token_raw = item.get("apiToken")
    bearer_token_raw = item.get("bearerToken")
    return {
        "auth_mode": normalize_jira_auth_mode(str(auth_mode_raw) if auth_mode_raw is not None else None),
        "base_url": str(item.get("baseUrl") or "").strip() or None,
        "email": str(item.get("email") or "").strip() or None,
        "api_token": decrypt_tenant_secret(str(api_token_raw) if api_token_raw is not None else None) or None,
        "bearer": decrypt_tenant_secret(str(bearer_token_raw) if bearer_token_raw is not None else None) or None,
    }


def integration_is_usable(item: Mapping[str, object]) -> bool:
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
