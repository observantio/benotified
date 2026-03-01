"""
Helpers for migrating legacy plaintext tenant secrets to encrypted values.
"""

from __future__ import annotations

import copy
from typing import Any, Iterable

from cryptography.fernet import Fernet

_SECRET_KEYS = ("api_token", "bearer", "apiToken", "bearerToken")


def _normalize_secret_value(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def encrypt_legacy_secret(value: Any, fernet: Fernet) -> tuple[str | None, bool]:
    normalized = _normalize_secret_value(value)
    if normalized is None:
        return None, value is not None
    if normalized.startswith("enc:"):
        return normalized, False
    encrypted = fernet.encrypt(normalized.encode("utf-8")).decode("utf-8")
    return f"enc:{encrypted}", True


def migrate_tenant_settings_payload(
    settings: Any,
    fernet: Fernet,
) -> tuple[Any, list[str]]:
    if not isinstance(settings, dict):
        return settings, []

    updated = copy.deepcopy(settings)
    changed_fields: list[str] = []

    jira = updated.get("jira")
    if isinstance(jira, dict):
        _migrate_secret_fields(
            jira,
            _SECRET_KEYS,
            fernet,
            changed_fields,
            path_prefix="jira",
        )

    integrations = updated.get("jira_integrations")
    if isinstance(integrations, list):
        for index, item in enumerate(integrations):
            if not isinstance(item, dict):
                continue
            _migrate_secret_fields(
                item,
                _SECRET_KEYS,
                fernet,
                changed_fields,
                path_prefix=f"jira_integrations[{index}]",
            )

    return updated, changed_fields


def _migrate_secret_fields(
    payload: dict[str, Any],
    keys: Iterable[str],
    fernet: Fernet,
    changed_fields: list[str],
    *,
    path_prefix: str,
) -> None:
    for key in keys:
        if key not in payload:
            continue
        encrypted, changed = encrypt_legacy_secret(payload.get(key), fernet)
        if not changed:
            continue
        payload[key] = encrypted
        changed_fields.append(f"{path_prefix}.{key}")
