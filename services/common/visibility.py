"""
Normalization utilities for handling visibility settings on resources...

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations
from typing import Optional

DEFAULT_ALLOWED: frozenset[str] = frozenset({"tenant", "group", "private"})
STORAGE_ALLOWED: frozenset[str] = frozenset({"public", "private", "group"})

def normalize_visibility(
    value: Optional[str],
    *,
    default_value: str = "private",
    public_alias: str = "tenant",
    allowed: Optional[frozenset[str]] = None,
) -> str:
    allowed_values = allowed if allowed is not None else DEFAULT_ALLOWED

    if default_value not in allowed_values:
        raise ValueError(f"default_value {default_value!r} is not in allowed {allowed_values}")
    if public_alias not in allowed_values:
        raise ValueError(f"public_alias {public_alias!r} is not in allowed {allowed_values}")
    normalized = (value or "").strip().lower()
    if not normalized:
        return default_value
    if normalized in allowed_values:
        return normalized
    if normalized == "public":
        return public_alias
    return default_value

def normalize_storage_visibility(value: Optional[str]) -> str:
    normalized = (value or "").strip().lower()
    if normalized in STORAGE_ALLOWED:
        return normalized
    if normalized == "tenant":
        return "public"
    return "public"
