"""
Silence metadata encoding and decoding for Alertmanager silences, allowing storage of visibility and shared group information within the silence comment field.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import json
from typing import Dict, List, Optional

from models.alerting.silences import Visibility


SILENCE_META_PREFIX = "[beobservant-meta]"

_VALID_VISIBILITIES = {v.value for v in Visibility}


def normalize_visibility(value: Optional[str]) -> str:
    if isinstance(value, Visibility):
        return value.value
    normalized = str(value).lower() if value else ""
    if normalized not in _VALID_VISIBILITIES:
        return Visibility.PRIVATE.value
    return normalized


def encode_silence_comment(comment: str, visibility: str, shared_group_ids: List[str]) -> str:
    payload = json.dumps({"visibility": visibility, "shared_group_ids": shared_group_ids or []}, separators=(",", ":"))
    return f"{SILENCE_META_PREFIX}{payload}\n{comment}"


def decode_silence_comment(comment: Optional[str]) -> Dict[str, object]:
    _default_visibility = Visibility.TENANT.value

    if not comment or not comment.startswith(SILENCE_META_PREFIX):
        return {"comment": comment or "", "visibility": _default_visibility, "shared_group_ids": []}

    raw = comment[len(SILENCE_META_PREFIX):]
    meta_str, comment_text = raw.split("\n", 1) if "\n" in raw else (raw, "")

    try:
        meta = json.loads(meta_str)
    except json.JSONDecodeError:
        return {"comment": comment, "visibility": _default_visibility, "shared_group_ids": []}

    visibility = normalize_visibility(meta.get("visibility") or _default_visibility)
    shared_group_ids = meta.get("shared_group_ids") or []
    if not isinstance(shared_group_ids, list):
        shared_group_ids = []

    return {"comment": comment_text, "visibility": visibility, "shared_group_ids": shared_group_ids}
