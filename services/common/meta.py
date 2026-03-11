"""
Incident metadata parsing and shared group ID extraction utilities for handling custom metadata annotations on incidents, allowing for flexible storage of additional information such as shared group IDs in either dictionary or JSON string format within the incident's annotations. This module provides functions to safely parse the metadata and extract shared group IDs while ensuring that only valid string group IDs are returned.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from collections.abc import Mapping
import json
from json import JSONDecodeError

from custom_types.json import JSONDict, is_json_object

INCIDENT_META_KEY = "beobservant_meta"

def parse_meta(annotations: object) -> JSONDict:
    if not isinstance(annotations, dict):
        return {}
    raw = annotations.get(INCIDENT_META_KEY)
    if is_json_object(raw):
        return raw
    if isinstance(raw, str):
        try:
            payload = json.loads(raw)
            if is_json_object(payload):
                return payload
            return {}
        except JSONDecodeError:
            return {}
    return {}

def _safe_group_ids(meta: Mapping[str, object]) -> list[str]:
    raw_group_ids = meta.get("shared_group_ids")
    if not isinstance(raw_group_ids, list):
        return []
    return [str(group_id) for group_id in raw_group_ids if isinstance(group_id, str) and group_id.strip()]
