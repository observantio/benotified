"""
Incident metadata parsing and shared group ID extraction utilities for handling custom metadata annotations on incidents, allowing for flexible storage of additional information such as shared group IDs in either dictionary or JSON string format within the incident's annotations. This module provides functions to safely parse the metadata and extract shared group IDs while ensuring that only valid string group IDs are returned.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from typing import Any, Dict, List
import json
from json import JSONDecodeError

INCIDENT_META_KEY = "beobservant_meta"

def parse_meta(annotations: Any) -> Dict[str, Any]:
    if not isinstance(annotations, dict):
        return {}
    raw = annotations.get(INCIDENT_META_KEY)
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except JSONDecodeError:
            return {}
    return {}

def _safe_group_ids(meta: Dict[str, Any]) -> List[str]:
    return [str(g) for g in (meta.get("shared_group_ids") or []) if isinstance(g, str) and g.strip()]
