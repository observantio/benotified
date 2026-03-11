"""
Silences operations for managing Alertmanager silences, including fetching, creating, updating, and deleting silences, as well as applying metadata and access control based on user permissions.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import TYPE_CHECKING, Dict, List, Optional
import httpx
import logging
from sqlalchemy.exc import SQLAlchemyError
from database import get_db_session
from db_models import PurgedSilence
from models.access.auth_models import TokenData
from models.alerting.silences import Silence, SilenceCreate, Visibility

if TYPE_CHECKING:
    from services.alertmanager_service import AlertManagerService

logger = logging.getLogger(__name__)

QueryParamValue = str | int | float | bool | None


def _visibility_value(value: object) -> Visibility:
    if isinstance(value, Visibility):
        return value
    raw = str(value or Visibility.TENANT.value).strip().lower()
    try:
        return Visibility(raw)
    except ValueError:
        return Visibility.TENANT

def apply_silence_metadata(service: AlertManagerService, silence: Silence) -> Silence:
    data = service.decode_silence_comment(silence.comment)
    comment = data.get("comment")
    visibility = data.get("visibility")
    shared_group_ids = data.get("shared_group_ids")
    silence.comment = str(comment or "")
    silence.visibility = _visibility_value(visibility)
    silence.shared_group_ids = [str(group_id) for group_id in shared_group_ids] if isinstance(shared_group_ids, list) else []
    return silence


def silence_accessible(silence: Silence, current_user: TokenData) -> bool:
    visibility = _visibility_value(silence.visibility)
    actor_id = str(getattr(current_user, "user_id", "") or "").strip()
    if actor_id and str(silence.created_by or "").strip() == actor_id:
        return True
    if visibility == Visibility.TENANT:
        return True
    if visibility == Visibility.GROUP:
        user_group_ids = getattr(current_user, "group_ids", []) or []
        return any(group_id in silence.shared_group_ids for group_id in user_group_ids)
    return False


def silence_owned_by(silence: Silence, current_user: TokenData) -> bool:
    owner = str(getattr(silence, "created_by", "") or "").strip()
    if not owner:
        return False
    actor_id = str(getattr(current_user, "user_id", "") or "").strip()
    return bool(actor_id) and owner == actor_id


async def prune_removed_member_group_silences(
    service: AlertManagerService,
    *,
    group_id: str,
    removed_user_ids: Optional[List[str]] = None,
    removed_usernames: Optional[List[str]] = None,
) -> int:
    target_group_id = str(group_id or "").strip()
    if not target_group_id:
        return 0

    removed_identifiers = {
        str(v or "").strip()
        for v in (removed_user_ids or []) + (removed_usernames or [])
        if str(v or "").strip()
    }
    removed_identifiers_lower = {v.lower() for v in removed_identifiers}
    if not removed_identifiers:
        return 0

    silences = await get_silences(service, filter_labels=None)
    updated = 0
    for silence in silences:
        silence = apply_silence_metadata(service, silence)
        if _visibility_value(silence.visibility) != Visibility.GROUP:
            continue
        if not silence.id:
            continue

        owner = str(getattr(silence, "created_by", "") or "").strip()
        if not owner:
            continue
        if owner not in removed_identifiers and owner.lower() not in removed_identifiers_lower:
            continue

        shared = [str(g).strip() for g in (silence.shared_group_ids or []) if str(g).strip()]
        if target_group_id not in shared:
            continue
        remaining = [gid for gid in shared if gid != target_group_id]
        next_visibility = Visibility.GROUP.value if remaining else Visibility.PRIVATE.value

        payload = SilenceCreate.model_validate(
            {
                "matchers": silence.matchers,
                "startsAt": silence.starts_at,
                "endsAt": silence.ends_at,
                "createdBy": silence.created_by,
                "comment": service.encode_silence_comment(silence.comment, next_visibility, remaining),
            }
        )
        new_id = await update_silence(service, silence.id, payload)
        if new_id:
            updated += 1
    return updated


async def get_silences(service: AlertManagerService, filter_labels: Optional[Dict[str, str]] = None) -> List[Silence]:
    params: Dict[str, QueryParamValue | Sequence[QueryParamValue]] = {}
    if filter_labels:
        params["filter"] = [f'{k}="{v}"' for k, v in filter_labels.items()]

    try:
        response = await service._client.get(
            f"{service.alertmanager_url}/api/v2/silences",
            params=params,
        )
        response.raise_for_status()
        raw = [Silence(**s) for s in response.json()]

        try:
            with get_db_session() as db:
                purged_ids = {p.id for p in db.query(PurgedSilence).all()}
        except SQLAlchemyError:
            purged_ids = set()

        if not purged_ids:
            return raw

        ids_removed = [s.id for s in raw if s.id and s.id in purged_ids]
        if ids_removed:
            logger.debug("Excluding purged silences from results: %s", ids_removed)
        return [s for s in raw if not (s.id and s.id in purged_ids)]
    except httpx.HTTPError as exc:
        logger.error("Error fetching silences: %s", exc)
        return []


async def get_silence(service: AlertManagerService, silence_id: str) -> Optional[Silence]:
    try:
        response = await service._client.get(f"{service.alertmanager_url}/api/v2/silence/{silence_id}")
        response.raise_for_status()
        return Silence(**response.json())
    except httpx.HTTPError as exc:
        logger.error("Error fetching silence %s: %s", silence_id, exc)
        return None


async def create_silence(service: AlertManagerService, silence: SilenceCreate) -> Optional[str]:
    try:
        response = await service._client.post(
            f"{service.alertmanager_url}/api/v2/silences",
            json=silence.model_dump(by_alias=True, exclude_none=True),
        )
        response.raise_for_status()
        payload = response.json()
        silence_id = payload.get("silenceID") if isinstance(payload, dict) else None
        return str(silence_id) if isinstance(silence_id, str) else None
    except httpx.HTTPError as exc:
        logger.error("Error creating silence: %s", exc)
        return None


async def delete_silence(service: AlertManagerService, silence_id: str) -> bool:
    try:
        response = await service._client.delete(f"{service.alertmanager_url}/api/v2/silence/{silence_id}")
        response.raise_for_status()

        for attempt in range(3):
            await asyncio.sleep(0.3 * (attempt + 1))
            remaining = await get_silence(service, silence_id)
            if remaining is None:
                return True
            state = (remaining.status or {}).get("state") if isinstance(remaining.status, dict) else None
            if state and str(state).lower() == "expired":
                return True

        logger.error("Silence %s still present after delete call", silence_id)
        return False
    except httpx.HTTPError as exc:
        logger.error("Error deleting silence %s: %s", silence_id, exc)
        return False


async def update_silence(service: AlertManagerService, silence_id: str, silence: SilenceCreate) -> Optional[str]:
    await delete_silence(service, silence_id)
    return await create_silence(service, silence)
