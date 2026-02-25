"""
Silences operations for managing Alertmanager silences, including fetching, creating, updating, and deleting silences, as well as applying metadata and access control based on user permissions.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""
import asyncio
from typing import Dict, List, Optional

import httpx

from database import get_db_session
from db_models import PurgedSilence
from models.access.auth_models import TokenData
from models.alerting.silences import Silence, SilenceCreate, Visibility


def apply_silence_metadata(service, silence: Silence) -> Silence:
    data = service.decode_silence_comment(silence.comment)
    silence.comment = data["comment"]
    silence.visibility = data["visibility"]
    silence.shared_group_ids = data["shared_group_ids"]
    return silence


def silence_accessible(service, silence: Silence, current_user: TokenData) -> bool:
    visibility = silence.visibility or Visibility.TENANT.value
    if silence.created_by == current_user.username:
        return True
    if visibility == Visibility.TENANT.value:
        return True
    if visibility == Visibility.GROUP.value:
        user_group_ids = getattr(current_user, "group_ids", []) or []
        return any(group_id in silence.shared_group_ids for group_id in user_group_ids)
    return False


async def get_silences(service, filter_labels: Optional[Dict[str, str]] = None) -> List[Silence]:
    params = {}
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
        except Exception:
            purged_ids = set()

        if not purged_ids:
            return raw

        ids_removed = [s.id for s in raw if s.id and s.id in purged_ids]
        if ids_removed:
            service.logger.debug("Excluding purged silences from results: %s", ids_removed)
        return [s for s in raw if not (s.id and s.id in purged_ids)]
    except httpx.HTTPError as exc:
        service.logger.error("Error fetching silences: %s", exc)
        return []


async def get_silence(service, silence_id: str) -> Optional[Silence]:
    try:
        response = await service._client.get(f"{service.alertmanager_url}/api/v2/silence/{silence_id}")
        response.raise_for_status()
        return Silence(**response.json())
    except httpx.HTTPError as exc:
        service.logger.error("Error fetching silence %s: %s", silence_id, exc)
        return None


async def create_silence(service, silence: SilenceCreate) -> Optional[str]:
    try:
        response = await service._client.post(
            f"{service.alertmanager_url}/api/v2/silences",
            json=silence.model_dump(by_alias=True, exclude_none=True),
        )
        response.raise_for_status()
        return response.json().get("silenceID")
    except httpx.HTTPError as exc:
        service.logger.error("Error creating silence: %s", exc)
        return None


async def delete_silence(service, silence_id: str) -> bool:
    try:
        response = await service._client.delete(f"{service.alertmanager_url}/api/v2/silence/{silence_id}")
        response.raise_for_status()

        for attempt in range(3):
            await asyncio.sleep(0.3 * (attempt + 1))
            remaining = await get_silence(service, silence_id)
            if remaining is None:
                return True
            try:
                state = (remaining.status or {}).get("state")
            except Exception:
                state = None
            if state and str(state).lower() == "expired":
                return True

        service.logger.error("Silence %s still present after delete call", silence_id)
        return False
    except httpx.HTTPError as exc:
        service.logger.error("Error deleting silence %s: %s", silence_id, exc)
        return False


async def update_silence(service, silence_id: str, silence: SilenceCreate) -> Optional[str]:
    await delete_silence(service, silence_id)
    return await create_silence(service, silence)
