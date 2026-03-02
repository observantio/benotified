"""
Access control utilities for checking user permissions and resolving group memberships for tenant-based resources.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
from typing import List, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from db_models import Group

logger = logging.getLogger(__name__)


def _resolve_groups(
    db: Session,
    tenant_id: str,
    group_ids: List[str],
    *,
    actor_group_ids: Optional[List[str]] = None,
    enforce_membership: bool = True,
) -> List[Group]:
    normalized = [s for gid in (group_ids or []) if gid is not None and (s := str(gid).strip())]
    if not normalized:
        return []

    groups = db.query(Group).filter(Group.tenant_id == tenant_id, Group.id.in_(normalized)).all()
    present_ids = {g.id for g in groups}
    missing = [gid for gid in normalized if gid not in present_ids]
    if missing:
        logger.warning("Skipping unknown group IDs for tenant %s: %s", tenant_id, missing)

    if enforce_membership:
        actor_groups = set(actor_group_ids or [])
        unauthorized = [gid for gid in normalized if gid in present_ids and gid not in actor_groups]
        if unauthorized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User is not a member of one or more specified groups",
            )

    return groups


def assign_shared_groups(
    db_obj,
    db: Session,
    tenant_id: str,
    visibility: str,
    group_ids: Optional[List[str]],
    *,
    actor_group_ids: Optional[List[str]],
):
    if visibility != "group":
        db_obj.shared_groups = []
        return
    if group_ids is None:
        raise ValueError("group_ids is required when visibility is 'group'")
    db_obj.shared_groups = _resolve_groups(
        db, tenant_id, group_ids,
        actor_group_ids=actor_group_ids,
    )


def has_access(
    visibility: str,
    created_by: Optional[str],
    user_id: str,
    shared_group_ids: List[str],
    user_group_ids: List[str],
    require_write: bool = False,
) -> bool:
    if created_by == user_id:
        return True
    if require_write:
        return False
    if visibility in ("public", "tenant"):
        return True
    if visibility == "group":
        return bool(set(shared_group_ids) & set(user_group_ids))
    if visibility == "private":
        return False
    logger.warning("Unknown visibility value %r encountered in access check", visibility)
    return False