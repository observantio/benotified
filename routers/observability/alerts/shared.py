"""Shared services and helper utilities for alertmanager routers."""

import logging
from typing import Sequence

from fastapi import HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError

from models.access.auth_models import TokenData
from models.alerting.channels import NotificationChannel, NotificationChannelCreate
from models.alerting.silences import SilenceCreate, SilenceCreateRequest, Visibility
from custom_types.json import JSONDict
from services.alerting.integration_security_service import allowed_channel_types, validate_shared_group_ids_for_user
from services.alertmanager_service import AlertManagerService
from services.notification_service import NotificationService
from services.storage_db_service import DatabaseStorageService

logger = logging.getLogger(__name__)

INVALID_FILTER_LABELS_JSON = "Invalid filter_labels JSON"

alertmanager_service = AlertManagerService()
notification_service = NotificationService()
storage_service = DatabaseStorageService()


class HideTogglePayload(BaseModel):
    hidden: bool = True


def scope_header(request: Request) -> str:
    return request.headers.get("x-scope-orgid") or request.headers.get("X-Scope-OrgID") or ""


async def sync_incidents(tenant_id: str, alerts: Sequence[JSONDict], *, log_context: str) -> None:
    try:
        await run_in_threadpool(storage_service.sync_incidents_from_alerts, tenant_id, list(alerts), False)
    except SQLAlchemyError as exc:
        logger.warning("Incident sync skipped (%s): %s", log_context, exc)


def build_silence_payload(silence: SilenceCreateRequest, current_user: TokenData) -> SilenceCreate:
    visibility = alertmanager_service.normalize_visibility(silence.visibility)
    shared_group_ids = (
        validate_shared_group_ids_for_user(
            current_user.tenant_id,
            silence.shared_group_ids or [],
            current_user,
        )
        if visibility == Visibility.GROUP.value
        else []
    )
    return SilenceCreate.parse_obj(
        {
            "matchers": silence.matchers,
            "startsAt": silence.starts_at,
            "endsAt": silence.ends_at,
            "createdBy": current_user.user_id,
            "comment": alertmanager_service.encode_silence_comment(silence.comment, visibility, shared_group_ids),
        }
    )


def validate_channel(
    channel: NotificationChannel | NotificationChannelCreate,
    channel_service: NotificationService,
) -> str:
    requested_type = str(channel.type or "").strip().lower()
    if requested_type not in allowed_channel_types():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Channel type '{requested_type}' is disabled by organization policy",
        )
    errors = channel_service.validate_channel_config(requested_type, channel.config)
    if errors:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"errors": errors, "status": "error"})
    return requested_type
