"""Alertmanager routers split by resource domain."""

from fastapi import APIRouter

from .alerts_routes import router as alerts_router
from .access import router as access_router
from .channels import router as channels_router
from .integrations import router as integrations_router
from .rules import router as rules_router
from .silences import router as silences_router
from .status import router as status_router
from .webhooks import router as webhooks_router

router = APIRouter(prefix="/api/alertmanager", tags=["alertmanager"])
router.include_router(alerts_router)
router.include_router(access_router)
router.include_router(integrations_router)
router.include_router(silences_router)
router.include_router(status_router)
router.include_router(rules_router)
router.include_router(channels_router)

webhook_router = APIRouter(tags=["alertmanager-webhooks"])
webhook_router.include_router(webhooks_router)

__all__ = ["router", "webhook_router"]
