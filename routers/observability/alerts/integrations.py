from fastapi import APIRouter, Depends

from custom_types.json import JSONDict
from middleware.dependencies import require_permission_with_scope
from models.access.auth_models import Permission, TokenData
from services.alerting.integration_security_service import allowed_channel_types

router = APIRouter()


@router.get("/integrations/channel-types")
async def get_integration_channel_types(
    current_user: TokenData = Depends(require_permission_with_scope(Permission.READ_CHANNELS, "alertmanager")),
) -> JSONDict:
    return {"allowedTypes": allowed_channel_types()}
