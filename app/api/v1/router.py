from fastapi import APIRouter
from .auth import api_v1_auth_router
from .qr_auth import api_v1_qr_auth_router
from .users import api_v1_user_info_router
from .integration_status import api_v1_integrations_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(api_v1_auth_router, tags=["auth"])
api_v1_router.include_router(api_v1_qr_auth_router, tags=["qr_auth"])
api_v1_router.include_router(api_v1_user_info_router, tags=["users_info"])
api_v1_router.include_router(api_v1_integrations_router, tags=["integrations"])
