from fastapi import APIRouter
from .auth import api_v2_auth_router
from .qr_auth import api_v2_qr_auth_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(api_v2_auth_router, tags=["auth"])
api_v1_router.include_router(api_v2_qr_auth_router, tags=["qr_auth"])
