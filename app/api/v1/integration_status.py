# app/api/v2/qr_auth.py

import io
from typing import Optional
import qrcode
from uuid import uuid4
from datetime import datetime

from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.services.redis.engine import redis_client
from app.services.db.db_session import get_session
from app.services.db.schemas import Users, UserIntegrations, IntegrationSource

from app.models.auth import (
    GoogleAuthRequest,
    GoogleAuthCodeRequest,
    GlobalUser,
    Token,
    TokenRefreshRequest,
    QRAuthData,
    TokenData,
)
from app.services.auth import (
    get_current_user,
    verify_google_token,
    create_access_token,
    create_refresh_token,
)
from app.settings import settings

from typing import List
from pydantic import BaseModel
from datetime import datetime
from fastapi import Depends


api_v1_integrations_router = APIRouter(prefix="/integrations", tags=["integrations"])


class IntegrationOut(BaseModel):
    id: int
    source: IntegrationSource
    connected_at: datetime

    class Config:
        orm_mode = True


@api_v1_integrations_router.get(
    "/integrations",
    response_model=List[IntegrationOut],
    summary="Получение списка интеграций текущего пользователя",
)
async def get_user_integrations(
    current_user: TokenData = Depends(get_current_user),
) -> List[IntegrationOut]:
    """
    Возвращает все подключения (источники) для авторизованного пользователя.
    """
    session: Session = await get_session().__anext__()

    db_user = (
        session.query(Users)
        .filter(Users.google_sub == current_user.google_sub)
        .first()
    )

    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="Пользователь не найден",
        )

    return db_user.integrations
