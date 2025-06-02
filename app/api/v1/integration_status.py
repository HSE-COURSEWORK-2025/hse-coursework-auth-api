# app/api/v2/qr_auth.py

import io
from typing import List
import qrcode
from uuid import uuid4
from datetime import datetime

from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.redis.engine import redis_client
from app.services.db.db_session import get_session
from app.services.db.schemas import Users, UserIntegrations, IntegrationSource

from app.models.auth import (
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

from pydantic import BaseModel


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
    session: AsyncSession = Depends(get_session),
) -> List[IntegrationOut]:
    """
    Возвращает все подключения (источники) для авторизованного пользователя.
    """
    # Находим пользователя по google_sub
    stmt_user = select(Users).where(Users.google_sub == current_user.google_sub)
    result_user = await session.execute(stmt_user)
    db_user = result_user.scalar_one_or_none()

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден",
        )

    # Загружаем интеграции этого пользователя
    stmt_integr = (
        select(UserIntegrations)
        .where(UserIntegrations.user_id == db_user.id)
        .order_by(UserIntegrations.connected_at)
    )
    result_int = await session.execute(stmt_integr)
    integrations = result_int.scalars().all()

    return integrations
