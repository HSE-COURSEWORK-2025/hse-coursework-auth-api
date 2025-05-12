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
    GoogleUser,
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

api_v1_qr_auth_router = APIRouter(prefix="/qr_auth", tags=["qr_auth"])


@api_v1_qr_auth_router.get("/get_auth_qr_code", summary="Получение QR кода")
async def get_qr_code(current_user: TokenData = Depends(get_current_user)):
    """
    Эндпоинт для генерации QR кода.

    - **data**: Строка с данными для кодирования.
    - **size**: (опционально) Размер изображения в пикселях.
    """
    try:
        user_code = uuid4()
        user_email = current_user.email
        key = f"{settings.QR_AUTH_PREFIX}{user_code}"
        await redis_client.set(key, user_email)

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        data = f"{settings.AUTH_API_URL}{settings.AUTH_API_QR_AUTH_PATH}?qr_code_data={user_code}"
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return StreamingResponse(buf, media_type="image/png")

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка генерации QR-кода",
        )


@api_v1_qr_auth_router.get("/auth_using_qr_code", summary="Вход по QR коду")
async def process_qr_code(qr_code_data: str) -> QRAuthData:
    """
    Обрабатывает одноразовый код из QR.
    1) Читает email из Redis
    2) Удаляет ключ
    3) Вытаскивает пользователя из БД
    4) Добавляет запись в user_integrations с source=google_health_api
    5) Возвращает токены
    """
    try:
        # 1) Достаём email из Redis
        key = f"{settings.QR_AUTH_PREFIX}{qr_code_data}"
        user_email = await redis_client.get(key)
        await redis_client.delete(key)

        if user_email is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Неверные данные QR-кода",
            )

        # 2) Берём сессию и пользователя
        session: Session = await get_session().__anext__()
        user = session.query(Users).filter(Users.email == user_email).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Пользователь не найден",
            )

        # 3) Регистрируем интеграцию Google Health API
        exists = (
            session.query(UserIntegrations)
            .filter_by(user_id=user.id, source=IntegrationSource.google_health_api)
            .first()
        )
        if not exists:
            integration = UserIntegrations(
                user_id=user.id,
                source=IntegrationSource.google_health_api,
                connected_at=datetime.utcnow(),
            )
            session.add(integration)
            session.commit()

        # 4) Генерируем токены
        jwt_data = {
            "google_sub": user.google_sub,
            "email": user.email,
            "name": user.name,
            "picture": user.picture,
        }
        access_token = create_access_token(data=jwt_data)
        refresh_token = create_refresh_token(data=jwt_data)

        # 5) Формируем ответ
        return QRAuthData(
            post_here=f"{settings.DATA_COLLECTION_API_URL}{settings.DATA_COLLECTION_API_POST_RAW_DATA_PATH}",
            access_token=access_token,
            refresh_token=refresh_token,
            refresh_token_url=f"{settings.AUTH_API_URL}{settings.AUTH_API_REFRESH_TOKEN_PATH}",
            token_type="bearer",
            email=user.email,
        )

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка получении данных по QR-коду",
        )
