# app/api/v2/qr_auth.py

import io
import os
import qrcode
from uuid import uuid4
from datetime import datetime
from typing import List

from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import StreamingResponse, FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.redis.engine import redis_client
from app.services.db.db_session import get_session
from app.services.db.schemas import Users, UserIntegrations, IntegrationSource
from app.models.auth import QRAuthData, TokenData
from app.services.auth import (
    get_current_user,
    create_access_token,
    create_refresh_token,
)
from app.settings import settings
from starlette.concurrency import run_in_threadpool

api_v1_qr_auth_router = APIRouter(prefix="/qr_auth", tags=["qr_auth"])



@api_v1_qr_auth_router.get(
    "/get_auth_qr_code", summary="Получение QR кода для аутентификации"
)
async def get_qr_code(
    current_user: TokenData = Depends(get_current_user),
):
    """
    Генерирует одноразовый QR-код, сохраняет в Redis и возвращает PNG.
    """
    try:
        user_code = uuid4().hex
        user_email = current_user.email
        key = f"{settings.QR_AUTH_REDIS_PREFIX}{user_code}"

        # Сохраняем email по ключу в Redis
        await redis_client.set(key, user_email)

        qr_url = f"{settings.DOMAIN_NAME}{settings.AUTH_API_QR_AUTH_PATH}?qr_code_data={user_code}"

        # Обёртываем генерацию QR-кода в поток
        def generate_qr_bytes() -> bytes:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(qr_url)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()

        img_bytes = await run_in_threadpool(generate_qr_bytes)

        return StreamingResponse(io.BytesIO(img_bytes), media_type="image/png")

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка генерации QR-кода",
        )


@api_v1_qr_auth_router.get(
    "/auth_using_qr_code", summary="Вход по QR коду"
)
async def process_qr_code(
    qr_code_data: str,
    session: AsyncSession = Depends(get_session),
) -> QRAuthData:
    """
    1) Читает email из Redis
    2) Удаляет ключ
    3) Ищет пользователя в БД
    4) Регистрирует интеграцию google_health_api
    5) Возвращает QRAuthData с токенами и URL
    """
    # 1) Достаём email из Redis
    key = f"{settings.QR_AUTH_REDIS_PREFIX}{qr_code_data}"
    user_email = await redis_client.get(key)
    await redis_client.delete(key)

    if not user_email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Неверные данные QR-кода",
        )

    # 2) Ищем пользователя
    q_user = select(Users).where(Users.email == user_email)
    res_user = await session.execute(q_user)
    user = res_user.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден",
        )

    # 3) Регистрируем интеграцию, если ещё не существует
    q_int = (
        select(UserIntegrations)
        .where(
            UserIntegrations.user_id == user.id,
            UserIntegrations.source == IntegrationSource.google_health_api
        )
    )
    res_int = await session.execute(q_int)
    exists = res_int.scalar_one_or_none()
    if not exists:
        new_int = UserIntegrations(
            user_id=user.id,
            source=IntegrationSource.google_health_api,
            connected_at=datetime.utcnow(),
        )
        session.add(new_int)
        await session.commit()

    # 4) Генерируем JWT
    jwt_data = {
        "google_sub": user.google_sub,
        "email":      user.email,
        "name":       user.name,
        "picture":    user.picture,
        "test_user":  user.test_user,
    }
    access_token  = create_access_token(data=jwt_data)
    refresh_token = create_refresh_token(data=jwt_data)

    # 5) Возвращаем QRAuthData
    return QRAuthData(
        post_here=f"{settings.DOMAIN_NAME}{settings.DATA_COLLECTION_API_POST_RAW_DATA_PATH}",
        access_token=access_token,
        refresh_token=refresh_token,
        refresh_token_url=f"{settings.DOMAIN_NAME}{settings.AUTH_API_REFRESH_TOKEN_PATH}",
        token_type="bearer",
        email=user.email,
    )


@api_v1_qr_auth_router.get(
    "/get_app_qr_code", summary="Получение QR-кода для скачивания приложения"
)
async def get_app_download_qr_code():
    """
    Отдаёт заранее сгенерированный PNG-файл с QR-кодом для скачивания приложения.
    """
    file_path = "./qr_app_link.png"
    if not os.path.isfile(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="QR-код не найден",
        )
    return FileResponse(path=file_path, media_type="image/png")
