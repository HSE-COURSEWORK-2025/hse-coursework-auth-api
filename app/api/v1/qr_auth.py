import io
from typing import Optional

import qrcode
from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel


from uuid import uuid4
from app.services.redis.engine import redis_client
from app.models.auth import (
    GoogleAuthRequest,
    GoogleAuthCodeRequest,
    GoogleUser,
    Token,
    TokenRefreshRequest,
    QRAuthData,
    TokenData
)
from app.services.auth import (
    get_current_user,
    verify_google_token,
    create_access_token,
    create_refresh_token,
    create_or_update_user,
)
from app.services.db.schemas import User
from app.settings import settings
from app.services.db.db_session import get_session
from sqlalchemy.orm import Session


api_v2_qr_auth_router = APIRouter(prefix="/qr_auth", tags=["qr_auth"])


@api_v2_qr_auth_router.get("/get_auth_qr_code", summary="Получение QR кода")
async def get_qr_code(current_user: TokenData = Depends(get_current_user)):
    """
    Эндпоинт для генерации QR кода.

    - **data**: Строка с данными для кодирования.
    - **size**: (опционально) Размер изображения в пикселях.
    """
    try:
        # Генерация QR кода с использованием библиотеки qrcode

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

        # Формирование ответа в виде потока байтов
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return StreamingResponse(buf, media_type="image/png")

    except Exception as e:
        # Логирование ошибки можно добавить при необходимости
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка генерации QR-кода",
        )


@api_v2_qr_auth_router.get("/auth_using_qr_code", summary="Вход по QR коду")
async def process_qr_code(qr_code_data: str) -> QRAuthData:
    try:
        # Генерация QR кода с использованием библиотеки qrcode

        key = f"{settings.QR_AUTH_PREFIX}{qr_code_data}"
        user_email = await redis_client.get(key)

        if user_email is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Неверные данные QR-кода: {str(e)}",
            )

        session: Session = await get_session().__anext__()
        user = session.query(User).filter(User.email == user_email).first()
        jwt_token_data = {
            "google_sub": user.google_sub,
            "email": user.email,
            "name": user.name,
            "picture": user.picture,
        }
        access_token = create_access_token(data=jwt_token_data)
        refresh_token = create_refresh_token(data=jwt_token_data)
        post_to_url = f"{settings.DATA_COLLECTION_API_URL}{settings.DATA_COLLECTION_API_POST_RAW_DATA_PATH}"
        refresh_token_url = f"{settings.AUTH_API_URL}{settings.AUTH_API_REFRESH_TOKEN_PATH}"
        # await redis_client.delete(key)
        return QRAuthData(
            post_here=post_to_url,
            access_token=access_token,
            refresh_token=refresh_token,
            refresh_token_url=refresh_token_url,
            token_type="bearer",
        )

    except Exception as e:
        # Логирование ошибки можно добавить при необходимости
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка получении данных по QR-коду",
        )
