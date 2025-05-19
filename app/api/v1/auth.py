import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.settings import settings
from app.services.db.schemas import Users, UserIntegrations, IntegrationSource
from app.services.db.db_session import get_session

from app.models.auth import (
    GoogleAuthRequest,
    GoogleAuthCodeRequest,
    GoogleUser,
    Token,
    TokenRefreshRequest,
    TokenData,
)
from app.services.auth import (
    get_current_user,
    verify_google_token,
    create_access_token,
    create_refresh_token,
    create_or_update_user,
    create_or_update_user_access_token,
    create_or_update_user_refresh_token,
)


api_v1_auth_router = APIRouter(prefix="/auth")


# Эндпоинт аутентификации с использованием Google ID токена (старый вариант)
@api_v1_auth_router.post("/google", response_model=Token)
async def auth_google(request_data: GoogleAuthRequest):
    session: Session = await get_session().__anext__()

    # Верификация гугловского ID токена
    google_user = await verify_google_token(request_data.token)

    db_user = create_or_update_user(session, google_user)

    # Формирование данных для JWT нашего приложения
    token_data = {
        "google_sub": db_user.google_sub,
        "email": db_user.email,
        "name": db_user.name,
        "picture": db_user.picture,
    }
    access_token = create_access_token(data=token_data)
    refresh_token = create_refresh_token(data=token_data)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@api_v1_auth_router.post("/google-code-fitness", response_model=Token)
async def auth_google_code_fitness(request_data: GoogleAuthCodeRequest):
    """
    Эндпоинт для обмена authorization code на токены Google Fitness API
    и создания записи об интеграции google_fitness_api.
    """
    # 1) Обмениваем код на токены у Google
    token_endpoint = "https://oauth2.googleapis.com/token"
    payload = {
        "code": request_data.code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    logging.info(f'payload: {payload}')

    try:
        async with httpx.AsyncClient() as client:
            token_response = await client.post(token_endpoint, data=payload)
    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error connecting to Google token endpoint",
        )

    if token_response.status_code != 200:
        raise HTTPException(
            status_code=token_response.status_code,
            detail="Error exchanging code for tokens",
        )

    token_data = token_response.json()

    # 2) Верифицируем id_token и получаем данные пользователя
    id_token_value = token_data.get("id_token")
    if not id_token_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing id_token in Google response",
        )
    google_user = await verify_google_token(id_token_value)

    # 3) Открываем сессию и создаём/обновляем пользователя и его токены
    session: Session = await get_session().__anext__()
    db_user = create_or_update_user(session, google_user)
    create_or_update_user_access_token(
        session, google_user, token_data.get("access_token")
    )
    create_or_update_user_refresh_token(
        session, google_user, token_data.get("refresh_token")
    )

    # 4) Отмечаем, что токен не нужно рефрешить
    db_user.need_to_refresh_google_api_token = False
    session.add(db_user)

    # 5) Регистрируем интеграцию Google Fitness API
    exists = (
        session.query(UserIntegrations)
        .filter_by(user_id=db_user.id, source=IntegrationSource.google_fitness_api)
        .first()
    )
    if not exists:
        integration = UserIntegrations(
            user_id=db_user.id,
            source=IntegrationSource.google_fitness_api,
            connected_at=datetime.utcnow(),
        )
        session.add(integration)

    # 6) Сохраняем всё в БД
    session.commit()
    session.refresh(db_user)

    # 7) Генерируем JWT для клиента
    jwt_payload = {
        "google_sub": db_user.google_sub,
        "email": db_user.email,
        "name": db_user.name,
        "picture": db_user.picture,
    }
    access_token = create_access_token(data=jwt_payload)
    refresh_token = create_refresh_token(data=jwt_payload)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


# Эндпоинт обновления токенов нашего приложения
@api_v1_auth_router.post("/refresh", response_model=Token)
async def refresh_token(refresh_req: TokenRefreshRequest):
    session: Session = await get_session().__anext__()
    try:
        payload = jwt.decode(
            refresh_req.refresh_token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        email: str = payload.get("email")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token payload invalid",
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )

    user = session.query(Users).filter(Users.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )

    if user.need_to_refresh_google_api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )

    token_data = {
        "google_sub": user.google_sub,
        "email": user.email,
        "name": user.name,
        "picture": user.picture,
    }
    new_access_token = create_access_token(data=token_data)
    new_refresh_token = create_refresh_token(data=token_data)
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }


@api_v1_auth_router.get("/users/me")
async def read_users_me(current_user: TokenData = Depends(get_current_user)):
    return {
        "google_sub": current_user.google_sub,
        "email": current_user.email,
        "name": current_user.name,
        "picture": current_user.picture,
    }
