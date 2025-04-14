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
from app.services.db.schemas import User
from app.services.db.db_session import get_session

from app.models.auth import GoogleAuthRequest, GoogleAuthCodeRequest, GoogleUser, Token, TokenRefreshRequest
from app.services.auth import get_current_user, verify_google_token, create_access_token, create_refresh_token, create_or_update_user



api_v2_auth_router = APIRouter(prefix="/auth")



# Эндпоинт аутентификации с использованием Google ID токена (старый вариант)
@api_v2_auth_router.post("/google", response_model=Token)
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

# Новый эндпоинт аутентификации с использованием authorization code
@api_v2_auth_router.post("/google-code", response_model=Token)
async def auth_google_code(request_data: GoogleAuthCodeRequest):
    # 1. Обмен authorization code на токены
    token_endpoint = "https://oauth2.googleapis.com/token"
    payload = {
        "code": request_data.code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        # Для client_secret желательно использовать отдельное значение, отличное от вашего SECRET_KEY,
        # например, settings.GOOGLE_CLIENT_SECRET
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    try:
        async with httpx.AsyncClient() as client:
            token_response = await client.post(token_endpoint, data=payload)
    except httpx.RequestError as exc:
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
    # В token_data могут быть следующие ключи: access_token, expires_in, id_token, refresh_token (если запрошен и доступен)
    id_token_value = token_data.get("id_token")
    if not id_token_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="id_token not found in token response"
        )
    
    # 2. Верификация id_token и получение данных пользователя
    google_user = await verify_google_token(id_token_value)

    # 3. Создание или обновление пользователя в БД
    session: Session = await get_session().__anext__()
    db_user = create_or_update_user(session, google_user)

    # 4. Генерация JWT токенов нашего приложения (включая access и refresh токены)
    jwt_token_data = {
        "google_sub": db_user.google_sub,
        "email": db_user.email,
        "name": db_user.name,
        "picture": db_user.picture,
    }
    access_token = create_access_token(data=jwt_token_data)
    refresh_token = create_refresh_token(data=jwt_token_data)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@api_v2_auth_router.post("/google-code-fitness", response_model=Token)
async def auth_google_code_fitness(request_data: GoogleAuthCodeRequest):
    """
    Эндпоинт для обмена authorization code на токены Google,
    предназначенные для работы с Google Fitness API.
    """
    token_endpoint = "https://oauth2.googleapis.com/token"
    payload = {
        "code": request_data.code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,  # Используйте отдельное значение для Google Client Secret
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    try:
        async with httpx.AsyncClient() as client:
            token_response = await client.post(token_endpoint, data=payload)
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error connecting to Google token endpoint"
        )

    if token_response.status_code != 200:
        raise HTTPException(
            status_code=token_response.status_code,
            detail="Error exchanging code for tokens"
        )

    # Распаковка ответа от Google, который должен содержать:
    # - access_token (для доступа к Google Fitness API)
    # - refresh_token (если запрошен и доступен)
    # - id_token (который можно использовать для верификации пользователя)
    token_data = token_response.json()
    
    # Если необходимо, можно дополнительно выполнить верификацию id_token и создать/обновить пользователя.
    # Например:
    id_token_value = token_data.get("id_token")
    if id_token_value:
        google_user = await verify_google_token(id_token_value)
        session: Session = await get_session().__anext__()
        create_or_update_user(session, google_user)
    
    # Возвращаем именно токены, полученные от Google.
    return {
        "id_token": token_data.get("id_token"),
        "access_token": token_data.get("access_token"),
        "refresh_token": token_data.get("refresh_token"),
        "token_type": "bearer",
    }


# Эндпоинт обновления токенов нашего приложения
@api_v2_auth_router.post("/refresh", response_model=Token)
async def refresh_token(refresh_req: TokenRefreshRequest):
    session: Session = await get_session().__anext__()
    try:
        payload = jwt.decode(
            refresh_req.refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
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

    user = session.query(User).filter(User.email == email).first()
    if user is None:
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


@api_v2_auth_router.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return {
        "google_sub": current_user.google_sub,
        "email": current_user.email,
        "name": current_user.name,
        "picture": current_user.picture,
    }
