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
from app.services.db.schemas import Users
from app.services.db.db_session import get_session

from app.models.auth import (
    GoogleAuthRequest,
    GoogleAuthCodeRequest,
    GoogleUser,
    TokenRefreshRequest,
    TokenData,
)
from app.models.users import (
    AccessToken
)
from fastapi.responses import JSONResponse
from app.services.db.schemas import (
    GoogleFitnessAPIAccessTokens,
    GoogleFitnessAPIRefreshTokens,
)
from app.services.google_api_tokens import is_token_valid, refresh_google_token
from urllib.parse import urlencode


api_v2_user_info_router = APIRouter(prefix="/internal/users")


# Получить всех пользователей
@api_v2_user_info_router.get("/get_all_users")
async def get_all_users():
    session: Session = await get_session().__anext__()
    users = session.query(Users).all()

    # Соберём базовый URL до параметров
    base = f"{settings.AUTH_API_URL}{settings.AUTH_API_GET_FRESH_GOOGLE_FITNESS_API_TOKEN_PATH}"

    result = []
    for user in users:
        # Кодируем email как query-параметр
        params = urlencode({"email": user.email})
        result.append(
            {
                "google_sub": user.google_sub,
                "email": user.email,
                "name": user.name,
                "picture": user.picture,
                "fresh_access_token_url": f"{base}?{params}",
            }
        )

    return result


@api_v2_user_info_router.get(
    "/get_user_google_fitness_api_fresh_access_token", response_model=AccessToken
)
async def get_user_google_fitness_api_fresh_access_token(email: str):
    session = await get_session().__anext__()

    user = session.query(Users).filter(Users.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    access_rec: GoogleFitnessAPIAccessTokens = user.google_fitness_api_access_token
    refresh_rec: GoogleFitnessAPIRefreshTokens = user.google_fitness_api_refresh_token

    if not access_rec or not refresh_rec:
        raise HTTPException(status_code=404, detail="Tokens not found")

    if not await is_token_valid(access_rec.token):
        try:
            new_access_token = await refresh_google_token(refresh_rec.token)
        except Exception as e:
            user.need_to_refresh_google_api_token = True
            session.add(user)
            session.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token outdated"
            )


        if not new_access_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Malformed token endpoint response",
            )

        access_rec.token = new_access_token
        session.add(access_rec)
        session.commit()

        access_token = new_access_token
    else:
        access_token = access_rec.token

    return {"access_token": access_token}
