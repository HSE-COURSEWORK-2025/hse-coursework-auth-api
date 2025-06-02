import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.settings import settings
from app.services.db.schemas import (
    Users,
    GoogleFitnessAPIAccessTokens,
    GoogleFitnessAPIRefreshTokens,
)
from app.services.db.db_session import get_session
from app.models.auth import (
    GlobalUser,
    Token,
    TokenData,
)


logger = logging.getLogger("auth")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> TokenData:
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = TokenData.parse_obj(payload)
    return user


async def verify_google_token(token: str) -> GlobalUser:
    """
    Верифицирует Google ID token и возвращает GlobalUser.
    """
    try:
        idinfo = google_id_token.verify_oauth2_token(
            token, google_requests.Request(), settings.GOOGLE_CLIENT_ID
        )
        if idinfo["iss"] not in ("accounts.google.com", "https://accounts.google.com"):
            raise ValueError("Invalid issuer")
        return GlobalUser(
            sub=idinfo["sub"],
            email=idinfo["email"],
            name=idinfo.get("name"),
            picture=idinfo.get("picture"),
            test_user=False,
        )
    except ValueError:
        logger.exception("Failed to verify Google token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google token",
        )


def create_access_token(
    data: dict, expires_delta: Optional[timedelta] = None
) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta
        if expires_delta
        else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(
    data: dict, expires_delta: Optional[timedelta] = None
) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta
        if expires_delta
        else timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


async def create_or_update_user(
    session: AsyncSession, google_user: GlobalUser
) -> Users:
    """
    Находит или создаёт Users по google_sub, обновляет поля при изменении.
    """
    q = select(Users).where(Users.google_sub == google_user.sub)
    result = await session.execute(q)
    db_user = result.scalar_one_or_none()

    if not db_user:
        db_user = Users(
            google_sub=google_user.sub,
            email=google_user.email,
            name=google_user.name,
            picture=google_user.picture,
            test_user=google_user.test_user,
        )
        session.add(db_user)
        await session.commit()
        await session.refresh(db_user)
        return db_user

    # обновляем, если что-то поменялось
    updated = False
    if db_user.email != google_user.email:
        db_user.email = google_user.email
        updated = True
    if db_user.name != google_user.name:
        db_user.name = google_user.name
        updated = True
    if db_user.picture != google_user.picture:
        db_user.picture = google_user.picture
        updated = True

    if updated:
        session.add(db_user)
        await session.commit()
        await session.refresh(db_user)

    return db_user


async def create_or_update_user_access_token(
    session: AsyncSession, google_user: GlobalUser, access_token: str
) -> None:
    """
    Сохраняет или обновляет GoogleFitnessAPIAccessTokens для пользователя.
    """
    if not access_token:
        return

    # Находим user
    q_user = select(Users).where(Users.google_sub == google_user.sub)
    res_user = await session.execute(q_user)
    db_user = res_user.scalar_one_or_none()
    if not db_user:
        return

    # Ищем существующий токен
    q = select(GoogleFitnessAPIAccessTokens).where(
        GoogleFitnessAPIAccessTokens.user_id == db_user.id
    )
    res = await session.execute(q)
    curr = res.scalar_one_or_none()

    if not curr:
        new = GoogleFitnessAPIAccessTokens(
            user_id=db_user.id, token=access_token
        )
        session.add(new)
    else:
        curr.token = access_token
        session.add(curr)

    await session.commit()


async def create_or_update_user_refresh_token(
    session: AsyncSession, google_user: GlobalUser, refresh_token: str
) -> None:
    """
    Сохраняет или обновляет GoogleFitnessAPIRefreshTokens для пользователя.
    """
    if not refresh_token:
        return

    q_user = select(Users).where(Users.google_sub == google_user.sub)
    res_user = await session.execute(q_user)
    db_user = res_user.scalar_one_or_none()
    if not db_user:
        return

    q = select(GoogleFitnessAPIRefreshTokens).where(
        GoogleFitnessAPIRefreshTokens.user_id == db_user.id
    )
    res = await session.execute(q)
    curr = res.scalar_one_or_none()

    if not curr:
        new = GoogleFitnessAPIRefreshTokens(
            user_id=db_user.id, token=refresh_token
        )
        session.add(new)
    else:
        curr.token = refresh_token
        session.add(curr)

    await session.commit()
