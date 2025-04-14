from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from google.oauth2 import id_token
from google.auth.transport import requests
from pydantic import BaseModel
from jose import JWTError, jwt
from typing import Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

from app.settings import settings
from app.services.db.schemas import User
from app.services.db.db_session import get_session
from app.models.auth import (
    GoogleAuthRequest,
    GoogleAuthCodeRequest,
    GoogleUser,
    Token,
    TokenRefreshRequest,
    TokenData,
)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> TokenData:
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        print(e)

    user = TokenData.parse_obj(payload)
    return user


# Функция верификации гугловского ID токена
async def verify_google_token(token: str) -> GoogleUser:
    try:
        idinfo = google_id_token.verify_oauth2_token(
            token, google_requests.Request(), settings.GOOGLE_CLIENT_ID
        )
        if idinfo["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
            raise ValueError("Invalid issuer.")
        return GoogleUser(
            sub=idinfo.get("sub"),
            email=idinfo.get("email"),
            name=idinfo.get("name"),
            picture=idinfo.get("picture"),
        )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )


# Генерация JWT access токена нашего приложения
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


# Генерация JWT refresh токена нашего приложения
def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


# Функция для создания/обновления пользователя в БД по данным из Google
def create_or_update_user(session: Session, google_user: GoogleUser) -> User:
    db_user = session.query(User).filter(User.google_sub == google_user.sub).first()
    if not db_user:
        # Если пользователь не найден, создаём нового
        db_user = User(
            google_sub=google_user.sub,
            email=google_user.email,
            name=google_user.name,
            picture=google_user.picture,
        )
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
    else:
        # Если найден, обновляем при необходимости
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
            session.commit()
            session.refresh(db_user)
    return db_user
