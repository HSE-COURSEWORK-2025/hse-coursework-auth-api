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


# Pydantic-схемы
class GoogleAuthRequest(BaseModel):
    token: str  # для старого варианта (ID токен с клиента)


class GoogleAuthCodeRequest(BaseModel):
    code: str  # authorization code, полученный через initCodeClient на клиенте


class GlobalUser(BaseModel):
    sub: str
    email: str
    name: Optional[str] = None
    picture: Optional[str] = None
    test_user: Optional[bool] = None


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class TokenData(BaseModel):
    google_sub: str
    email: str
    name: str
    picture: str
    test_user: Optional[bool] = False


class QRAuthData(BaseModel):
    post_here: str
    access_token: str
    refresh_token: str
    refresh_token_url: str
    token_type: str
    email: str
