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


# Pydantic-схемы
class GoogleAuthRequest(BaseModel):
    token: str  # для старого варианта (ID токен с клиента)

class GoogleAuthCodeRequest(BaseModel):
    code: str  # authorization code, полученный через initCodeClient на клиенте

class GoogleUser(BaseModel):
    sub: str
    email: str
    name: Optional[str] = None
    picture: Optional[str] = None

class Token(BaseModel):
    id_token: Optional[str] = None
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
