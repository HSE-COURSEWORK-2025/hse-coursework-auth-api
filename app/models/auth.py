from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel



class GoogleAuthRequest(BaseModel):
    token: str


class GoogleAuthCodeRequest(BaseModel):
    code: str


class GlobalUser(BaseModel):
    sub: str
    email: str
    name: Optional[str] = None
    picture: Optional[str] = None
    test_user: Optional[bool] = None
    birth_date: Optional[datetime] = datetime(2000, 1, 1, tzinfo=timezone.utc).replace(
        tzinfo=None
    )
    gender: Optional[str] = "male"


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
