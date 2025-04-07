from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from google.oauth2 import id_token
from google.auth.transport import requests
from pydantic import BaseModel
from jose import JWTError, jwt
from typing import Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from app.settings import settings
from app.services.db.schemas import User
from app.services.db.db_session import get_session

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

api_v2_auth_router = APIRouter(prefix="/auth")

# Pydantic-схемы
class GoogleAuthRequest(BaseModel):
    token: str

class GoogleUser(BaseModel):
    sub: str
    email: str
    name: Optional[str] = None
    picture: Optional[str] = None

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenRefreshRequest(BaseModel):
    refresh_token: str

# Функция верификации гугловского токена
async def verify_google_token(token: str) -> GoogleUser:
    try:
        idinfo = id_token.verify_oauth2_token(
            token,
            requests.Request(),
            settings.GOOGLE_CLIENT_ID
        )
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError("Invalid issuer.")
        return GoogleUser(
            sub=idinfo.get("sub"),
            email=idinfo.get("email"),
            name=idinfo.get("name"),
            picture=idinfo.get("picture")
        )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

# Функция генерации JWT токена для нашего приложения
# в полезную нагрузку которого включены все атрибуты пользователя из БД
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)

# Функция генерации refresh токена
def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)

# Эндпоинт для аутентификации через Google
@api_v2_auth_router.post("/google", response_model=Token)
async def auth_google(request: GoogleAuthRequest):
    session: Session = await get_session().__anext__()

    # Верификация гугловского токена
    google_user = await verify_google_token(request.token)

    # Поиск пользователя по google_sub в БД
    db_user = session.query(User).filter(User.google_sub == google_user.sub).first()
    if not db_user:
        # Если пользователь не найден, создаём нового
        db_user = User(
            google_sub=google_user.sub,
            email=google_user.email,
            name=google_user.name,
            picture=google_user.picture
        )
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
    else:
        # Если пользователь найден, проверяем актуальность данных из Google
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

    # Формирование данных для токена с включением всех атрибутов пользователя
    token_data = {
        "google_sub": db_user.google_sub,
        "email": db_user.email,
        "name": db_user.name,
        "picture": db_user.picture
    }

    access_token = create_access_token(data=token_data)
    refresh_token = create_refresh_token(data=token_data)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

# Эндпоинт для обновления токенов
@api_v2_auth_router.post("/refresh", response_model=Token)
async def refresh_token(refresh_req: TokenRefreshRequest):
    session: Session = await get_session().__anext__()

    try:
        payload = jwt.decode(refresh_req.refresh_token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("email")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token payload invalid"
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    user = session.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    token_data = {
        "google_sub": user.google_sub,
        "email": user.email,
        "name": user.name,
        "picture": user.picture
    }
    new_access_token = create_access_token(data=token_data)
    new_refresh_token = create_refresh_token(data=token_data)
    return {"access_token": new_access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}

# Защищённый эндпоинт для примера
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    session: Session = await get_session().__anext__()

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("email")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = session.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

@api_v2_auth_router.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return {
        "google_sub": current_user.google_sub,
        "email": current_user.email,
        "name": current_user.name,
        "picture": current_user.picture
    }
