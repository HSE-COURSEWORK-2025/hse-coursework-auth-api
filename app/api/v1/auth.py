import logging
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.settings import settings
from app.services.db.schemas import Users, UserIntegrations, IntegrationSource
from app.services.db.engine import db_engine
from app.services.db.db_session import get_session
from app.services.auth import (
    verify_google_token,
    create_access_token,
    create_refresh_token,
    create_or_update_user,
    create_or_update_user_access_token,
    create_or_update_user_refresh_token,
    get_current_user,
)
from app.models.auth import (
    GoogleAuthCodeRequest,
    Token,
    TokenRefreshRequest,
    TokenData,
    GlobalUser,
)

api_v1_auth_router = APIRouter(prefix="/auth")
logger = logging.getLogger("auth")


@api_v1_auth_router.post(
    "/google-code-fitness",
    response_model=Token,
    summary="Авторизация через Google Fitness (code → токены)",
)
async def auth_google_code_fitness(
    request_data: GoogleAuthCodeRequest,
    session: AsyncSession = Depends(get_session),
) -> Token:
    # 1) Exchange code for tokens
    token_endpoint = "https://oauth2.googleapis.com/token"
    payload = {
        "code": request_data.code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(token_endpoint, data=payload)
        token_resp.raise_for_status()
        token_data = token_resp.json()

        access_token = token_data["access_token"]

        # 2) Дополнительный запрос в People API
        people_endpoint = (
            "https://people.googleapis.com/v1/people/me"
            "?personFields=genders,birthdays"
        )
        people_resp = await client.get(
            people_endpoint,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        people_resp.raise_for_status()
        profile = people_resp.json()

    # 3) Парсим пол
    gender = None
    for g in profile.get("genders", []):
        meta = g.get("metadata", {})
        if meta.get("primary", False):
            gender = g.get("value")
            break
    if gender is None and profile.get("genders"):
        gender = profile["genders"][0].get("value")

    # 4) Парсим дату рождения
    bdate = None
    
    year = 2000
    month = 1
    day = 1

    for b in profile.get("birthdays", []):
        if b.get("metadata", {}).get("primary"):
            d = b.get("date", {})
            if d:
                year = d.get("year") if d.get("year") else year
                month = d.get("month") if d.get("month") else month
                day = d.get("day") if d.get("day") else day
            
            
    if bdate is None and profile.get("birthdays"):
        d = profile["birthdays"][0].get("date", {})

        year = d.get("year") if d.get("year") else year
        month = d.get("month") if d.get("month") else month
        day = d.get("day") if d.get("day") else day
    
    bdate = datetime(year, month, day, tzinfo=timezone.utc)
    
    # 5) Verify id_token и get user info
    google_user = await verify_google_token(token_data["id_token"])

    # 6) Create/update user and store tokens
    db_user = await create_or_update_user(session, google_user)

    # 7) Записываем в модель пол и дату
    if gender:
        db_user.gender = gender
    if bdate:
        bdate_naive = bdate.astimezone(timezone.utc).replace(tzinfo=None)
        db_user.birth_date = bdate_naive

    session.add(db_user)

    await create_or_update_user_access_token(
        session, google_user, access_token
    )
    await create_or_update_user_refresh_token(
        session, google_user, token_data["refresh_token"]
    )

    # 8) Сбросим флаг обновления токена и проставим интеграцию
    db_user.need_to_refresh_google_api_token = False
    session.add(db_user)
    # … остальной код по UserIntegrations, коммит и отдача JWT …
    await session.commit()
    await session.refresh(db_user)

    jwt_payload = {
        "google_sub": db_user.google_sub,
        "email": db_user.email,
        "name": db_user.name,
        "picture": db_user.picture,
        "test_user": db_user.test_user,
    }
    return Token(
        access_token=create_access_token(data=jwt_payload),
        refresh_token=create_refresh_token(data=jwt_payload),
        token_type="bearer",
    )


@api_v1_auth_router.post(
    "/refresh", response_model=Token, summary="Обновить JWT нашего приложения"
)
async def refresh_token(
    refresh_req: TokenRefreshRequest,
    session: AsyncSession = Depends(get_session),
) -> Token:
    # 1) Decode our refresh token
    from jose import JWTError, jwt

    try:
        payload = jwt.decode(
            refresh_req.refresh_token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        email: str = payload.get("email")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid refresh payload")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # 2) Load user
    q = select(Users).where(Users.email == email)
    result = await session.execute(q)
    user = result.scalar_one_or_none()
    if not user or user.need_to_refresh_google_api_token:
        raise HTTPException(status_code=401, detail="User not found or token expired")

    # 3) Issue new tokens
    jwt_payload = {
        "google_sub": user.google_sub,
        "email": user.email,
        "name": user.name,
        "picture": user.picture,
        "test_user": user.test_user,
    }
    return Token(
        access_token=create_access_token(data=jwt_payload),
        refresh_token=create_refresh_token(data=jwt_payload),
        token_type="bearer",
    )


@api_v1_auth_router.get(
    "/users/me", response_model=TokenData, summary="Информация о текущем пользователе"
)
async def read_users_me(
    current_user: TokenData = Depends(get_current_user),
) -> TokenData:
    return current_user


@api_v1_auth_router.get(
    "/get-test-account",
    response_model=Token,
    summary="Создать или получить тестовый аккаунт",
)
async def get_test_account(
    session: AsyncSession = Depends(get_session),
) -> Token:
    # 1) Считаем количество тестовых юзеров
    cnt_q = select(func.count()).select_from(Users).where(Users.test_user.is_(True))
    result = await session.execute(cnt_q)
    test_count = result.scalar_one() or 0

    # 2) Собираем данные
    new_index = test_count + 1
    google_user = GlobalUser(
        sub=f"test-sub-{new_index}",
        email=f"test{new_index}@test.com",
        name=f"Test User {new_index}",
        picture="https://avatar.iran.liara.run/public",
        test_user=True,
    )

    # 3) Создаём или обновляем
    db_user = await create_or_update_user(session, google_user)
    await session.commit()
    await session.refresh(db_user)

    # 4) Отдаём JWT
    jwt_payload = {
        "google_sub": db_user.google_sub,
        "email": db_user.email,
        "name": db_user.name,
        "picture": db_user.picture,
        "test_user": db_user.test_user,
    }
    return Token(
        access_token=create_access_token(data=jwt_payload),
        refresh_token=create_refresh_token(data=jwt_payload),
        token_type="bearer",
    )


@api_v1_auth_router.get(
    "/auth-test-account",
    response_model=Token,
    summary="Авторизация через тестовый аккаунт",
)
async def auth_test_account(
    test_account_login: str,
    session: AsyncSession = Depends(get_session),
) -> Token:
    q = select(Users).where(
        Users.google_sub == test_account_login
    )
    result = await session.execute(q)
    found_user = result.scalar_one_or_none()
    if not found_user:
        raise HTTPException(status_code=404, detail="User login not found")

    # 7) Issue our JWTs
    jwt_payload = {
        "google_sub": found_user.google_sub,
        "email": found_user.email,
        "name": found_user.name,
        "picture": found_user.picture,
        "test_user": found_user.test_user,
    }
    access_token = create_access_token(data=jwt_payload)
    refresh_token = create_refresh_token(data=jwt_payload)

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )
