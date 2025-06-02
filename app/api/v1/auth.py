import logging
from datetime import datetime

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
    logger.info(f"Exchanging Google code for tokens, payload={payload}")

    try:
        async with httpx.AsyncClient() as client:
            token_response = await client.post(token_endpoint, data=payload)
    except httpx.RequestError as e:
        logger.error("Error connecting to Google token endpoint", exc_info=e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error connecting to Google token endpoint",
        )

    if token_response.status_code != 200:
        logger.error("Google token exchange failed: %s", token_response.text)
        raise HTTPException(
            status_code=token_response.status_code,
            detail="Error exchanging code for tokens",
        )
    token_data = token_response.json()

    # 2) Verify id_token
    id_token_value = token_data.get("id_token")
    if not id_token_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing id_token in Google response",
        )
    google_user = await verify_google_token(id_token_value)

    # 3) Create/update user and store Google API tokens
    db_user = await create_or_update_user(session, google_user)
    await create_or_update_user_access_token(
        session, google_user, token_data["access_token"]
    )
    await create_or_update_user_refresh_token(
        session, google_user, token_data["refresh_token"]
    )

    # 4) Mark that we just got fresh Google tokens
    db_user.need_to_refresh_google_api_token = False
    session.add(db_user)

    # 5) Ensure UserIntegrations row exists
    q = select(UserIntegrations).where(
        UserIntegrations.user_id == db_user.id,
        UserIntegrations.source == IntegrationSource.google_fitness_api,
    )
    result = await session.execute(q)
    if not result.scalar_one_or_none():
        ui = UserIntegrations(
            user_id=db_user.id,
            source=IntegrationSource.google_fitness_api,
            connected_at=datetime.utcnow(),
        )
        session.add(ui)

    # 6) Commit & refresh
    await session.commit()
    await session.refresh(db_user)

    # 7) Issue our JWTs
    jwt_payload = {
        "google_sub": db_user.google_sub,
        "email": db_user.email,
        "name": db_user.name,
        "picture": db_user.picture,
        "test_user": db_user.test_user,
    }
    access_token = create_access_token(data=jwt_payload)
    refresh_token = create_refresh_token(data=jwt_payload)

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
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
        picture="https://img.redro.pl/obrazy/user-icon-human-person-symbol-avatar-login-sign-400-260853306.jpg",
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
