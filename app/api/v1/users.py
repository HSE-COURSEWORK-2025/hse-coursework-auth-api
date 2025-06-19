
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from urllib.parse import urlencode

from app.settings import settings
from app.services.db.schemas import (
    Users,
    GoogleFitnessAPIAccessTokens,
    GoogleFitnessAPIRefreshTokens,
)
from app.services.db.db_session import get_session
from app.services.google_api_tokens import is_token_valid, refresh_google_token
from app.services.auth import create_access_token, create_refresh_token
from app.models.users import AccessToken

api_v1_user_info_router = APIRouter(prefix="/internal/users")


@api_v1_user_info_router.get("/get_all_users")
async def get_all_users(
    session: AsyncSession = Depends(get_session),
    test_users: bool = False,
    real_users: bool = True,
):
    if test_users and real_users:
        q = select(Users)

    elif (real_users and not test_users) or (not real_users and test_users):
        q = select(Users).where(Users.test_user == test_users)

    else:
        raise HTTPException(status_code=404, detail="Users not found")

    result = await session.execute(q)
    users = result.scalars().all()

    google_fitness_api_token_url = (
        f"{settings.DOMAIN_NAME}{settings.AUTH_API_GET_GOOGLE_FITNESS_API_TOKEN_PATH}"
    )
    access_token_url = (
        f"{settings.DOMAIN_NAME}{settings.AUTH_API_GET_ACCESS_TOKEN_PATH}"
    )

    result_list = []
    for user in users:
        params = urlencode({"email": user.email})
        result_list.append(
            {
                "google_sub": user.google_sub,
                "email": user.email,
                "name": user.name,
                "picture": user.picture,
                "google_fitness_api_token_url": f"{google_fitness_api_token_url}?{params}",
                "access_token_url": f"{access_token_url}?{params}",
            }
        )

    return result_list


@api_v1_user_info_router.get(
    "/get_user_google_fitness_api_fresh_access_token", response_model=AccessToken
)
async def get_user_google_fitness_api_fresh_access_token(
    email: str, session: AsyncSession = Depends(get_session)
):
    q = select(Users).where(Users.email == email)
    result = await session.execute(q)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    access_rec: GoogleFitnessAPIAccessTokens = user.google_fitness_api_access_token
    refresh_rec: GoogleFitnessAPIRefreshTokens = user.google_fitness_api_refresh_token

    if not access_rec or not refresh_rec:
        raise HTTPException(status_code=404, detail="Tokens not found")

    if not await is_token_valid(access_rec.token):
        try:
            new_access = await refresh_google_token(refresh_rec.token)
        except Exception:
            user.need_to_refresh_google_api_token = True
            session.add(user)
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token outdated",
            )

        if not new_access:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Malformed token endpoint response",
            )

        access_rec.token = new_access
        session.add(access_rec)
        await session.commit()
        return {"access_token": new_access}

    return {"access_token": access_rec.token}


@api_v1_user_info_router.get("/get_user_auth_token", response_model=AccessToken)
async def get_user_auth_token(email: str, session: AsyncSession = Depends(get_session)):
    q = select(Users).where(Users.email == email)
    result = await session.execute(q)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    payload = {
        "google_sub": user.google_sub,
        "email": user.email,
        "name": user.name,
        "picture": user.picture,
        "test_user": False,
    }
    access = create_access_token(data=payload)
    refresh = create_refresh_token(data=payload)
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
    }
