import logging

import httpx
from fastapi import HTTPException, status

from app.settings import settings



TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
TOKENINFO_ENDPOINT = "https://oauth2.googleapis.com/tokeninfo"


async def is_token_valid(access_token: str) -> bool:
    tokeninfo_url = f"{TOKENINFO_ENDPOINT}?access_token={access_token}"
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(tokeninfo_url, timeout=5.0)
    except Exception as e:
        logging.error("Error calling tokeninfo endpoint: %s", e)
        return False

    if resp.status_code != 200:
        return False

    data = resp.json()
    try:
        return int(data.get("expires_in", 0)) > 0
    except (ValueError, TypeError):
        return False


async def refresh_google_token(refresh_token: str) -> dict:
    payload = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            TOKEN_ENDPOINT,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10.0,
        )
    if resp.status_code != 200:
        logging.warning("Google token refresh failed: %s", resp.text)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token outdated"
        )

    refresh_data = resp.json()

    new_access = refresh_data.get("access_token")

    if not new_access:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Malformed token endpoint response",
        )

    return new_access
