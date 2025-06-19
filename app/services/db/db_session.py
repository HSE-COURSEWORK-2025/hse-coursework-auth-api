from app.services.db.engine import db_engine
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
)


async def get_session():
    """
    Асинхронный генератор, возвращающий AsyncSession.
    Используйте в хэндлерах как:
        async with get_session() as session:
            ...
    Сессия автоматически закроется при выходе из блока.
    """

    async with db_engine.create_session() as session:
        yield session
