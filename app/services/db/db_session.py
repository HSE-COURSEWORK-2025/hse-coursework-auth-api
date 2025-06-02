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
    # Вместо явного session = db_engine.create_session() и ручного закрытия —
    # используем асинхронный контекстный менеджер
    async with db_engine.create_session() as session:
        yield session
