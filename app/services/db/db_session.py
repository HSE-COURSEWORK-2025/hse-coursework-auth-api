from app.services.db.engine import db_engine


async def get_session():
    session = db_engine.create_session()
    try:
        yield session
    finally:
        session.close()
