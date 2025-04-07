import uvicorn
from app.settings import settings

uvicorn.run(
    "app.main:app",
    host="0.0.0.0",
    port=settings.PORT,
    log_level=str(settings.LOG_LEVEL).lower(),
)
