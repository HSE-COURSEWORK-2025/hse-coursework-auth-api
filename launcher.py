import uvicorn
from app.settings import settings


log_config = uvicorn.config.LOGGING_CONFIG
log_config["formatters"]["access"]["fmt"] = "%(message)s"
uvicorn.run(
    "app.main:app",
    host="0.0.0.0",
    port=settings.PORT,
    log_level=str(settings.LOG_LEVEL).lower(),
    access_log=True,
)
