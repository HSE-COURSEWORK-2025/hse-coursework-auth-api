from pathlib import Path
import logging
import secrets
from pydantic import AnyHttpUrl, validator, EmailStr
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    LOG_LEVEL: str = "DEBUG"
    LOG_UVICORN_FORMAT: str = "%(asctime)s %(levelname)s uvicorn: %(message)s"
    LOG_ACCESS_FORMAT: str = "%(asctime)s %(levelname)s access: %(message)s"
    LOG_DEFAULT_FORMAT: str = "%(asctime)s %(levelname)s %(name)s: %(message)s"

    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    APP_VERSION: str = "dev"
    APP_TITLE: str = "HSE-COURSEWORK Auth API"
    APP_CONTACT_NAME: str = "MALYSH_II"
    APP_CONTACT_EMAIL: EmailStr = "iimalysh@edu.hse.ru"
    APP_OPENAPI_URL: str = "/openapi.json"
    APP_DOCS_URL: str | None = "/docs"
    APP_REDOC_URL: str | None = None
    PRODUCTION: bool = False

    ROOT_PATH: str | None = "/auth-api"
    PORT: int | None = 8080

    SECRET_KEY: str = secrets.token_urlsafe(32)

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8
    BACKEND_CORS_ORIGINS: list[AnyHttpUrl] = []

    GOOGLE_CLIENT_ID: str | None = None

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: str | list[str]) -> str | list[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    class Config:
        # env_file = ".env"
        env_file = ".env.development"
        env_file_encoding = "utf-8"
        case_sensitive = False
        env_nested_delimiter = "__"
        extra = "allow"


settings = Settings()


def setup_logging():
    logging.basicConfig(
        level=settings.LOG_LEVEL.upper(),
        format=settings.LOG_DEFAULT_FORMAT,
    )
    # uvicorn
    handler_default = logging.StreamHandler()
    handler_default.setFormatter(logging.Formatter(settings.LOG_UVICORN_FORMAT))
    logging.getLogger("uvicorn").handlers = [handler_default]
    # uvicorn access
    handler_access = logging.StreamHandler()
    handler_access.setFormatter(logging.Formatter(settings.LOG_ACCESS_FORMAT))
    logging.getLogger("uvicorn.access").handlers = [handler_access]
