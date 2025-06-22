import logging
import json
import datetime

# from prometheus_fastapi_instrumentator import Instrumentator

from fastapi import FastAPI, Request
from fastapi.routing import APIRoute
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi

from app.settings import settings, app_logger
from app.api.root import root_router
from app.api.v1.router import api_v1_router
from app.services.db.schemas import Base
from app.services.db.engine import db_engine

from app.services.redis.engine import redis_client
from opentelemetry.propagate import inject

from logging_loki import LokiHandler
from logging.handlers import QueueHandler, QueueListener

from multiprocessing import Queue

from app.services.utils import PrometheusMiddleware, metrics, setting_otlp


# logger = logging.getLogger(__name__)
# setup_logging()


def custom_generate_unique_id(route: APIRoute):
    return f"{route.tags[0]}-{route.name}"


app = FastAPI(
    root_path=settings.ROOT_PATH,
    title=settings.APP_TITLE,
    version=settings.APP_VERSION,
    contact={
        "name": settings.APP_CONTACT_NAME,
        "email": str(settings.APP_CONTACT_EMAIL),
    },
    generate_unique_id_function=custom_generate_unique_id,
    openapi_url=settings.APP_OPENAPI_URL,
    docs_url=settings.APP_DOCS_URL,
    redoc_url=settings.APP_REDOC_URL,
    swagger_ui_oauth2_redirect_url=settings.APP_DOCS_URL + "/oauth2-redirect",
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    response = await call_next(request)
    status = response.status_code
    app_logger.info(
        f"{request.method} {request.url.path}",
        extra={"status_code": status}
    )
    return response


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description="API documentation with Bearer auth",
        routes=app.routes,
    )

    if settings.ROOT_PATH:
        openapi_schema["servers"] = [{"url": settings.ROOT_PATH}]

    openapi_schema["components"]["securitySchemes"] = {
        "Bearer": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            openapi_schema["paths"][path][method]["security"] = [{"Bearer": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# instrumentator = Instrumentator(
#     should_ignore_untemplated=True,
#     excluded_handlers=["/metrics"],
# ).instrument(app)


@app.on_event("startup")
async def startup_event():
    # instrumentator.expose(
    #     app,
    #     endpoint="/metrics",
    #     include_in_schema=False,
    #     tags=["root"],
    # )
    try:
        Base.metadata.create_all(bind=db_engine.engine)
    except Exception:
        pass

    await redis_client.connect()


@app.on_event("shutdown")
async def shutdown_event():
    await redis_client.disconnect()


if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


app.include_router(api_v1_router)
app.include_router(root_router)
