import logging

from prometheus_fastapi_instrumentator import Instrumentator

from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from starlette.middleware.cors import CORSMiddleware

from app.settings import settings, setup_logging
from app.api.root import root_router
from app.api.v1.router import api_v1_router
from app.services.db.schemas import Base
from app.services.db.engine import db_engine

logger = logging.getLogger(__name__)
setup_logging()


# кастомизация для генератора openapi клиента
def custom_generate_unique_id(route: APIRoute):
    return f"{route.tags[0]}-{route.name}"


app = FastAPI(
    root_path=settings.ROOT_PATH,
    title=settings.APP_TITLE,
    version=settings.APP_VERSION,
    contact={
        "name": settings.APP_CONTACT_NAME,
        "email": str(settings.APP_CONTACT_EMAIL),
        # "url": str(settings.APP_CONTACT_URL),
    },
    generate_unique_id_function=custom_generate_unique_id,
    openapi_url=settings.APP_OPENAPI_URL,
    docs_url=settings.APP_DOCS_URL,
    redoc_url=settings.APP_REDOC_URL,
    swagger_ui_oauth2_redirect_url=settings.APP_DOCS_URL + "/oauth2-redirect",
)

# Custom OpenAPI schema with Bearer token security scheme
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description="API documentation with Bearer auth",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "Bearer": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    # Apply security scheme globally
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            openapi_schema["paths"][path][method]["security"] = [{"Bearer": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

instrumentator = Instrumentator(
    should_ignore_untemplated=True,
    excluded_handlers=["/metrics"],
).instrument(app)


@app.on_event("startup")
async def startup_event():
    instrumentator.expose(
        app,
        endpoint="/metrics",
        include_in_schema=False,
        tags=["root"],
    )
    try:
        Base.metadata.create_all(bind=db_engine.engine)
    except Exception:
        pass


@app.on_event("shutdown")
async def shutdown_event():
    # await cmdb_client_stop()
    # await FastAPILimiter.close()
    ...


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
