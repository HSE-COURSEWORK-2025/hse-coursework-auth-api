from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from app.settings import settings

root_router = APIRouter(
    include_in_schema=False,
    tags=["root"],
)


@root_router.get("/", status_code=200, name="root")
def get_root():
    content = f"""
        <html>
        <head><title>{settings.APP_TITLE}</title></head>
        <body>
        <h1>{settings.APP_TITLE}</h1>
        """
    if settings.APP_DOCS_URL:
        content += f"""
        <p><a href='/auth-api{settings.APP_DOCS_URL}'>Swagger UI</a></p>
        """
    if settings.APP_REDOC_URL:
        content += f"""
        <p><a href='/auth-api{settings.APP_REDOC_URL}'>ReDoc</a></p>
        """
    content += """
        <p><a href='/auth-api/metrics'>Metrics</a></p>
        </body>
        </html>
        """
    return HTMLResponse(content=content)


@root_router.get("/status", status_code=200, name="status")
def get_health():
    return "ok"
