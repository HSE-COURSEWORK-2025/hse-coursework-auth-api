# swagger_export.py

import json
from fastapi.openapi.utils import get_openapi
from app.main import app    # замените main на имя вашего модуля, где объявлен FastAPI()

def export_openapi(path: str = "openapi.json") -> None:
    """
    Генерирует OpenAPI-схему из приложения и сохраняет её в JSON-файл.
    """
    schema = get_openapi(
        title=app.title or "FastAPI",
        version=app.version or "0.0.0",
        description=app.description or "",
        routes=app.routes,
    )
    with open(path, "w", encoding="utf-8") as f:
        json.dump(schema, f, ensure_ascii=False, indent=2)
    print(f"✔️ OpenAPI schema exported to {path}")

if __name__ == "__main__":
    export_openapi()
