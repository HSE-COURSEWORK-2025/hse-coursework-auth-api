# HSE Coursework: Auth API

## Описание

Этот репозиторий содержит сервис аутентификации. Сервис поддерживает аутентификацию через Google и тестовые аккаунты, а также передает данные для выгрузки по QR-коду. Также сервис хранит токены пользователей.

## Основные возможности
- Авторизация через Google OAuth2
- Генерация и обновление JWT-токенов
- Авторизация через тестовые аккаунты
- Генерация QR-кода с информацией для выгрузи из [мобильного приложения](https://github.com/HSE-COURSEWORK-2025/hse-coursework-android-app)
- Хранение и обновление access токенов Google Fitness API

## Структура проекта

- `app/` — основной код приложения
  - `api/` — роутеры FastAPI
  - `models/` — Pydantic-схемы
  - `services/` — бизнес-логика, работа с БД, Redis, Google API
  - `settings.py` — глобальные настройки приложения
- `deployment/` — манифесты Kubernetes (Deployment, Service)
- `requirements.txt` — зависимости Python
- `Dockerfile` — сборка Docker-образа
- `launcher.py`, `launch_app.sh` — запуск приложения

## Быстрый старт (локально)

1. **Установите зависимости:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Создайте файл `.env` или используйте `.env.development`**
3. **Запустите приложение:**
   ```bash
   python launcher.py
   ```
   или через Uvicorn:
   ```bash
   uvicorn app.main:app --reload --port 8080
   ```

## Переменные окружения

- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` — OAuth2 Google
- `GOOGLE_REDIRECT_URI` — URI для редиректа Google OAuth
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` — параметры БД
- `REDIS_HOST`, `REDIS_PORT` — параметры Redis
- `SECRET_KEY` — секрет для подписи JWT
- `ROOT_PATH`, `PORT` — путь и порт приложения
- `DOMAIN_NAME` — домен для формирования ссылок

Пример `.env`:
```
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
ROOT_PATH=/auth-api
PORT=8080
DB_HOST=localhost
...
```

## Сборка и запуск в Docker

```bash
docker build -t awesomecosmonaut/auth-api-app .
docker run -p 8080:8080 --env-file .env awesomecosmonaut/auth-api-app
```

## Деплой в Kubernetes

1. Соберите и отправьте образ:
   ```bash
   ./deploy.sh
   ```
2. Остановить сервис:
   ```bash
   ./stop.sh
   ```
3. Манифесты находятся в папке `deployment/` (Deployment, Service)

## Метрики и документация
- Swagger UI: `/auth-api/docs`
- OpenAPI: `/auth-api/openapi.json`
- Метрики Prometheus: `/auth-api/metrics`
