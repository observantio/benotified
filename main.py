"""
Entrypoint for the BeNotified service.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Awaitable, Callable
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.responses import Response
from config import config
from database import connection_test, ensure_database_exists, init_database, init_db
from middleware.headers import security_headers_middleware
from middleware.error_handlers import general_exception_handler, validation_exception_handler
from middleware.concurrency_limit import ConcurrencyLimitMiddleware
from middleware.request_size_limit import RequestSizeLimitMiddleware
from routers.observability.alerts import router as alertmanager_alerts_router, webhook_router as alertmanager_webhook_router
from routers.observability.incidents import router as alertmanager_incidents_router
from routers.observability.jira import router as alertmanager_jira_router

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("benotified")

ensure_database_exists(config.BENOTIFIED_DATABASE_URL)
init_database(config.BENOTIFIED_DATABASE_URL, config.LOG_LEVEL == "debug")
init_db()

app = FastAPI(
    title="BeNotified",
    description="Internal alerting service for BeObservant",
    version="1.0.0",
    docs_url="/docs" if config.ENABLE_API_DOCS else None,
    redoc_url="/redoc" if config.ENABLE_API_DOCS else None,
    openapi_url="/openapi.json" if config.ENABLE_API_DOCS else None,
)

app.middleware("http")(security_headers_middleware)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, general_exception_handler)

app.add_middleware(RequestSizeLimitMiddleware, max_bytes=config.MAX_REQUEST_BYTES)
app.add_middleware(
    ConcurrencyLimitMiddleware,
    max_concurrent=config.MAX_CONCURRENT_REQUESTS,
    acquire_timeout=config.CONCURRENCY_ACQUIRE_TIMEOUT,
)


@app.middleware("http")
async def require_internal_service_token(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    allowed_paths = {"/health", "/ready"}
    if config.ENABLE_API_DOCS:
        allowed_paths.update({"/docs", "/redoc", "/openapi.json"})

    if request.url.path in allowed_paths:
        return await call_next(request)

    if request.url.path in {
        "/internal/v1/alertmanager/alerts/webhook",
        "/internal/v1/alertmanager/alerts/critical",
        "/internal/v1/alertmanager/alerts/warning",
    }:
        return await call_next(request)

    expected = config.get_secret("BENOTIFIED_EXPECTED_SERVICE_TOKEN") or config.get_secret("GATEWAY_INTERNAL_SERVICE_TOKEN")
    if not expected:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Service token not configured"},
        )

    provided = request.headers.get("X-Service-Token")
    if not provided or not secrets.compare_digest(provided, expected):
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": "Forbidden"})

    return await call_next(request)


app.include_router(alertmanager_alerts_router, prefix="/internal/v1")
app.include_router(alertmanager_incidents_router, prefix="/internal/v1")
app.include_router(alertmanager_jira_router, prefix="/internal/v1")

app.include_router(alertmanager_webhook_router, prefix="/internal/v1/alertmanager")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "benotified"}


@app.get("/ready", response_model=None)
async def ready() -> JSONResponse:
    checks: dict[str, bool] = {"database": connection_test()}
    ok = all(checks.values())
    payload: dict[str, bool | str | dict[str, bool]] = {"status": "ready" if ok else "not_ready", "checks": checks}
    if not ok:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=payload)
    return JSONResponse(status_code=status.HTTP_200_OK, content=payload)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.HOST, port=config.PORT, loop="uvloop", log_level=config.LOG_LEVEL)
