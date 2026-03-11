"""
Shared router-level error handling helpers (moved from routers).
Decorators for mapping expected exceptions to HTTP status codes consistently across route handlers.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from functools import wraps
from typing import Awaitable, Callable, TypeVar
import logging

import httpx
from fastapi import HTTPException, status, Request
from fastapi.responses import JSONResponse
logger = logging.getLogger(__name__)
RouteResult = TypeVar("RouteResult")

def handle_route_errors(
    *,
    bad_request_exceptions: tuple[type[Exception], ...] = (ValueError,),
    bad_request_detail: str | None = None,
    bad_gateway_exceptions: tuple[type[Exception], ...] = (httpx.HTTPError,),
    bad_gateway_detail: str = "Upstream request failed",
    internal_detail: str | None = "Internal server error",
) -> Callable[[Callable[..., Awaitable[RouteResult]]], Callable[..., Awaitable[RouteResult]]]:

    def decorator(func: Callable[..., Awaitable[RouteResult]]) -> Callable[..., Awaitable[RouteResult]]:
        @wraps(func)
        async def wrapper(*args: object, **kwargs: object) -> RouteResult:
            try:
                return await func(*args, **kwargs)
            except HTTPException:
                raise
            except bad_request_exceptions as exc:
                detail = bad_request_detail or str(exc) or "Invalid request"
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc
            except bad_gateway_exceptions as exc:
                logger.warning("Upstream request failed in %s: %s", func.__name__, exc)
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=bad_gateway_detail) from exc
            except Exception as exc:
                logger.exception("Unhandled exception in route %s: %s", func.__name__, exc)
                if internal_detail:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=internal_detail,
                    ) from exc
                raise

        return wrapper

    return decorator


def validation_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    logger.warning(f"Request validation error for {request.url}: {exc}")
    detail = exc.errors() if hasattr(exc, "errors") else [{"msg": str(exc)}]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": detail},
    )


def general_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    logger.exception(f"Unhandled exception for {request.url}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )
