"""
Shared router-level error handling helpers (moved from routers).
Decorators for mapping expected exceptions to HTTP status codes consistently across route handlers.


Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from functools import wraps
from typing import Any, Awaitable, Callable, TypeVar
import logging

import httpx
from fastapi import HTTPException, status


F = TypeVar("F", bound=Callable[..., Awaitable[Any]])
logger = logging.getLogger(__name__)


def handle_route_errors(
    *,
    bad_request_exceptions: tuple[type[Exception], ...] = (ValueError,),
    bad_request_detail: str | None = None,
    bad_gateway_exceptions: tuple[type[Exception], ...] = (httpx.HTTPError,),
    bad_gateway_detail: str = "Upstream request failed",
    internal_detail: str | None = "Internal server error",
) -> Callable[[F], F]:

    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
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


from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError


def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()},
    )


def general_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )
