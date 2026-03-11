"""
Resilience decorators for service calls and rate limiting.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import asyncio
import logging
import random
from functools import wraps
from typing import Awaitable, Callable, ParamSpec, TypeVar
import httpx

from config import config

logger = logging.getLogger(__name__)

P = ParamSpec('P')
T = TypeVar('T')
AsyncFunc = Callable[P, Awaitable[T]]

def with_retry(
    max_retries: int = config.MAX_RETRIES,
    backoff: float = config.RETRY_BACKOFF
) -> Callable[[AsyncFunc[P, T]], AsyncFunc[P, T]]:
    def decorator(func: AsyncFunc[P, T]) -> AsyncFunc[P, T]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            last_exception: Exception | None = None

            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except httpx.HTTPStatusError as exc:
                    status_code = exc.response.status_code
                    if 400 <= status_code < 500:
                        logger.debug(
                            "%s: non-retriable HTTPStatusError %s — failing fast",
                            func.__name__, status_code
                        )
                        raise

                    last_exception = exc
                    if attempt < max_retries:
                        wait_time = min(config.RETRY_MAX_BACKOFF, backoff * (2 ** attempt))
                        jitter = wait_time * max(0.0, config.RETRY_JITTER)
                        wait_time = max(0.0, wait_time + random.uniform(-jitter, jitter))
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_retries + 1} failed for "
                            f"{func.__name__}: {exc}. Retrying in {wait_time}s..."
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(
                            f"All {max_retries + 1} attempts failed for "
                            f"{func.__name__}: {exc}"
                        )
                except (httpx.RequestError, asyncio.TimeoutError) as exc:
                    last_exception = exc
                    if attempt < max_retries:
                        wait_time = min(config.RETRY_MAX_BACKOFF, backoff * (2 ** attempt))
                        jitter = wait_time * max(0.0, config.RETRY_JITTER)
                        wait_time = max(0.0, wait_time + random.uniform(-jitter, jitter))
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_retries + 1} failed for "
                            f"{func.__name__}: {exc}. Retrying in {wait_time}s..."
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(
                            f"All {max_retries + 1} attempts failed for "
                            f"{func.__name__}: {exc}"
                        )

            if last_exception is not None:
                raise last_exception
            raise RuntimeError(f"Retry wrapper exited without result or captured exception for {func.__name__}")

        return wrapper
    return decorator


def with_timeout(timeout: float = config.DEFAULT_TIMEOUT) -> Callable[[AsyncFunc[P, T]], AsyncFunc[P, T]]:
    def decorator(func: AsyncFunc[P, T]) -> AsyncFunc[P, T]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout)
            except asyncio.TimeoutError:
                logger.error(f"Timeout after {timeout}s for {func.__name__}")
                raise

        return wrapper
    return decorator
