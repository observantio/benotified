"""
Shared HTTP client utilities for making requests to external services, including functions for handling authentication, error handling, and response parsing. This module provides a common interface for making HTTP requests to services like Keycloak for user provisioning and token validation, abstracting away the details of the HTTP interactions and allowing for easier integration with different authentication providers.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import httpx
from config import config

def create_async_client(timeout_seconds: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_seconds),
        limits=httpx.Limits(
            max_connections=config.HTTP_CLIENT_MAX_CONNECTIONS,
            max_keepalive_connections=config.HTTP_CLIENT_MAX_KEEPALIVE_CONNECTIONS,
            keepalive_expiry=config.HTTP_CLIENT_KEEPALIVE_EXPIRY,
        ),
    )
