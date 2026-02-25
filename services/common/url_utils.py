"""
Utilities for checking if URLs are valid and properly formatted, including functions to validate URL formats, ensure that URLs have a scheme (defaulting to https:// if missing), and create configured HTTP clients for making requests to external services. This module provides common URL-related utilities that can be used across different parts of the application when working with URLs for external services, such as authentication providers or API endpoints.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import ipaddress
from urllib.parse import urlparse

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_MAX_URL_LENGTH = 2048


def is_safe_http_url(value: str | None) -> bool:
    if not value or not isinstance(value, str):
        return False

    if len(value) > _MAX_URL_LENGTH:
        return False

    try:
        parsed = urlparse(value.strip())
    except ValueError:
        return False

    if parsed.scheme not in _ALLOWED_SCHEMES:
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    if hostname in ("localhost",) or hostname.endswith(".local"):
        return False

    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    except ValueError:
        pass

    if not parsed.netloc or "." not in hostname:
        return False

    return True
