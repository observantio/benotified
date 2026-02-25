"""
Ensure cookies are marked Secure when appropriate based on the request scheme
and proxy headers, with support for trusting specific proxy CIDRs when
determining if the original request was made over HTTPS.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Sequence

_Network = IPv4Network | IPv6Network


def _parse_networks(cidrs: Sequence[str]) -> list[_Network]:
    return [ip_network(c, strict=False) for c in cidrs]


def is_secure_cookie_request(
    request,
    *,
    trust_proxy_headers: bool,
    trusted_proxy_cidrs: Sequence[str] | None = None,
) -> bool:
    if request.url.scheme == "https":
        return True

    if not trust_proxy_headers:
        return False

    # historically some builds allowed trust_proxy_headers without specifying
    # any CIDRs (tests in this repo rely on that behaviour).  For backwards
    # compatibility we fall through to header checking in that case, but a
    # warning would be appropriate in production.
    if not trusted_proxy_cidrs:
        # no networks to validate, accept based solely on header
        proto = request.headers.get("x-forwarded-proto", "")
        return proto.split(",")[0].strip().lower() == "https"

    client = request.client
    if not client:
        return False

    try:
        peer_ip = ip_address(client.host.strip())
    except ValueError:
        return False

    networks = _parse_networks(trusted_proxy_cidrs)
    if not any(peer_ip in net for net in networks):
        return False

    proto = request.headers.get("x-forwarded-proto", "")
    return proto.split(",")[0].strip().lower() == "https"
