"""
Provider interfaces and implementations for secrets management, defining a protocol for secret providers and a simple implementation that reads secrets from environment variables. The SecretProvider protocol specifies methods for retrieving individual secrets by key as well as retrieving multiple secrets at once, while the EnvSecretProvider provides a concrete implementation that accesses secrets stored in the process environment. This module allows for flexible integration of different secret management solutions by adhering to the defined protocol, enabling secure handling of sensitive information such as API keys, database credentials, and other configuration secrets within the application.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Protocol


class SecretProvider(Protocol):
    def get(self, key: str) -> Optional[str]: ...
    def get_many(self, keys: List[str]) -> Dict[str, Optional[str]]: ...


class EnvSecretProvider:
    def get(self, key: str) -> Optional[str]:
        return os.environ.get(key) or None

    def get_many(self, keys: List[str]) -> Dict[str, Optional[str]]:
        return {k: self.get(k) for k in keys}


def build_secret_provider() -> SecretProvider:
    vault_addr = os.getenv("VAULT_ADDR", "").strip()
    if not vault_addr:
        return EnvSecretProvider()

    from vault import VaultClientError, VaultSecretProvider

    token = os.getenv("VAULT_TOKEN", "").strip() or None
    role_id = os.getenv("VAULT_ROLE_ID", "").strip() or None
    secret_id_file = os.getenv("VAULT_SECRET_ID_FILE", "").strip() or None
    secret_id = os.getenv("VAULT_SECRET_ID", "").strip() or None

    secret_id_fn = None
    if role_id:
        if secret_id_file:
            def secret_id_fn() -> str:
                with open(secret_id_file) as f:
                    return f.read().strip()
        elif secret_id:
            secret_id_fn = lambda: secret_id
        else:
            raise VaultClientError(
                "VAULT_ROLE_ID set but neither VAULT_SECRET_ID nor VAULT_SECRET_ID_FILE provided"
            )

    return VaultSecretProvider(
        address=vault_addr,
        token=token,
        role_id=role_id,
        secret_id_fn=secret_id_fn,
        prefix=os.getenv("VAULT_PREFIX", "secret").strip(),
        kv_version=int(os.getenv("VAULT_KV_VERSION", "2")),
        timeout=float(os.getenv("VAULT_TIMEOUT", "2.0")),
        cacert=os.getenv("VAULT_CACERT", "").strip() or None,
        cache_ttl=float(os.getenv("VAULT_CACHE_TTL", "30.0")),
    )