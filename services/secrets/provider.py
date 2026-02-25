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

    def get(self, key: str) -> Optional[str]:
        ...

    def get_many(self, keys: List[str]) -> Dict[str, Optional[str]]:
        ...


class EnvSecretProvider:

    def get(self, key: str) -> Optional[str]:
        val = os.getenv(key)
        return val if val else None

    def get_many(self, keys: List[str]) -> Dict[str, Optional[str]]:
        return {k: self.get(k) for k in keys}
