"""
Encryption utilities for symmetrically encrypting and decrypting sensitive configuration data using Fernet encryption. This module provides functions to encrypt and decrypt dictionary configurations, ensuring that sensitive information such as API keys and channel credentials are stored securely in the database and can be recovered only with the correct encryption key.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""
import json
import logging
from functools import lru_cache
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from config import config as app_config

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _get_fernet() -> Fernet:
    key = app_config.DATA_ENCRYPTION_KEY
    if not key:
        raise RuntimeError("DATA_ENCRYPTION_KEY is not configured")
    try:
        return Fernet(key)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Invalid DATA_ENCRYPTION_KEY format") from exc


def encrypt_config(cfg: dict[str, Any]) -> dict[str, Any]:
    try:
        f = _get_fernet()
        payload = json.dumps(cfg, default=str).encode()
        return {"__encrypted__": f.encrypt(payload).decode()}
    except RuntimeError:
        raise
    except Exception as exc:
        raise ValueError("Failed to encrypt channel config") from exc


def decrypt_config(cfg: dict[str, Any]) -> dict[str, Any]:
    if "__encrypted__" not in cfg:
        return cfg
    try:
        f = _get_fernet()
        return json.loads(f.decrypt(cfg["__encrypted__"].encode()).decode())
    except RuntimeError:
        raise
    except InvalidToken as exc:
        raise ValueError("Cannot decrypt channel config – wrong key or corrupted data") from exc
    except Exception as exc:
        raise ValueError("Failed to decrypt channel config") from exc
