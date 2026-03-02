"""
Configuration management for the application, loading settings from environment variables with support for defaults, type conversion, and validation. This module defines a `Config` class that encapsulates all configuration options for the application, including server settings, service URLs, authentication parameters, rate limiting controls, and security hardening features. The configuration is designed to be flexible and secure by default, with special considerations for production environments. It also includes integration with Vault for secret management when enabled.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
import os
from typing import Optional, List
from services.secrets.provider import SecretProvider, EnvSecretProvider

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec

logger = logging.getLogger(__name__)

def _to_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _to_list(value: Optional[str], default: Optional[List[str]] = None) -> List[str]:
    if value is None:
        return default or []
    parsed = [item.strip() for item in value.split(",") if item.strip()]
    return parsed if parsed else (default or [])


def _normalized_secret(value: Optional[str]) -> str:
    return str(value or "").strip().lower()


def _is_weak_secret(value: Optional[str]) -> bool:
    normalized = _normalized_secret(value)
    if not normalized:
        return True
    weak_markers = ("changeme", "replace_with", "example", "default", "secret", "password")
    return any(marker in normalized for marker in weak_markers)


def _generate_rsa_keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def _generate_ec_keypair() -> tuple[str, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def _env_name() -> str:
    return (os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "development").strip().lower()


def _is_production_env() -> bool:
    return _env_name() in {"prod", "production"}


def build_secret_provider() -> SecretProvider:
    vault_addr = os.getenv("VAULT_ADDR", "").strip()
    if not vault_addr:
        return EnvSecretProvider()

    from services.secrets.vault_client import VaultClientError, VaultSecretProvider

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


class Config:
    EXAMPLE_DATABASE_URL: str = "postgresql://user:changeme123@localhost:5432/appdb"
    ALLOWED_JWT_ALGORITHMS: frozenset[str] = frozenset({"RS256", "ES256"})
    ALLOWED_CONTEXT_ALGORITHMS: frozenset[str] = frozenset({"HS256", "HS512", "RS256", "ES256"})

    VAULT_SECRET_KEYS: tuple[str, ...] = (
        "DATABASE_URL",
        "BENOTIFIED_DATABASE_URL",
        "DATA_ENCRYPTION_KEY",
        "JWT_SECRET_KEY",
        "JWT_PRIVATE_KEY",
        "JWT_PUBLIC_KEY",
        "INBOUND_WEBHOOK_TOKEN",
        "GATEWAY_INTERNAL_SERVICE_TOKEN",
        "BENOTIFIED_EXPECTED_SERVICE_TOKEN",
        "BENOTIFIED_CONTEXT_VERIFY_KEY",
        "BENOTIFIED_CONTEXT_SIGNING_KEY",
    )

    def __init__(self) -> None:
        self.APP_ENV: str = _env_name()
        self.IS_PRODUCTION: bool = _is_production_env()
        self.DEFAULT_ADMIN_TENANT = os.getenv("DEFAULT_ADMIN_TENANT", "default")

        self.HOST: str = os.getenv("HOST", "127.0.0.1")
        self.PORT: int = int(os.getenv("PORT", "4319"))
        self.LOG_LEVEL: str = os.getenv("LOG_LEVEL", "info")
        self.ENABLE_API_DOCS: bool = _to_bool(os.getenv("ENABLE_API_DOCS"), default=not self.IS_PRODUCTION)

        self.ALERTMANAGER_URL: str = os.getenv("ALERTMANAGER_URL", "http://alertmanager:9093")
        self.MIMIR_URL: str = os.getenv("MIMIR_URL", "http://mimir:9009")

        self.DATABASE_URL: str = os.getenv("DATABASE_URL", self.EXAMPLE_DATABASE_URL)
        self.BENOTIFIED_DATABASE_URL: str = os.getenv("BENOTIFIED_DATABASE_URL", self.DATABASE_URL)

        self.DATA_ENCRYPTION_KEY: Optional[str] = os.getenv("DATA_ENCRYPTION_KEY")

        self.DEFAULT_TIMEOUT: float = float(os.getenv("DEFAULT_TIMEOUT", "30.0"))
        self.MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "3"))
        self.RETRY_BACKOFF: float = float(os.getenv("RETRY_BACKOFF", "1.0"))
        self.RETRY_MAX_BACKOFF: float = float(os.getenv("RETRY_MAX_BACKOFF", "8.0"))
        self.RETRY_JITTER: float = float(os.getenv("RETRY_JITTER", "0.1"))

        self.RATE_LIMIT_GC_EVERY = int(os.getenv("RATE_LIMIT_GC_EVERY", "1000"))
        self.RATE_LIMIT_STALE_AFTER_SECONDS: int = int(os.getenv("RATE_LIMIT_STALE_AFTER_SECONDS", "300"))
        self.RATE_LIMIT_MAX_STATES: int = int(os.getenv("RATE_LIMIT_MAX_STATES", "10000"))
        self.RATE_LIMIT_FALLBACK_MODE: str = os.getenv("RATE_LIMIT_FALLBACK_MODE", "memory").strip().lower()
        
        self.HTTP_CLIENT_MAX_CONNECTIONS: int = int(os.getenv("HTTP_CLIENT_MAX_CONNECTIONS", "100"))
        self.HTTP_CLIENT_MAX_KEEPALIVE_CONNECTIONS: int = int(os.getenv("HTTP_CLIENT_MAX_KEEPALIVE_CONNECTIONS", "40"))
        self.HTTP_CLIENT_KEEPALIVE_EXPIRY: float = float(os.getenv("HTTP_CLIENT_KEEPALIVE_EXPIRY", "30"))
        self.SERVICE_CACHE_TTL_SECONDS: int = int(os.getenv("SERVICE_CACHE_TTL_SECONDS", "60"))

        self.MAX_QUERY_LIMIT: int = int(os.getenv("MAX_QUERY_LIMIT", "1000"))
        self.DEFAULT_QUERY_LIMIT: int = int(os.getenv("DEFAULT_QUERY_LIMIT", "20"))

        self.MAX_REQUEST_BYTES: int = int(os.getenv("MAX_REQUEST_BYTES", "1048576"))
        self.MAX_CONCURRENT_REQUESTS: int = int(os.getenv("MAX_CONCURRENT_REQUESTS", "200"))
        self.CONCURRENCY_ACQUIRE_TIMEOUT: float = float(os.getenv("CONCURRENCY_ACQUIRE_TIMEOUT", "1.0"))

        self.RATE_LIMIT_PUBLIC_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PUBLIC_PER_MINUTE", "120"))

        self.TRUST_PROXY_HEADERS: bool = _to_bool(os.getenv("TRUST_PROXY_HEADERS"), default=False)
        self.TRUSTED_PROXY_CIDRS: List[str] = _to_list(os.getenv("TRUSTED_PROXY_CIDRS"), default=[])
        self.REQUIRE_CLIENT_IP_FOR_PUBLIC_ENDPOINTS: bool = _to_bool(
            os.getenv("REQUIRE_CLIENT_IP_FOR_PUBLIC_ENDPOINTS"), default=self.IS_PRODUCTION
        )
        self.ALLOWLIST_FAIL_OPEN: bool = _to_bool(os.getenv("ALLOWLIST_FAIL_OPEN"), default=False)

        self.AUTH_PUBLIC_IP_ALLOWLIST: Optional[str] = os.getenv("AUTH_PUBLIC_IP_ALLOWLIST")
        self.WEBHOOK_IP_ALLOWLIST: Optional[str] = os.getenv("WEBHOOK_IP_ALLOWLIST")
        self.GRAFANA_PROXY_IP_ALLOWLIST: Optional[str] = os.getenv("GRAFANA_PROXY_IP_ALLOWLIST")
        self.INBOUND_WEBHOOK_TOKEN: Optional[str] = os.getenv("INBOUND_WEBHOOK_TOKEN")
        self.GATEWAY_INTERNAL_SERVICE_TOKEN: Optional[str] = os.getenv("GATEWAY_INTERNAL_SERVICE_TOKEN")
        self.BENOTIFIED_EXPECTED_SERVICE_TOKEN: Optional[str] = os.getenv("BENOTIFIED_EXPECTED_SERVICE_TOKEN")
        self.BENOTIFIED_CONTEXT_VERIFY_KEY: Optional[str] = os.getenv("BENOTIFIED_CONTEXT_VERIFY_KEY")
        self.BENOTIFIED_CONTEXT_SIGNING_KEY: Optional[str] = os.getenv("BENOTIFIED_CONTEXT_SIGNING_KEY")
        self.BENOTIFIED_CONTEXT_ISSUER: str = os.getenv("BENOTIFIED_CONTEXT_ISSUER", "beobservant-main")
        self.BENOTIFIED_CONTEXT_AUDIENCE: str = os.getenv("BENOTIFIED_CONTEXT_AUDIENCE", "benotified")
        self.BENOTIFIED_CONTEXT_ALGORITHM: str = (
            os.getenv("BENOTIFIED_CONTEXT_ALGORITHM") or os.getenv("BENOTIFIED_CONTEXT_ALGORITHMS") or "HS256"
        ).strip().upper()
        self.BENOTIFIED_CONTEXT_ALGORITHMS: str = self.BENOTIFIED_CONTEXT_ALGORITHM
        self.BENOTIFIED_CONTEXT_REPLAY_TTL_SECONDS: int = int(
            os.getenv("BENOTIFIED_CONTEXT_REPLAY_TTL_SECONDS", "180")
        )
        self.BENOTIFIED_TLS_ENABLED: bool = _to_bool(os.getenv("BENOTIFIED_TLS_ENABLED"), default=False)

        self.DEFAULT_ORG_ID: str = os.getenv("DEFAULT_ORG_ID", "default")
        self.DEFAULT_OTLP_TOKEN: Optional[str] = os.getenv("DEFAULT_OTLP_TOKEN")

        self.JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "RS256").strip().upper()
        self.JWT_SECRET_KEY: Optional[str] = os.getenv("JWT_SECRET_KEY")
        self.JWT_PRIVATE_KEY: Optional[str] = os.getenv("JWT_PRIVATE_KEY")
        self.JWT_PUBLIC_KEY: Optional[str] = os.getenv("JWT_PUBLIC_KEY")
        self.JWT_AUTO_GENERATE_KEYS: bool = _to_bool(
            os.getenv("JWT_AUTO_GENERATE_KEYS"), default=not self.IS_PRODUCTION
        )

        self.CORS_ORIGINS: List[str] = _to_list(
            os.getenv("CORS_ORIGINS"), default=["http://localhost:3000"]
        )
        self.CORS_ALLOW_CREDENTIALS: bool = _to_bool(os.getenv("CORS_ALLOW_CREDENTIALS"), default=True)

        self.VAULT_ENABLED: bool = _to_bool(os.getenv("VAULT_ENABLED"), default=False)
        self.VAULT_ADDR: Optional[str] = os.getenv("VAULT_ADDR")
        self.VAULT_TOKEN: Optional[str] = os.getenv("VAULT_TOKEN")
        self.VAULT_ROLE_ID: Optional[str] = os.getenv("VAULT_ROLE_ID")
        self.VAULT_SECRET_ID: Optional[str] = os.getenv("VAULT_SECRET_ID")
        self.VAULT_SECRET_ID_FILE: Optional[str] = os.getenv("VAULT_SECRET_ID_FILE")
        self.VAULT_CACERT: Optional[str] = os.getenv("VAULT_CACERT")
        self.VAULT_SECRETS_PREFIX: str = os.getenv("VAULT_SECRETS_PREFIX", "secret")
        self.VAULT_KV_VERSION: int = int(os.getenv("VAULT_KV_VERSION", "2"))
        self.VAULT_TIMEOUT: float = float(os.getenv("VAULT_TIMEOUT", "2.0"))
        self.VAULT_CACHE_TTL: float = float(os.getenv("VAULT_CACHE_TTL", "30.0"))
        self.VAULT_FAIL_ON_MISSING: bool = _to_bool(os.getenv("VAULT_FAIL_ON_MISSING"), default=self.IS_PRODUCTION)

        try:
            self._load_vault_secrets()
        except Exception as exc:
            if self.VAULT_ENABLED and (self.IS_PRODUCTION or self.VAULT_FAIL_ON_MISSING):
                raise
            logger.warning("Vault not available or misconfigured; continuing with environment variables: %s", exc)

        if not hasattr(self, "_secret_provider") or self._secret_provider is None:
            self._secret_provider: SecretProvider = EnvSecretProvider()

        self.DEFAULT_RULE_GROUP: str = os.getenv("DEFAULT_RULE_GROUP", "BENOTFIED")
        self.ENABLED_NOTIFICATION_CHANNEL_TYPES: List[str] = [
            t.strip().lower()
            for t in os.getenv(
                "ENABLED_NOTIFICATION_CHANNEL_TYPES", "email,slack,teams,webhook,pagerduty"
            ).split(",")
            if t.strip()
        ]

        self._apply_security_defaults()
        self.validate()

    def _load_vault_secrets(self) -> None:
        if not self.VAULT_ENABLED:
            return

        from services.secrets.vault_client import VaultClientError, VaultSecretProvider

        if not self.VAULT_ADDR:
            raise ValueError("VAULT_ADDR must be set when VAULT_ENABLED=true")

        secret_id_fn = None
        if self.VAULT_ROLE_ID:
            if self.VAULT_SECRET_ID_FILE:
                vault_secret_id_file = self.VAULT_SECRET_ID_FILE
                def secret_id_fn() -> str:
                    with open(vault_secret_id_file) as f:
                        return f.read().strip()
            elif self.VAULT_SECRET_ID:
                secret_id_fn = lambda: self.VAULT_SECRET_ID
            else:
                raise VaultClientError(
                    "VAULT_ROLE_ID set but neither VAULT_SECRET_ID nor VAULT_SECRET_ID_FILE provided"
                )

        provider = VaultSecretProvider(
            address=self.VAULT_ADDR,
            token=self.VAULT_TOKEN,
            role_id=self.VAULT_ROLE_ID,
            secret_id_fn=secret_id_fn,
            prefix=self.VAULT_SECRETS_PREFIX,
            kv_version=self.VAULT_KV_VERSION,
            timeout=self.VAULT_TIMEOUT,
            cacert=self.VAULT_CACERT,
            cache_ttl=self.VAULT_CACHE_TTL,
        )
        self._secret_provider = provider

        for key in self.VAULT_SECRET_KEYS:
            try:
                val = provider.get(key)
            except Exception:
                val = None
            if val:
                setattr(self, key, val)
                logger.info("Loaded secret %s from Vault", key)

    def get_secret(self, key: str) -> Optional[str]:
        val = getattr(self, key, None)
        if val:
            return val
        try:
            return self._secret_provider.get(key)
        except Exception:
            return None

    def _apply_security_defaults(self) -> None:
        if self.JWT_ALGORITHM in self.ALLOWED_JWT_ALGORITHMS and (
            not self.JWT_PRIVATE_KEY or not self.JWT_PUBLIC_KEY
        ):
            if self.JWT_AUTO_GENERATE_KEYS and not self.IS_PRODUCTION:
                if self.JWT_ALGORITHM == "RS256":
                    private_key, public_key = _generate_rsa_keypair()
                elif self.JWT_ALGORITHM == "ES256":
                    private_key, public_key = _generate_ec_keypair()
                else:
                    raise ValueError("Unsupported JWT_ALGORITHM for auto key generation")
                self.JWT_PRIVATE_KEY = private_key
                self.JWT_PUBLIC_KEY = public_key
                logger.warning(
                    "Generated ephemeral JWT keypair for %s. Persist JWT_PRIVATE_KEY and JWT_PUBLIC_KEY "
                    "in a secret manager to avoid token invalidation on restart.",
                    self.JWT_ALGORITHM,
                )

    def validate(self) -> None:
        if self.DATABASE_URL == self.EXAMPLE_DATABASE_URL or "changeme123" in self.DATABASE_URL:
            raise ValueError(
                "Unsafe DATABASE_URL detected. Set DATABASE_URL to a non-example credentialed connection string."
            )

        if self.JWT_ALGORITHM not in self.ALLOWED_JWT_ALGORITHMS:
            raise ValueError(
                f"Unsupported JWT_ALGORITHM '{self.JWT_ALGORITHM}'. "
                f"Allowed values: {sorted(self.ALLOWED_JWT_ALGORITHMS)}"
            )

        if self.JWT_SECRET_KEY:
            logger.warning(
                "JWT_SECRET_KEY is currently unused for JWT_ALGORITHM=%s. "
                "Configure JWT_PRIVATE_KEY/JWT_PUBLIC_KEY instead.",
                self.JWT_ALGORITHM,
            )

        if self.JWT_ALGORITHM in self.ALLOWED_JWT_ALGORITHMS and (
            not self.JWT_PRIVATE_KEY or not self.JWT_PUBLIC_KEY
        ):
            raise ValueError("JWT_PRIVATE_KEY and JWT_PUBLIC_KEY must be configured for RS256/ES256 tokens")

        if self.IS_PRODUCTION and self.JWT_AUTO_GENERATE_KEYS:
            raise ValueError("JWT_AUTO_GENERATE_KEYS must be disabled in production")

        if self.IS_PRODUCTION and not self.DATA_ENCRYPTION_KEY:
            raise ValueError("DATA_ENCRYPTION_KEY must be configured in production")
        
        if self.DATA_ENCRYPTION_KEY:
            try:
                Fernet(self.DATA_ENCRYPTION_KEY)
            except Exception as exc:
                raise ValueError("DATA_ENCRYPTION_KEY must be a valid Fernet key") from exc

        if any(origin.strip() == "*" for origin in self.CORS_ORIGINS) and self.CORS_ALLOW_CREDENTIALS:
            raise ValueError("CORS_ORIGINS cannot contain '*' when CORS_ALLOW_CREDENTIALS is enabled.")

        if self.BENOTIFIED_CONTEXT_ALGORITHM not in self.ALLOWED_CONTEXT_ALGORITHMS:
            raise ValueError(
                f"Unsupported BENOTIFIED_CONTEXT_ALGORITHM '{self.BENOTIFIED_CONTEXT_ALGORITHM}'. "
                f"Allowed values: {sorted(self.ALLOWED_CONTEXT_ALGORITHMS)}"
            )
        if self.BENOTIFIED_CONTEXT_REPLAY_TTL_SECONDS <= 0:
            raise ValueError("BENOTIFIED_CONTEXT_REPLAY_TTL_SECONDS must be greater than 0")

        if self.IS_PRODUCTION:
            required_production_secrets = {
                "INBOUND_WEBHOOK_TOKEN": self.INBOUND_WEBHOOK_TOKEN,
                "BENOTIFIED_EXPECTED_SERVICE_TOKEN": (
                    self.BENOTIFIED_EXPECTED_SERVICE_TOKEN or self.GATEWAY_INTERNAL_SERVICE_TOKEN
                ),
                "BENOTIFIED_CONTEXT_VERIFY_KEY": (
                    self.BENOTIFIED_CONTEXT_VERIFY_KEY or self.BENOTIFIED_CONTEXT_SIGNING_KEY
                ),
                "GATEWAY_INTERNAL_SERVICE_TOKEN": self.GATEWAY_INTERNAL_SERVICE_TOKEN,
            }
            for key, value in required_production_secrets.items():
                if _is_weak_secret(value):
                    raise ValueError(f"{key} must be set to a strong non-placeholder secret in production")
            if self.ALLOWLIST_FAIL_OPEN:
                raise ValueError("ALLOWLIST_FAIL_OPEN must be false in production")

        if self.MAX_QUERY_LIMIT <= 0:
            raise ValueError("MAX_QUERY_LIMIT must be greater than 0")
        if self.DEFAULT_QUERY_LIMIT <= 0:
            raise ValueError("DEFAULT_QUERY_LIMIT must be greater than 0")
        if self.DEFAULT_QUERY_LIMIT > self.MAX_QUERY_LIMIT:
            raise ValueError("DEFAULT_QUERY_LIMIT cannot exceed MAX_QUERY_LIMIT")


class Constants:
    STATUS_HEALTHY: str = "Healthy"
    STATUS_SUCCESS: str = "Success"
    STATUS_ERROR: str = "Error"


config = Config()
constants = Constants()