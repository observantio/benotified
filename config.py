"""
Configuration management for the application, loading settings from environment variables with support for defaults, type conversion, and validation. This module defines a `Config` class that encapsulates all configuration options for the application, including server settings, service URLs, authentication parameters, rate limiting controls, and security hardening features. The configuration is designed to be flexible and secure by default, with special considerations for production environments. It also includes integration with Vault for secret management when enabled.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
import os
import secrets
from typing import Optional, List

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


def _is_placeholder(value: Optional[str], placeholders: List[str]) -> bool:
    if value is None:
        return True
    normalized = value.strip()
    return not normalized or normalized in placeholders


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

class Config:

    ALLOWED_JWT_ALGORITHMS = {"RS256", "ES256"}
    EXAMPLE_DATABASE_URL = "postgresql://beobservant:changeme123@localhost:5432/beobservant"

    def __init__(self) -> None:
        self.APP_ENV: str = _env_name()
        self.IS_PRODUCTION: bool = _is_production_env()

        # Server configuration
        self.HOST: str = os.getenv("HOST", "127.0.0.1")
        self.PORT: int = int(os.getenv("PORT", "4319"))
        self.LOG_LEVEL: str = os.getenv("LOG_LEVEL", "info")

        # Service URLs
        self.TEMPO_URL: str = os.getenv("TEMPO_URL", "http://tempo:3200")
        self.LOKI_URL: str = os.getenv("LOKI_URL", "http://loki:3100")
        self.ALERTMANAGER_URL: str = os.getenv("ALERTMANAGER_URL", "http://alertmanager:9093")
        self.GRAFANA_URL: str = os.getenv("GRAFANA_URL", "http://grafana:3000")
        self.MIMIR_URL: str = os.getenv("MIMIR_URL", "http://mimir:9009")

        # Grafana credentials
        self.GRAFANA_USERNAME: str = os.getenv("GRAFANA_USERNAME", "admin")
        self.GRAFANA_PASSWORD: str = os.getenv("GRAFANA_PASSWORD", "admin")
        self.GRAFANA_API_KEY: Optional[str] = os.getenv("GRAFANA_API_KEY")

        # Encryption key for sensitive data at rest (channel config in DB)
        self.DATA_ENCRYPTION_KEY: Optional[str] = os.getenv("DATA_ENCRYPTION_KEY")

        # Database
        self.DATABASE_URL: str = os.getenv("DATABASE_URL", self.EXAMPLE_DATABASE_URL)
        self.BENOTIFIED_DATABASE_URL: str = os.getenv("BENOTIFIED_DATABASE_URL", self.DATABASE_URL)

        # Request settings
        self.DEFAULT_TIMEOUT: float = float(os.getenv("DEFAULT_TIMEOUT", "30.0"))
        self.MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "3"))
        self.RETRY_BACKOFF: float = float(os.getenv("RETRY_BACKOFF", "1.0"))
        self.RETRY_MAX_BACKOFF: float = float(os.getenv("RETRY_MAX_BACKOFF", "8.0"))
        self.RETRY_JITTER: float = float(os.getenv("RETRY_JITTER", "0.1"))

        # Shared upstream HTTP client pool tuning
        self.HTTP_CLIENT_MAX_CONNECTIONS: int = int(os.getenv("HTTP_CLIENT_MAX_CONNECTIONS", "100"))
        self.HTTP_CLIENT_MAX_KEEPALIVE_CONNECTIONS: int = int(os.getenv("HTTP_CLIENT_MAX_KEEPALIVE_CONNECTIONS", "40"))
        self.HTTP_CLIENT_KEEPALIVE_EXPIRY: float = float(os.getenv("HTTP_CLIENT_KEEPALIVE_EXPIRY", "30"))

        # Query optimizations
        self.LOKI_FALLBACK_CONCURRENCY: int = int(os.getenv("LOKI_FALLBACK_CONCURRENCY", "4"))
        self.LOKI_MAX_FALLBACK_QUERIES: int = int(os.getenv("LOKI_MAX_FALLBACK_QUERIES", "4"))
        self.TEMPO_TRACE_FETCH_CONCURRENCY: int = int(os.getenv("TEMPO_TRACE_FETCH_CONCURRENCY", "8"))
        self.TEMPO_VOLUME_BUCKET_CONCURRENCY: int = int(os.getenv("TEMPO_VOLUME_BUCKET_CONCURRENCY", "8"))
        # When true, use Tempo/Mimir metrics API for trace count/volume queries where possible.
        # Operators can opt out by setting TEMPO_USE_METRICS_FOR_COUNT=false
        self.TEMPO_USE_METRICS_FOR_COUNT: bool = _to_bool(os.getenv("TEMPO_USE_METRICS_FOR_COUNT"), default=True)
        self.SERVICE_CACHE_TTL_SECONDS: int = int(os.getenv("SERVICE_CACHE_TTL_SECONDS", "30"))

        # CORS settings
        self.CORS_ORIGINS: List[str] = _to_list(os.getenv("CORS_ORIGINS"), default=["*"])
        self.CORS_ALLOW_CREDENTIALS: bool = _to_bool(os.getenv("CORS_ALLOW_CREDENTIALS"), default=True)

        # API limits
        self.MAX_QUERY_LIMIT: int = int(os.getenv("MAX_QUERY_LIMIT", "1000"))
        # Default number of items returned by list endpoints (can be overridden by client)
        self.DEFAULT_QUERY_LIMIT: int = int(os.getenv("DEFAULT_QUERY_LIMIT", "20"))

        # Request protection / backpressure
        self.MAX_REQUEST_BYTES: int = int(os.getenv("MAX_REQUEST_BYTES", "1048576"))
        self.MAX_CONCURRENT_REQUESTS: int = int(os.getenv("MAX_CONCURRENT_REQUESTS", "200"))
        self.CONCURRENCY_ACQUIRE_TIMEOUT: float = float(os.getenv("CONCURRENCY_ACQUIRE_TIMEOUT", "1.0"))

        # Rate limiting / spam protection (per-process; use an API gateway for global limits)
        self.RATE_LIMIT_USER_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_USER_PER_MINUTE", "600"))
        self.RATE_LIMIT_PUBLIC_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PUBLIC_PER_MINUTE", "120"))
        self.RATE_LIMIT_LOGIN_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_LOGIN_PER_MINUTE", "10"))
        self.RATE_LIMIT_REGISTER_PER_HOUR: int = int(os.getenv("RATE_LIMIT_REGISTER_PER_HOUR", "5"))
        self.RATE_LIMIT_GRAFANA_PROXY_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_GRAFANA_PROXY_PER_MINUTE", "3000"))

        # Client IP and network boundary controls
        self.TRUST_PROXY_HEADERS: bool = _to_bool(os.getenv("TRUST_PROXY_HEADERS"), default=False)
        self.AUTH_PUBLIC_IP_ALLOWLIST: Optional[str] = os.getenv("AUTH_PUBLIC_IP_ALLOWLIST")
        self.GATEWAY_IP_ALLOWLIST: Optional[str] = os.getenv("GATEWAY_IP_ALLOWLIST")
        self.WEBHOOK_IP_ALLOWLIST: Optional[str] = os.getenv("WEBHOOK_IP_ALLOWLIST")
        self.AGENT_INGEST_IP_ALLOWLIST: Optional[str] = os.getenv("AGENT_INGEST_IP_ALLOWLIST")
        self.GRAFANA_PROXY_IP_ALLOWLIST: Optional[str] = os.getenv("GRAFANA_PROXY_IP_ALLOWLIST")
        self.AGENT_HEARTBEAT_TOKEN: Optional[str] = os.getenv("AGENT_HEARTBEAT_TOKEN")

        # Optional shared secrets for inbound endpoints
        self.INBOUND_WEBHOOK_TOKEN: Optional[str] = os.getenv("INBOUND_WEBHOOK_TOKEN")
        self.OTLP_INGEST_TOKEN: Optional[str] = os.getenv("OTLP_INGEST_TOKEN")

        self.GATEWAY_INTERNAL_SERVICE_TOKEN: Optional[str] = os.getenv("GATEWAY_INTERNAL_SERVICE_TOKEN")
        self.BENOTIFIED_EXPECTED_SERVICE_TOKEN: Optional[str] = os.getenv("BENOTIFIED_EXPECTED_SERVICE_TOKEN")
        self.BENOTIFIED_CONTEXT_VERIFY_KEY: Optional[str] = os.getenv("BENOTIFIED_CONTEXT_VERIFY_KEY")
        self.BENOTIFIED_CONTEXT_SIGNING_KEY: Optional[str] = os.getenv("BENOTIFIED_CONTEXT_SIGNING_KEY")
        self.BENOTIFIED_CONTEXT_ISSUER: str = os.getenv("BENOTIFIED_CONTEXT_ISSUER", "beobservant-main")
        self.BENOTIFIED_CONTEXT_AUDIENCE: str = os.getenv("BENOTIFIED_CONTEXT_AUDIENCE", "benotified")
        self.BENOTIFIED_CONTEXT_ALGORITHMS: str = os.getenv("BENOTIFIED_CONTEXT_ALGORITHMS", "HS256")
        self.BENOTIFIED_TLS_ENABLED: bool = _to_bool(os.getenv("BENOTIFIED_TLS_ENABLED"), default=False)

        # Authentication
        self.JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "RS256").strip().upper()
        self.JWT_EXPIRATION_MINUTES: int = int(os.getenv("JWT_EXPIRATION_MINUTES", "1440"))
        self.JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
        self.JWT_PRIVATE_KEY: Optional[str] = os.getenv("JWT_PRIVATE_KEY")
        self.JWT_PUBLIC_KEY: Optional[str] = os.getenv("JWT_PUBLIC_KEY")
        self.JWT_AUTO_GENERATE_KEYS: bool = _to_bool(
            os.getenv("JWT_AUTO_GENERATE_KEYS"),
            default=not self.IS_PRODUCTION,
        )

        # Identity provider / OIDC (Keycloak recommended)
        self.AUTH_PROVIDER: str = os.getenv("AUTH_PROVIDER", "local").strip().lower()
        self.AUTH_PASSWORD_FLOW_ENABLED: bool = _to_bool(os.getenv("AUTH_PASSWORD_FLOW_ENABLED"), default=False)
        self.OIDC_ISSUER_URL: Optional[str] = os.getenv("OIDC_ISSUER_URL")
        self.OIDC_CLIENT_ID: Optional[str] = os.getenv("OIDC_CLIENT_ID")
        self.OIDC_CLIENT_SECRET: Optional[str] = os.getenv("OIDC_CLIENT_SECRET")
        self.OIDC_AUDIENCE: Optional[str] = os.getenv("OIDC_AUDIENCE")
        self.OIDC_JWKS_URL: Optional[str] = os.getenv("OIDC_JWKS_URL")
        self.OIDC_SCOPES: str = os.getenv("OIDC_SCOPES", "openid profile email")
        self.OIDC_AUTO_PROVISION_USERS: bool = _to_bool(os.getenv("OIDC_AUTO_PROVISION_USERS"), default=True)

        # Keycloak admin API (optional, for app-driven user provisioning)
        self.KEYCLOAK_ADMIN_URL: Optional[str] = os.getenv("KEYCLOAK_ADMIN_URL")
        self.KEYCLOAK_ADMIN_REALM: Optional[str] = os.getenv("KEYCLOAK_ADMIN_REALM")
        self.KEYCLOAK_ADMIN_CLIENT_ID: Optional[str] = os.getenv("KEYCLOAK_ADMIN_CLIENT_ID")
        self.KEYCLOAK_ADMIN_CLIENT_SECRET: Optional[str] = os.getenv("KEYCLOAK_ADMIN_CLIENT_SECRET")
        self.KEYCLOAK_USER_PROVISIONING_ENABLED: bool = _to_bool(
            os.getenv("KEYCLOAK_USER_PROVISIONING_ENABLED"),
            default=False,
        )

        # Production hardening controls
        self.DEFAULT_ADMIN_BOOTSTRAP_ENABLED: bool = _to_bool(
            os.getenv("DEFAULT_ADMIN_BOOTSTRAP_ENABLED"),
            default=not self.IS_PRODUCTION,
        )
        self.REQUIRE_TOTP_ENCRYPTION_KEY: bool = _to_bool(
            os.getenv("REQUIRE_TOTP_ENCRYPTION_KEY"),
            default=self.IS_PRODUCTION,
        )
        self.TRUSTED_PROXY_CIDRS: List[str] = _to_list(os.getenv("TRUSTED_PROXY_CIDRS"), default=[])
        self.REQUIRE_CLIENT_IP_FOR_PUBLIC_ENDPOINTS: bool = _to_bool(
            os.getenv("REQUIRE_CLIENT_IP_FOR_PUBLIC_ENDPOINTS"),
            default=self.IS_PRODUCTION,
        )

        # Cookie / allowlist hardening
        self.FORCE_SECURE_COOKIES: bool = _to_bool(os.getenv("FORCE_SECURE_COOKIES"), default=self.IS_PRODUCTION)
        # When true, an explicit-but-empty allowlist will be treated as permissive. Default is false (fail-closed).
        self.ALLOWLIST_FAIL_OPEN: bool = _to_bool(os.getenv("ALLOWLIST_FAIL_OPEN"), default=False)

        self.DB_AUTO_CREATE_SCHEMA: bool = _to_bool(
            os.getenv("DB_AUTO_CREATE_SCHEMA"),
            default=not self.IS_PRODUCTION,
        )

        self.RATE_LIMIT_GC_EVERY: int = int(os.getenv("RATE_LIMIT_GC_EVERY", "1024"))
        self.RATE_LIMIT_STALE_AFTER_SECONDS: int = int(os.getenv("RATE_LIMIT_STALE_AFTER_SECONDS", "3600"))
        self.RATE_LIMIT_MAX_STATES: int = int(os.getenv("RATE_LIMIT_MAX_STATES", "200000"))
        self.RATE_LIMIT_FALLBACK_MODE: str = os.getenv("RATE_LIMIT_FALLBACK_MODE", "memory").strip().lower()
        self.PASSWORD_HASH_MAX_CONCURRENCY: int = int(os.getenv("PASSWORD_HASH_MAX_CONCURRENCY", "8"))

        # Default admin bootstrap (can be overridden via environment)
        self.DEFAULT_ADMIN_USERNAME: str = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
        self.DEFAULT_ADMIN_PASSWORD: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "")
        self.DEFAULT_ADMIN_EMAIL: str = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@example.com")
        self.DEFAULT_ADMIN_TENANT: str = os.getenv("DEFAULT_ADMIN_TENANT", "default")

        # Multi-tenancy
        self.DEFAULT_ORG_ID: str = os.getenv("DEFAULT_ORG_ID", "default")
        self.OTLP_GATEWAY_URL: str = os.getenv("OTLP_GATEWAY_URL", "http://otlp-gateway:4320")
        self.DEFAULT_OTLP_TOKEN: Optional[str] = os.getenv("DEFAULT_OTLP_TOKEN")

        # Vault / secret-store integration (opt-in)
        self.VAULT_ENABLED: bool = _to_bool(os.getenv("VAULT_ENABLED"), default=False)
        self.VAULT_ADDR: Optional[str] = os.getenv("VAULT_ADDR")
        self.VAULT_TOKEN: Optional[str] = os.getenv("VAULT_TOKEN")
        self.VAULT_ROLE_ID: Optional[str] = os.getenv("VAULT_ROLE_ID")
        self.VAULT_SECRET_ID: Optional[str] = os.getenv("VAULT_SECRET_ID")
        self.VAULT_CACERT: Optional[str] = os.getenv("VAULT_CACERT")
        self.VAULT_SECRETS_PREFIX: str = os.getenv("VAULT_SECRETS_PREFIX", "secret")
        self.VAULT_KV_VERSION: int = int(os.getenv("VAULT_KV_VERSION", "2"))
        self.VAULT_TIMEOUT: float = float(os.getenv("VAULT_TIMEOUT", "2.0"))
        self.VAULT_FAIL_ON_MISSING: bool = _to_bool(os.getenv("VAULT_FAIL_ON_MISSING"), default=self.IS_PRODUCTION)
        try:
            self._load_vault_secrets()
        except Exception as exc: 
            if self.VAULT_ENABLED and (self.IS_PRODUCTION or self.VAULT_FAIL_ON_MISSING):
                raise
            logger.warning("Vault not available or misconfigured; continuing with environment variables: %s", exc)
        if not hasattr(self, "_secret_provider") or self._secret_provider is None:
            from services.secrets.provider import EnvSecretProvider, SecretProvider

            self._secret_provider: SecretProvider = EnvSecretProvider()

        # Alerting and notifications defaults
        self.DEFAULT_RULE_GROUP: str = os.getenv("DEFAULT_RULE_GROUP", "default")
        self.DEFAULT_SLACK_CHANNEL: str = os.getenv("DEFAULT_SLACK_CHANNEL", "default")
        self.ENABLED_NOTIFICATION_CHANNEL_TYPES: list = [
            channel_type.strip().lower()
            for channel_type in os.getenv(
                "ENABLED_NOTIFICATION_CHANNEL_TYPES",
                "email,slack,teams,webhook,pagerduty",
            ).split(",")
            if channel_type.strip()
        ]

        self._apply_security_defaults()
        self.validate()

    def _load_vault_secrets(self) -> None:
        if not self.VAULT_ENABLED:
            return
        from services.secrets.provider import EnvSecretProvider, SecretProvider
        from services.secrets.vault_client import VaultClientError, VaultSecretProvider

        if not self.VAULT_ADDR:
            raise ValueError("VAULT_ADDR must be set when VAULT_ENABLED=true")

        secret_id_fn = (lambda: self.VAULT_SECRET_ID) if self.VAULT_SECRET_ID else None

        provider = VaultSecretProvider(
            address=self.VAULT_ADDR,
            token=self.VAULT_TOKEN,
            role_id=self.VAULT_ROLE_ID,
            secret_id_fn=secret_id_fn,
            prefix=self.VAULT_SECRETS_PREFIX,
            kv_version=self.VAULT_KV_VERSION,
            timeout=self.VAULT_TIMEOUT,
        )

        # keys we want to fetch from Vault if present
        secret_keys = [
            "DATABASE_URL",
            "JWT_PRIVATE_KEY",
            "JWT_PUBLIC_KEY",
            "DEFAULT_ADMIN_PASSWORD",
            "DATA_ENCRYPTION_KEY",
            "GRAFANA_PASSWORD",
            "GRAFANA_API_KEY",
            "OIDC_CLIENT_SECRET",
            "KEYCLOAK_ADMIN_CLIENT_SECRET",
            "DEFAULT_OTLP_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "INBOUND_WEBHOOK_TOKEN",
            "OTLP_INGEST_TOKEN",
            "GATEWAY_INTERNAL_SERVICE_TOKEN",
            "BENOTIFIED_EXPECTED_SERVICE_TOKEN",
            "BENOTIFIED_CONTEXT_VERIFY_KEY",
            "BENOTIFIED_CONTEXT_SIGNING_KEY",
            "AGENT_HEARTBEAT_TOKEN",
        ]

        for sk in secret_keys:
            try:
                val = provider.get(sk)
            except Exception:
                val = None

            if val:
                setattr(self, sk, val)
                logger.info("Loaded secret %s from Vault", sk)

    def get_secret(self, key: str) -> Optional[str]:
        val = getattr(self, key, None)
        if val:
            return val

        try:
            return self._secret_provider.get(key)
        except Exception:
            return None

    def _apply_security_defaults(self) -> None:
        if _is_placeholder(
            self.DEFAULT_ADMIN_PASSWORD,
            placeholders=["admin123", "admin", "password", "changeme"],
        ):

            if not self.IS_PRODUCTION and self.DEFAULT_ADMIN_BOOTSTRAP_ENABLED:
                self.DEFAULT_ADMIN_PASSWORD = secrets.token_urlsafe(18)
                logger.warning(
                    "Generated runtime DEFAULT_ADMIN_PASSWORD for non-production startup. Persist via secret manager before deployment.",
                )

        if _is_placeholder(
            self.JWT_SECRET_KEY,
            placeholders=["change-this-secret-key-in-production", "changeme", "secret", ""],
        ):
            if not self.IS_PRODUCTION:
                self.JWT_SECRET_KEY = secrets.token_urlsafe(32)
                logger.info("Generated runtime JWT_SECRET_KEY for local compatibility.")

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
                    "Generated ephemeral JWT keypair for %s. Persist JWT_PRIVATE_KEY and JWT_PUBLIC_KEY in a secret manager to avoid token invalidation on restart.",
                    self.JWT_ALGORITHM,
                )

    def validate(self) -> None:
        if self.DATABASE_URL == self.EXAMPLE_DATABASE_URL or "changeme123" in self.DATABASE_URL:
            raise ValueError(
                "Unsafe DATABASE_URL detected. Set DATABASE_URL to a non-example credentialed connection string."
            )

        if self.JWT_ALGORITHM not in self.ALLOWED_JWT_ALGORITHMS:
            raise ValueError(
                f"Unsupported JWT_ALGORITHM '{self.JWT_ALGORITHM}'. Allowed values: {sorted(self.ALLOWED_JWT_ALGORITHMS)}"
            )

        if self.JWT_SECRET_KEY:
            logger.warning(
                "JWT_SECRET_KEY is currently unused for JWT_ALGORITHM=%s. Configure JWT_PRIVATE_KEY/JWT_PUBLIC_KEY instead.",
                self.JWT_ALGORITHM,
            )

        if self.JWT_ALGORITHM in self.ALLOWED_JWT_ALGORITHMS and (
            not self.JWT_PRIVATE_KEY or not self.JWT_PUBLIC_KEY
        ):
            raise ValueError("JWT_PRIVATE_KEY and JWT_PUBLIC_KEY must be configured for RS256/ES256 tokens")

        if self.IS_PRODUCTION and self.JWT_AUTO_GENERATE_KEYS:
            raise ValueError("JWT_AUTO_GENERATE_KEYS must be disabled in production")

        if self.IS_PRODUCTION and _is_placeholder(
            self.DEFAULT_ADMIN_PASSWORD,
            placeholders=["admin123", "admin", "password", "changeme", ""],
        ):
            raise ValueError("DEFAULT_ADMIN_PASSWORD must be set to a strong value in production")

        if self.IS_PRODUCTION and self.DEFAULT_ADMIN_BOOTSTRAP_ENABLED:
            raise ValueError("DEFAULT_ADMIN_BOOTSTRAP_ENABLED must be false in production")

        if self.IS_PRODUCTION and self.DB_AUTO_CREATE_SCHEMA:
            raise ValueError("DB_AUTO_CREATE_SCHEMA must be disabled in production; use Alembic migrations")

        if self.REQUIRE_TOTP_ENCRYPTION_KEY and not self.DATA_ENCRYPTION_KEY:
            raise ValueError("DATA_ENCRYPTION_KEY is required when REQUIRE_TOTP_ENCRYPTION_KEY is enabled")

        wildcard_enabled = any(origin.strip() == "*" for origin in self.CORS_ORIGINS)
        if wildcard_enabled and self.CORS_ALLOW_CREDENTIALS:
            raise ValueError(
                "CORS_ORIGINS cannot contain '*' when CORS_ALLOW_CREDENTIALS is enabled."
            )

        if self.MAX_QUERY_LIMIT <= 0:
            raise ValueError("MAX_QUERY_LIMIT must be greater than 0")
        if self.DEFAULT_QUERY_LIMIT <= 0:
            raise ValueError("DEFAULT_QUERY_LIMIT must be greater than 0")
        if self.DEFAULT_QUERY_LIMIT > self.MAX_QUERY_LIMIT:
            raise ValueError("DEFAULT_QUERY_LIMIT cannot exceed MAX_QUERY_LIMIT")


class Constants:
    APP_NAME: str = "Be Observant with Your Infrastructure"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = (
        "Unified API for managing Tempo, Loki, AlertManager, and Grafana"
    )

    # HTTP status messages
    STATUS_HEALTHY: str = "Healthy"
    STATUS_SUCCESS: str = "Success"
    STATUS_ERROR: str = "Error"


    # Service names
    SERVICE_TEMPO: str = "Tempo"
    SERVICE_LOKI: str = "Loki"
    SERVICE_ALERTMANAGER: str = "AlertManager"
    SERVICE_GRAFANA: str = "Grafana"

config = Config()
constants = Constants()
