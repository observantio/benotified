"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import importlib
import json
import runpy
import sys
import types

import pytest
from fastapi import Request
from starlette.responses import Response

from tests._env import ensure_test_env

ensure_test_env()


def _request(path: str, headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": path,
            "headers": headers or [],
            "client": ("127.0.0.1", 1234),
            "scheme": "http",
            "query_string": b"",
        }
    )


def _load_main(monkeypatch, *, enable_docs: bool = False, secret_value: str | None = "service-token"):
    if "main" in sys.modules:
        del sys.modules["main"]

    import config as config_module
    import database as database_module

    monkeypatch.setattr(database_module, "ensure_database_exists", lambda url: None)
    monkeypatch.setattr(database_module, "init_database", lambda url, debug: None)
    monkeypatch.setattr(database_module, "init_db", lambda: None)
    monkeypatch.setattr(database_module, "connection_test", lambda: True)

    monkeypatch.setattr(config_module.config, "ENABLE_API_DOCS", enable_docs)
    monkeypatch.setattr(config_module.config, "MAX_REQUEST_BYTES", 1024)
    monkeypatch.setattr(config_module.config, "MAX_CONCURRENT_REQUESTS", 2)
    monkeypatch.setattr(config_module.config, "CONCURRENCY_ACQUIRE_TIMEOUT", 0.1)
    monkeypatch.setattr(config_module.config, "BENOTIFIED_DATABASE_URL", "sqlite://")
    monkeypatch.setattr(config_module.config, "LOG_LEVEL", "info")
    monkeypatch.setattr(config_module.config, "HOST", "127.0.0.1")
    monkeypatch.setattr(config_module.config, "PORT", 4319)
    monkeypatch.setattr(
        config_module.config,
        "get_secret",
        lambda key: secret_value if key in {"BENOTIFIED_EXPECTED_SERVICE_TOKEN", "GATEWAY_INTERNAL_SERVICE_TOKEN"} else None,
    )

    return importlib.import_module("main")


@pytest.mark.asyncio
async def test_require_internal_service_token_paths(monkeypatch):
    main_module = _load_main(monkeypatch, enable_docs=True, secret_value="expected-token")

    async def call_next(_request: Request) -> Response:
        return Response(status_code=204)

    allowed = await main_module.require_internal_service_token(_request("/health"), call_next)
    docs = await main_module.require_internal_service_token(_request("/docs"), call_next)
    webhook = await main_module.require_internal_service_token(_request("/internal/v1/alertmanager/alerts/webhook"), call_next)
    missing = await main_module.require_internal_service_token(_request("/secure"), call_next)
    bad = await main_module.require_internal_service_token(
        _request("/secure", headers=[(b"x-service-token", b"wrong")]),
        call_next,
    )
    good = await main_module.require_internal_service_token(
        _request("/secure", headers=[(b"x-service-token", b"expected-token")]),
        call_next,
    )

    assert allowed.status_code == 204
    assert docs.status_code == 204
    assert webhook.status_code == 204
    assert missing.status_code == 403
    assert bad.status_code == 403
    assert good.status_code == 204


@pytest.mark.asyncio
async def test_require_internal_service_token_reports_missing_configuration(monkeypatch):
    main_module = _load_main(monkeypatch, enable_docs=False, secret_value=None)

    async def call_next(_request: Request) -> Response:
        return Response(status_code=204)

    response = await main_module.require_internal_service_token(_request("/secure"), call_next)
    assert response.status_code == 500
    assert json.loads(response.body.decode("utf-8"))["detail"] == "Service token not configured"


@pytest.mark.asyncio
async def test_health_and_ready_routes(monkeypatch):
    main_module = _load_main(monkeypatch)
    assert await main_module.health() == {"status": "healthy", "service": "benotified"}

    monkeypatch.setattr(main_module, "connection_test", lambda: True)
    ready = await main_module.ready()
    assert ready.status_code == 200
    assert json.loads(ready.body.decode("utf-8"))["status"] == "ready"

    monkeypatch.setattr(main_module, "connection_test", lambda: False)
    not_ready = await main_module.ready()
    assert not_ready.status_code == 503
    assert json.loads(not_ready.body.decode("utf-8"))["status"] == "not_ready"


def test_main_dunder_main_runs_uvicorn(monkeypatch):
    _load_main(monkeypatch)
    captured = {}
    monkeypatch.setitem(sys.modules, "uvicorn", types.SimpleNamespace(run=lambda app, **kwargs: captured.update({"app": app, **kwargs})))
    runpy.run_module("main", run_name="__main__")
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 4319
    assert captured["loop"] == "uvloop"