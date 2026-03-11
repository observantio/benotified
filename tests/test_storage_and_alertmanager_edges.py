"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import inspect
import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request
from sqlalchemy.exc import SQLAlchemyError

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from config import config
from models.access.auth_models import Role, TokenData
from services import alertmanager_service as alert_mod
from services.storage_db_service import DatabaseStorageService


def _request(headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "path": "/internal/v1/alertmanager/alerts/webhook",
            "headers": headers or [],
            "client": ("127.0.0.1", 1234),
            "scheme": "http",
            "query_string": b"",
        }
    )


class _FakeScalarQuery:
    def __init__(self, rows=None, first_value=None):
        self.rows = rows or []
        self.first_value = first_value

    def filter(self, *_args, **_kwargs):
        return self

    def filter_by(self, **_kwargs):
        return self

    def all(self):
        return self.rows

    def first(self):
        return self.first_value


class _FakeDB:
    def __init__(self, *, rows=None, first_value=None):
        self.rows = rows or []
        self.first_value = first_value
        self.added = []
        self.deleted = []
        self.executed = []
        self.committed = False

    def query(self, *_args, **_kwargs):
        return _FakeScalarQuery(rows=self.rows, first_value=self.first_value)

    def add(self, obj):
        self.added.append(obj)

    def delete(self, obj):
        self.deleted.append(obj)

    def execute(self, stmt):
        self.executed.append(stmt)

    def commit(self):
        self.committed = True


@contextmanager
def _db_ctx(db):
    yield db


def test_storage_service_delegates_to_subservices(monkeypatch):
    svc = DatabaseStorageService()
    svc.incidents = SimpleNamespace(
        sync_incidents_from_alerts=lambda *args: ("sync", args),
        list_incidents=lambda **kwargs: ("list-incidents", kwargs),
        get_incident_summary=lambda **kwargs: ("summary", kwargs),
        unlink_jira_integration_from_incidents=lambda **kwargs: ("unlink", kwargs),
        get_incident_for_user=lambda **kwargs: ("incident", kwargs),
        update_incident=lambda *args, **kwargs: ("update-incident", args, kwargs),
        filter_alerts_for_user=lambda *args: ("filter", args),
    )
    svc.rules = SimpleNamespace(
        get_public_alert_rules=lambda *args: ("public", args),
        get_alert_rules=lambda *args, **kwargs: ("rules", args, kwargs),
        get_alert_rules_for_org=lambda *args: ("org-rules", args),
        get_hidden_rule_ids=lambda *args: ["r1"],
        get_hidden_rule_names=lambda *args: ["name"],
        toggle_rule_hidden=lambda *args: True,
        get_alert_rules_with_owner=lambda *args, **kwargs: [("rule", "owner")],
        get_alert_rule_raw=lambda *args: "raw",
        get_alert_rule=lambda *args, **kwargs: "rule",
        get_alert_rule_by_name_for_delivery=lambda *args, **kwargs: "delivery",
        create_alert_rule=lambda *args, **kwargs: "created-rule",
        update_alert_rule=lambda *args, **kwargs: "updated-rule",
        delete_alert_rule=lambda *args, **kwargs: True,
    )
    svc.channels = SimpleNamespace(
        get_notification_channels=lambda *args, **kwargs: ["channel"],
        get_notification_channel=lambda *args, **kwargs: "channel-1",
        create_notification_channel=lambda *args, **kwargs: "created-channel",
        update_notification_channel=lambda *args, **kwargs: "updated-channel",
        delete_notification_channel=lambda *args, **kwargs: True,
        is_notification_channel_owner=lambda *args: True,
        test_notification_channel=lambda *args, **kwargs: {"ok": True},
        get_notification_channels_for_rule_name=lambda *args, **kwargs: ["delivery-channel"],
    )

    assert svc.sync_incidents_from_alerts("tenant", [{"a": 1}]) == ("sync", ("tenant", [{"a": 1}], True))
    assert svc.list_incidents("tenant", "user", ["g1"], limit=10, offset=2)[0] == "list-incidents"
    assert svc.get_incident_summary("tenant", "user")[0] == "summary"
    assert svc.unlink_jira_integration_from_incidents("tenant", "jira")[0] == "unlink"
    assert svc.get_incident_for_user("inc", "tenant", "user")[0] == "incident"
    assert svc.update_incident("inc", "tenant", "user", "payload")[0] == "update-incident"
    assert svc.filter_alerts_for_user("tenant", "user", ["g1"], [{"a": 1}])[0] == "filter"
    assert svc.get_public_alert_rules("tenant")[0] == "public"
    assert svc.get_alert_rules("tenant", "user")[0] == "rules"
    assert svc.get_alert_rules_for_org("tenant", "org")[0] == "org-rules"
    assert svc.get_hidden_rule_ids("tenant", "user") == ["r1"]
    assert svc.get_hidden_rule_names("tenant", "user") == ["name"]
    assert svc.toggle_rule_hidden("tenant", "user", "rule", True) is True
    assert svc.get_alert_rules_with_owner("tenant", "user") == [("rule", "owner")]
    assert svc.get_alert_rule_raw("rule", "tenant") == "raw"
    assert svc.get_alert_rule("rule", "tenant", "user") == "rule"
    assert svc.get_alert_rule_by_name_for_delivery("tenant", "cpu") == "delivery"
    assert svc.create_alert_rule("payload", "tenant", "user") == "created-rule"
    assert svc.update_alert_rule("rule", "payload", "tenant", "user") == "updated-rule"
    assert svc.delete_alert_rule("rule", "tenant", "user") is True
    assert svc.get_notification_channels("tenant", "user") == ["channel"]
    assert svc.get_notification_channel("channel", "tenant", "user") == "channel-1"
    assert svc.create_notification_channel("payload", "tenant", "user") == "created-channel"
    assert svc.update_notification_channel("channel", "payload", "tenant", "user") == "updated-channel"
    assert svc.delete_notification_channel("channel", "tenant", "user") is True
    assert svc.is_notification_channel_owner("channel", "tenant", "user") is True
    assert svc.test_notification_channel("channel", "tenant", "user") == {"ok": True}
    assert svc.get_notification_channels_for_rule_name("tenant", "cpu") == ["delivery-channel"]


def test_storage_service_hidden_resource_helpers(monkeypatch):
    svc = DatabaseStorageService()

    db = _FakeDB(rows=[("s1",), ("s2",)])
    monkeypatch.setattr("services.storage_db_service.get_db_session", lambda: _db_ctx(db))
    assert svc.get_hidden_silence_ids("tenant", "user") == ["s1", "s2"]

    db = _FakeDB(first_value=None)
    monkeypatch.setattr("services.storage_db_service.get_db_session", lambda: _db_ctx(db))
    assert svc.toggle_silence_hidden("tenant", "user", "sil-1", True) is True
    assert len(db.added) == 1

    existing = SimpleNamespace(id="sil-1")
    db = _FakeDB(first_value=existing)
    monkeypatch.setattr("services.storage_db_service.get_db_session", lambda: _db_ctx(db))
    assert svc.toggle_silence_hidden("tenant", "user", "sil-1", False) is True
    assert db.deleted == [existing]

    db = _FakeDB(rows=[("c1",)])
    monkeypatch.setattr("services.storage_db_service.get_db_session", lambda: _db_ctx(db))
    assert svc.get_hidden_channel_ids("tenant", "user") == ["c1"]

    db = _FakeDB(first_value=None)
    monkeypatch.setattr("services.storage_db_service.get_db_session", lambda: _db_ctx(db))
    assert svc.toggle_channel_hidden("tenant", "user", "ch-1", True) is True
    assert len(db.added) == 1

    existing = SimpleNamespace(id="ch-1")
    db = _FakeDB(first_value=existing)
    monkeypatch.setattr("services.storage_db_service.get_db_session", lambda: _db_ctx(db))
    assert svc.toggle_channel_hidden("tenant", "user", "ch-1", False) is True
    assert db.deleted == [existing]

    pruned = {}
    db = _FakeDB()
    monkeypatch.setattr("services.storage_db_service.get_db_session", lambda: _db_ctx(db))
    monkeypatch.setattr(
        "services.storage_db_service.prune_removed_member_group_shares",
        lambda *_args, **kwargs: pruned.setdefault("kwargs", kwargs) or {"channels": 1},
    )
    assert svc.prune_removed_member_group_shares("tenant", "group-1", ["u1"], ["user1"])
    assert pruned["kwargs"]["group_id"] == "group-1"

    db = _FakeDB(rows=[("jira-1",)])
    monkeypatch.setattr("services.storage_db_service.get_db_session", lambda: _db_ctx(db))
    assert svc.get_hidden_jira_integration_ids("tenant", "user") == ["jira-1"]

    class InsertBuilder:
        def values(self, **kwargs):
            self.values_kwargs = kwargs
            return self

        def on_conflict_do_nothing(self, **kwargs):
            self.conflict_kwargs = kwargs
            return {"inserted": self.values_kwargs, "conflict": kwargs}

    builder = InsertBuilder()
    monkeypatch.setattr("services.storage_db_service.pg_insert", lambda _model: builder)
    monkeypatch.setattr("services.storage_db_service.get_db_session", lambda: _db_ctx(_FakeDB()))
    db = _FakeDB()
    monkeypatch.setattr("services.storage_db_service.get_db_session", lambda: _db_ctx(db))
    assert svc.toggle_jira_integration_hidden("tenant", "user", "jira-1", True) is True
    assert db.executed

    existing = SimpleNamespace(id="jira-1")
    db = _FakeDB(first_value=existing)
    monkeypatch.setattr("services.storage_db_service.get_db_session", lambda: _db_ctx(db))
    assert svc.toggle_jira_integration_hidden("tenant", "user", "jira-1", False) is True
    assert db.deleted == [existing]


@pytest.mark.asyncio
async def test_alertmanager_service_helpers_and_delete_silence(monkeypatch):
    svc = alert_mod.AlertManagerService("http://alertmanager/")
    assert svc.alertmanager_url == "http://alertmanager"
    assert svc.parse_filter_labels(None) is None
    assert svc.parse_filter_labels('{"a":1}') == {"a": "1"}
    with pytest.raises(ValueError):
        svc.parse_filter_labels("not-json")
    with pytest.raises(ValueError):
        svc.parse_filter_labels("[]")

    current_user = TokenData(user_id="u1", username="user", tenant_id="tenant", org_id="org", role=Role.ADMIN, permissions=["p"], group_ids=["g1"])
    assert svc.user_scope(current_user) == ("tenant", "u1", ["g1"])

    captured = []
    monkeypatch.setattr(alert_mod, "enforce_public_endpoint_security", lambda *args, **kwargs: captured.append((args, kwargs)))
    monkeypatch.setattr(config, "RATE_LIMIT_PUBLIC_PER_MINUTE", 10)
    monkeypatch.setattr(config, "WEBHOOK_IP_ALLOWLIST", ["127.0.0.1"])

    monkeypatch.setattr(config, "INBOUND_WEBHOOK_TOKEN", None)
    monkeypatch.setattr(config, "IS_PRODUCTION", False)
    svc.enforce_webhook_security(_request(), scope="alerts")
    assert captured

    monkeypatch.setattr(config, "IS_PRODUCTION", True)
    with pytest.raises(HTTPException) as exc:
        svc.enforce_webhook_security(_request(), scope="alerts")
    assert exc.value.status_code == 500

    monkeypatch.setattr(config, "INBOUND_WEBHOOK_TOKEN", "secret")
    svc.enforce_webhook_security(_request(headers=[(b"x-beobservant-webhook-token", b"secret")]), scope="alerts")
    svc.enforce_webhook_security(_request(headers=[(b"authorization", b"Bearer secret")]), scope="alerts")
    with pytest.raises(HTTPException) as exc:
        svc.enforce_webhook_security(_request(), scope="alerts")
    assert exc.value.status_code == 401

    monkeypatch.setattr("services.alertmanager_service.normalize_visibility_ops", lambda value: value or "private")
    monkeypatch.setattr("services.alertmanager_service.encode_silence_comment_ops", lambda *args: json.dumps(args))
    monkeypatch.setattr("services.alertmanager_service.decode_silence_comment_ops", lambda comment: {"comment": comment})
    monkeypatch.setattr("services.alertmanager_service.apply_silence_metadata_ops", lambda *_args: "silence")
    monkeypatch.setattr("services.alertmanager_service.silence_accessible_ops", lambda *_args: True)
    monkeypatch.setattr("services.alertmanager_service.silence_owned_by_ops", lambda *_args: True)
    monkeypatch.setattr("services.alertmanager_service.resolve_rule_org_id_ops", lambda *_args: "org-2")
    monkeypatch.setattr("services.alertmanager_service.yaml_quote", lambda value: f'"{value}"')
    monkeypatch.setattr("services.alertmanager_service.group_enabled_rules", lambda rules: {"default": rules})
    monkeypatch.setattr("services.alertmanager_service.build_ruler_group_yaml", lambda group_name, rules: f"{group_name}:{len(rules)}")
    monkeypatch.setattr("services.alertmanager_service.extract_mimir_group_names", lambda namespace_yaml: [namespace_yaml])
    assert svc.normalize_visibility(None) == "private"
    assert svc.encode_silence_comment("comment", "group", ["g1"]) 
    assert svc.decode_silence_comment("c") == {"comment": "c"}
    assert svc.apply_silence_metadata("silence") == "silence"
    assert svc.silence_accessible("silence", current_user) is True
    assert svc.silence_owned_by("silence", current_user) is True
    assert svc.resolve_rule_org_id(None, current_user) == "org-2"
    assert svc._yaml_quote("x") == '"x"'
    assert svc._group_enabled_rules(["r"]) == {"default": ["r"]}
    assert svc._build_ruler_group_yaml("default", ["r1", "r2"]) == "default:2"
    assert svc._extract_mimir_group_names("ns") == ["ns"]

    async def async_value(value):
        return value

    monkeypatch.setattr("services.alertmanager_service.notify_for_alerts_ops", lambda *_args: async_value(None))
    monkeypatch.setattr("services.alertmanager_service.list_metric_names_ops", lambda *_args: async_value(["metric"]))
    monkeypatch.setattr("services.alertmanager_service.sync_mimir_rules_for_org_ops", lambda *_args: async_value(None))
    monkeypatch.setattr("services.alertmanager_service.get_alerts_ops", lambda *_args: async_value(["alert"]))
    monkeypatch.setattr("services.alertmanager_service.get_alert_groups_ops", lambda *_args: async_value(["group"]))
    monkeypatch.setattr("services.alertmanager_service.post_alerts_ops", lambda *_args: async_value(True))
    monkeypatch.setattr("services.alertmanager_service.get_silences_ops", lambda *_args: async_value(["silence"]))
    monkeypatch.setattr("services.alertmanager_service.get_silence_ops", lambda *_args: async_value("silence"))
    monkeypatch.setattr("services.alertmanager_service.create_silence_ops", lambda *_args: async_value("new-silence"))
    monkeypatch.setattr("services.alertmanager_service.update_silence_ops", lambda *_args: async_value("updated-silence"))
    monkeypatch.setattr("services.alertmanager_service.prune_removed_member_group_silences_ops", lambda *_args, **_kwargs: async_value(2))
    monkeypatch.setattr("services.alertmanager_service.get_status_ops", lambda *_args: async_value("status"))
    monkeypatch.setattr("services.alertmanager_service.get_receivers_ops", lambda *_args: async_value(["receiver"]))
    assert await svc.notify_for_alerts("tenant", [], object(), object()) is None
    assert await svc.list_metric_names("org") == ["metric"]
    assert await svc.sync_mimir_rules_for_org("org", []) is None
    assert await svc.get_alerts() == ["alert"]
    assert await svc.get_alert_groups() == ["group"]
    assert await svc.post_alerts([]) is True
    monkeypatch.setattr("services.alertmanager_service.delete_alerts_ops", lambda *_args: async_value(True))
    assert await svc.delete_alerts() is True
    assert await svc.get_silences() == ["silence"]
    assert await svc.get_silence("sil-1") == "silence"
    assert await svc.create_silence("payload") == "new-silence"
    assert await svc.update_silence("sil-1", "payload") == "updated-silence"
    assert await svc.prune_removed_member_group_silences(group_id="g1") == 2
    assert await svc.get_status() == "status"
    assert await svc.get_receivers() == ["receiver"]

    monkeypatch.setattr("services.alertmanager_service.delete_silence_ops", lambda *_args: async_value(False))
    assert await svc.delete_silence("sil-1") is False

    db = _FakeDB(first_value=None)
    monkeypatch.setattr("services.alertmanager_service.delete_silence_ops", lambda *_args: async_value(True))
    monkeypatch.setattr("services.alertmanager_service.get_db_session", lambda: _db_ctx(db))
    assert await svc.delete_silence("sil-1") is True
    assert db.added
    assert db.committed is True

    db = _FakeDB(first_value=SimpleNamespace(id="sil-1"))
    monkeypatch.setattr("services.alertmanager_service.get_db_session", lambda: _db_ctx(db))
    assert await svc.delete_silence("sil-1") is True
    assert db.added == []

    @contextmanager
    def broken_ctx():
        raise SQLAlchemyError("boom")
        yield

    monkeypatch.setattr("services.alertmanager_service.get_db_session", broken_ctx)
    assert await svc.delete_silence("sil-1") is True