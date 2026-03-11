"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy.exc import SQLAlchemyError

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from models.access.auth_models import Role, TokenData
from models.alerting.silences import Matcher, Silence, SilenceCreate, Visibility
from services.alerting import silences_ops as sil_mod


class _Response:
    def __init__(self, payload, *, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://alertmanager")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("bad", request=request, response=response)


class _Query:
    def __init__(self, rows, *, error=None):
        self.rows = rows
        self.error = error

    def all(self):
        if self.error:
            raise self.error
        return self.rows


class _DB:
    def __init__(self, rows=None, *, error=None):
        self.rows = rows or []
        self.error = error

    def query(self, *_args, **_kwargs):
        return _Query(self.rows, error=self.error)


class _Ctx:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        return self.db

    def __exit__(self, exc_type, exc, tb):
        return False


class _Client:
    def __init__(self, *, get_payload=None, post_payload=None, delete_status=200, get_error=None):
        self.get_payload = get_payload
        self.post_payload = post_payload
        self.delete_status = delete_status
        self.get_error = get_error
        self.calls = []

    async def get(self, url, params=None):
        self.calls.append(("get", url, params))
        if self.get_error:
            raise self.get_error
        return _Response(self.get_payload)

    async def post(self, url, json=None):
        self.calls.append(("post", url, json))
        return _Response(self.post_payload)

    async def delete(self, url):
        self.calls.append(("delete", url, None))
        return _Response({}, status_code=self.delete_status)


def _user(**kwargs) -> TokenData:
    payload = {
        "user_id": "u1",
        "username": "alice",
        "tenant_id": "tenant-a",
        "org_id": "org-a",
        "role": Role.USER,
        "permissions": ["read:silences"],
        "group_ids": ["g1"],
        "is_superuser": False,
    }
    payload.update(kwargs)
    return TokenData(**payload)


def _silence(**kwargs) -> Silence:
    payload = {
        "id": "s1",
        "matchers": [{"name": "alertname", "value": "CPUHigh", "isRegex": False, "isEqual": True}],
        "startsAt": "2024-01-01T00:00:00Z",
        "endsAt": "2024-01-01T01:00:00Z",
        "createdBy": "u1",
        "comment": "encoded",
        "status": {"state": "active"},
        "visibility": "group",
        "sharedGroupIds": ["g1", "g2"],
    }
    payload.update(kwargs)
    return Silence.model_validate(payload)


def test_silence_metadata_and_access_helpers():
    service = SimpleNamespace(decode_silence_comment=lambda comment: {"comment": "plain", "visibility": "group", "shared_group_ids": ["g1"]})

    assert sil_mod._visibility_value("bad") == Visibility.TENANT
    silence = sil_mod.apply_silence_metadata(service, _silence())
    assert silence.comment == "plain"
    assert silence.visibility == Visibility.GROUP
    assert silence.shared_group_ids == ["g1"]

    assert sil_mod.silence_accessible(_silence(createdBy="u1"), _user()) is True
    assert sil_mod.silence_accessible(_silence(createdBy="u2", visibility="tenant"), _user()) is True
    assert sil_mod.silence_accessible(_silence(createdBy="u2", visibility="group", sharedGroupIds=["g1"]), _user()) is True
    assert sil_mod.silence_accessible(_silence(createdBy="u2", visibility="private", sharedGroupIds=[]), _user()) is False
    assert sil_mod.silence_owned_by(_silence(createdBy="u1"), _user()) is True
    assert sil_mod.silence_owned_by(_silence(createdBy="u2"), _user()) is False


@pytest.mark.asyncio
async def test_get_silences_get_single_create_and_update(monkeypatch):
    client = _Client(
        get_payload=[
            _silence(id="keep").model_dump(by_alias=True),
            _silence(id="purged").model_dump(by_alias=True),
        ],
        post_payload={"silenceID": "new-id"},
    )
    service = SimpleNamespace(_client=client, alertmanager_url="https://am")
    monkeypatch.setattr(sil_mod, "get_db_session", lambda: _Ctx(_DB([SimpleNamespace(id="purged")])) )

    silences = await sil_mod.get_silences(service, filter_labels={"severity": "critical"})
    assert [item.id for item in silences] == ["keep"]
    assert client.calls[0][2] == {"filter": ['severity="critical"']}

    client.get_payload = _silence(id="single").model_dump(by_alias=True)
    single = await sil_mod.get_silence(service, "single")
    assert single and single.id == "single"

    created = await sil_mod.create_silence(
        service,
        SilenceCreate(
            matchers=[Matcher(name="severity", value="critical")],
            startsAt="2024-01-01T00:00:00Z",
            endsAt="2024-01-01T01:00:00Z",
            createdBy="u1",
            comment="hello",
        ),
    )
    assert created == "new-id"

    deleted = []
    created_payloads = []

    async def fake_delete(_service, silence_id):
        deleted.append(silence_id)
        return True

    async def fake_create(_service, silence):
        created_payloads.append(silence.comment)
        return "recreated"

    monkeypatch.setattr(sil_mod, "delete_silence", fake_delete)
    monkeypatch.setattr(sil_mod, "create_silence", fake_create)
    updated = await sil_mod.update_silence(service, "old-id", SilenceCreate(matchers=[Matcher(name="a", value="b")], startsAt="2024-01-01T00:00:00Z", endsAt="2024-01-01T01:00:00Z", createdBy="u1", comment="updated"))
    assert updated == "recreated"
    assert deleted == ["old-id"]
    assert created_payloads == ["updated"]


@pytest.mark.asyncio
async def test_silence_error_and_delete_paths(monkeypatch):
    service = SimpleNamespace(_client=_Client(get_payload=[]), alertmanager_url="https://am")
    service._client.get_error = httpx.RequestError("boom", request=httpx.Request("GET", "https://am"))
    monkeypatch.setattr(sil_mod, "get_db_session", lambda: _Ctx(_DB([], error=SQLAlchemyError("db"))))
    assert await sil_mod.get_silences(service) == []
    assert await sil_mod.get_silence(service, "missing") is None

    service = SimpleNamespace(_client=_Client(get_payload=[], delete_status=200), alertmanager_url="https://am")

    states = iter([
        _silence(status={"state": "active"}),
        _silence(status={"state": "expired"}),
    ])

    async def fake_get_silence(_service, _silence_id):
        return next(states)

    async def fake_sleep(_seconds):
        return None

    monkeypatch.setattr(sil_mod, "get_silence", fake_get_silence)
    monkeypatch.setattr(sil_mod.asyncio, "sleep", fake_sleep)
    assert await sil_mod.delete_silence(service, "s1") is True

    states = iter([_silence(status={"state": "active"}), _silence(status={"state": "active"}), _silence(status={"state": "active"})])
    assert await sil_mod.delete_silence(service, "s1") is False


@pytest.mark.asyncio
async def test_prune_removed_member_group_silences(monkeypatch):
    service = SimpleNamespace(
        encode_silence_comment=lambda comment, visibility, shared_group_ids: f"{comment}|{visibility}|{','.join(shared_group_ids)}",
        decode_silence_comment=lambda comment: {"comment": "decoded", "visibility": "group", "shared_group_ids": ["g1", "g2"]},
    )

    assert await sil_mod.prune_removed_member_group_silences(service, group_id="", removed_user_ids=["u1"]) == 0
    assert await sil_mod.prune_removed_member_group_silences(service, group_id="g1", removed_user_ids=[]) == 0

    silences = [
        _silence(id="s1", createdBy="u1", visibility="group", sharedGroupIds=["g1", "g2"]),
        _silence(id="s2", createdBy="other", visibility="group", sharedGroupIds=["g1"]),
        _silence(id=None, createdBy="u1", visibility="group", sharedGroupIds=["g1"]),
    ]
    updated = []

    async def fake_get_silences(_service, filter_labels=None):
        return silences

    async def fake_update(_service, silence_id, payload):
        updated.append((silence_id, payload.comment))
        return f"new-{silence_id}"

    monkeypatch.setattr(sil_mod, "get_silences", fake_get_silences)
    monkeypatch.setattr(sil_mod, "update_silence", fake_update)

    result = await sil_mod.prune_removed_member_group_silences(service, group_id="g1", removed_user_ids=["u1"], removed_usernames=["alice"])
    assert result == 1
    assert updated == [("s1", "decoded|group|g2")]
