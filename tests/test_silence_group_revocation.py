"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
"""

import pytest

from models.alerting.silences import Silence
from services.alerting import silences_ops


class _Svc:
    @staticmethod
    def decode_silence_comment(comment: str):
        return {"comment": comment, "visibility": "group", "shared_group_ids": ["g1"]}

    @staticmethod
    def encode_silence_comment(comment: str, visibility: str, shared_group_ids: list[str]) -> str:
        return f"{visibility}|{','.join(shared_group_ids)}|{comment}"


@pytest.mark.asyncio
async def test_prune_removed_member_group_silences_updates_matching_owner(monkeypatch):
    svc = _Svc()
    silence = Silence(
        id="s1",
        matchers=[{"name": "alertname", "value": "CPUHigh", "isRegex": False, "isEqual": True}],
        startsAt="2026-01-01T00:00:00Z",
        endsAt="2026-01-01T01:00:00Z",
        createdBy="owner",
        comment="maintenance",
        status={"state": "active"},
    )

    async def _fake_get_silences(*args, **kwargs):
        return [silence]

    monkeypatch.setattr(silences_ops, "get_silences", _fake_get_silences)

    calls = {}

    async def _fake_update(_service, silence_id, payload):
        calls["silence_id"] = silence_id
        calls["comment"] = payload.comment
        return silence_id

    monkeypatch.setattr(silences_ops, "update_silence", _fake_update)

    updated = await silences_ops.prune_removed_member_group_silences(
        svc,
        group_id="g1",
        removed_user_ids=[],
        removed_usernames=["owner"],
    )

    assert updated == 1
    assert calls["silence_id"] == "s1"
    assert calls["comment"].startswith("private||")
