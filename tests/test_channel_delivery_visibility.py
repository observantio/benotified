"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
"""

from types import SimpleNamespace

from services.storage.channels import ChannelStorageService


def _group(group_id: str):
    return SimpleNamespace(id=group_id)


def test_group_rule_cannot_dispatch_private_channel():
    rule = SimpleNamespace(
        visibility="group",
        created_by="u1",
        shared_groups=[_group("g1")],
    )
    channel = SimpleNamespace(
        visibility="private",
        created_by="u1",
        shared_groups=[],
    )
    assert ChannelStorageService._rule_channel_compatible(rule, channel) is False


def test_group_rule_dispatches_group_channel_with_overlap():
    rule = SimpleNamespace(
        visibility="group",
        created_by="u1",
        shared_groups=[_group("g1")],
    )
    channel = SimpleNamespace(
        visibility="group",
        created_by="u2",
        shared_groups=[_group("g1")],
    )
    assert ChannelStorageService._rule_channel_compatible(rule, channel) is True
