"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env
ensure_test_env()

import json
from cryptography.fernet import Fernet

from config import config
from services.common import encryption as encryption_module
from services.storage.channels import ChannelStorageService
from models.alerting.channels import NotificationChannelCreate, ChannelType
from database import get_db_session
from db_models import NotificationChannel as NotificationChannelDB


def test_encrypt_decrypt_config_roundtrip(monkeypatch):
    key = Fernet.generate_key().decode()
    prev = config.DATA_ENCRYPTION_KEY
    try:
        config.DATA_ENCRYPTION_KEY = key
        cfg = {"a": 1, "b": "s"}
        enc = encryption_module.encrypt_config(cfg)
        assert isinstance(enc, dict) and "__encrypted__" in enc
        dec = encryption_module.decrypt_config(enc)
        assert dec == cfg
    finally:
        config.DATA_ENCRYPTION_KEY = prev


import pytest

@pytest.mark.skipif(not __import__('database', fromlist=['']).connection_test(), reason="DB not available")
def test_create_channel_stores_encrypted_and_owner_sees_config(monkeypatch):
    svc = ChannelStorageService(None)
    prev = config.DATA_ENCRYPTION_KEY
    try:
        config.DATA_ENCRYPTION_KEY = Fernet.generate_key().decode()
        ch_in = NotificationChannelCreate(name="c1", type=ChannelType.SLACK, config={"webhook_url": "https://x"}, enabled=True, visibility="private")
        created = svc.create_notification_channel(ch_in, tenant_id="t-1", user_id="owner", group_ids=None)
        # owner should see full config
        assert created.config == {"webhook_url": "https://x"}

        # DB should store encrypted payload
        with get_db_session() as db:
            db_ch = db.query(NotificationChannelDB).filter(NotificationChannelDB.id == created.id).first()
            assert db_ch is not None
            assert isinstance(db_ch.config, dict)
            assert "__encrypted__" in db_ch.config
    finally:
        config.DATA_ENCRYPTION_KEY = prev


import pytest

@pytest.mark.skipif(not __import__('database', fromlist=['']).connection_test(), reason="DB not available")
def test_get_notification_channel_access_control():
    svc = ChannelStorageService(None)
    # create channel as owner
    ch_in = NotificationChannelCreate(name="c2", type=ChannelType.SLACK, config={"webhook_url": "https://x"}, enabled=True, visibility="private")
    created = svc.create_notification_channel(ch_in, tenant_id="t-2", user_id="owner2", group_ids=None)

    # non-owner should not be able to fetch private channel
    fetched = svc.get_notification_channel(created.id, tenant_id="t-2", user_id="someone_else", group_ids=None)
    assert fetched is None

    # owner can fetch and sees config
    fetched_owner = svc.get_notification_channel(created.id, tenant_id="t-2", user_id="owner2", group_ids=None)
    assert fetched_owner is not None
    assert fetched_owner.config == {"webhook_url": "https://x"}
