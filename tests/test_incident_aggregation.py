"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
"""

import os
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/observantio_test")

from db_models import AlertIncident, Base
from services.storage import incidents as incidents_module
from services.storage.incidents import IncidentStorageService


def _session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_sync_incidents_aggregates_multiple_fingerprints_into_single_incident(monkeypatch):
    SessionLocal = _session_factory()

    @contextmanager
    def fake_db_session():
        db = SessionLocal()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    monkeypatch.setattr(incidents_module, "get_db_session", fake_db_session)

    service = IncidentStorageService()
    tenant_id = "t1"

    service.sync_incidents_from_alerts(
        tenant_id,
        [
            {
                "fingerprint": "fp-a",
                "labels": {
                    "alertname": "system_memory_usage_bytes",
                    "instance": "node-a",
                    "severity": "critical",
                    "org_id": "org-1",
                },
                "annotations": {"summary": "A"},
            },
            {
                "fingerprint": "fp-b",
                "labels": {
                    "alertname": "system_memory_usage_bytes",
                    "instance": "node-b",
                    "severity": "critical",
                    "org_id": "org-1",
                },
                "annotations": {"summary": "B"},
            },
        ],
        resolve_missing=False,
    )

    with SessionLocal() as db:
        incidents = db.query(AlertIncident).filter(AlertIncident.tenant_id == tenant_id).all()
        assert len(incidents) == 1
        assert incidents[0].status == "open"


def test_sync_incidents_resolve_uses_incident_key_not_single_fingerprint(monkeypatch):
    SessionLocal = _session_factory()

    @contextmanager
    def fake_db_session():
        db = SessionLocal()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    monkeypatch.setattr(incidents_module, "get_db_session", fake_db_session)

    service = IncidentStorageService()
    tenant_id = "t1"

    service.sync_incidents_from_alerts(
        tenant_id,
        [
            {
                "fingerprint": "fp-a",
                "labels": {"alertname": "system_memory_usage_bytes", "severity": "critical", "org_id": "org-1"},
                "annotations": {"summary": "A"},
            },
            {
                "fingerprint": "fp-b",
                "labels": {"alertname": "system_memory_usage_bytes", "severity": "critical", "org_id": "org-1"},
                "annotations": {"summary": "B"},
            },
        ],
        resolve_missing=False,
    )
    service.sync_incidents_from_alerts(tenant_id, [], resolve_missing=True)

    with SessionLocal() as db:
        incidents = db.query(AlertIncident).filter(AlertIncident.tenant_id == tenant_id).all()
        assert len(incidents) == 1
        assert incidents[0].status == "resolved"
