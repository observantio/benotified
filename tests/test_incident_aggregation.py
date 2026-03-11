"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
"""

import os
import json
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/observantio_test")

from db_models import AlertIncident, Base
from services.storage import incidents as incidents_module
from services.storage.incidents import (
    IncidentStorageService,
    METRIC_STATES_ANNOTATION_KEY,
)
from services.common.meta import INCIDENT_META_KEY


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


def test_sync_incidents_deduplicates_existing_open_rows_with_same_incident_key(monkeypatch):
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

    tenant_id = "t1"
    now = datetime.now(timezone.utc)
    key = "rule:Memory Boom|scope:*"

    with SessionLocal() as db:
        for fp in ("fp-a", "fp-b", "fp-c", "fp-d"):
            db.add(
                AlertIncident(
                    id=f"inc-{fp}",
                    tenant_id=tenant_id,
                    fingerprint=fp,
                    alert_name="Memory Boom",
                    severity="warning",
                    status="open",
                    labels={"alertname": "Memory Boom", "severity": "warning", "state": fp},
                    annotations={INCIDENT_META_KEY: json.dumps({"incident_key": key})},
                    starts_at=now,
                    last_seen_at=now,
                    resolved_at=None,
                    notes=[],
                )
            )
        db.commit()

    service = IncidentStorageService()
    service.sync_incidents_from_alerts(
        tenant_id,
        [
            {
                "fingerprint": "fp-x",
                "labels": {
                    "alertname": "Memory Boom",
                    "severity": "warning",
                    "state": "cached",
                },
                "annotations": {"summary": "Memory Boom"},
            }
        ],
        resolve_missing=False,
    )

    with SessionLocal() as db:
        incidents = db.query(AlertIncident).filter(AlertIncident.tenant_id == tenant_id).all()
        open_incidents = [item for item in incidents if item.status == "open"]
        resolved_incidents = [item for item in incidents if item.status == "resolved"]
        assert len(open_incidents) == 1
        assert len(resolved_incidents) == 3


def test_sync_incidents_aggregates_metric_states_into_single_incident(monkeypatch):
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
                "fingerprint": "fp-used",
                "labels": {
                    "alertname": "Memory Boom",
                    "severity": "warning",
                    "state": "used",
                },
                "annotations": {"summary": "used"},
            },
            {
                "fingerprint": "fp-free",
                "labels": {
                    "alertname": "Memory Boom",
                    "severity": "warning",
                    "state": "free",
                },
                "annotations": {"summary": "free"},
            },
            {
                "fingerprint": "fp-cached",
                "labels": {
                    "alertname": "Memory Boom",
                    "severity": "warning",
                    "state": "cached",
                },
                "annotations": {"summary": "cached"},
            },
        ],
        resolve_missing=False,
    )

    with SessionLocal() as db:
        incidents = db.query(AlertIncident).filter(AlertIncident.tenant_id == tenant_id).all()
        assert len(incidents) == 1
        merged = str((incidents[0].annotations or {}).get(METRIC_STATES_ANNOTATION_KEY) or "")
        assert merged == "used,free,cached"


def test_sync_incidents_skips_suppressed_alerts(monkeypatch):
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
                "fingerprint": "fp-suppressed",
                "labels": {
                    "alertname": "system_memory_usage_bytes",
                    "severity": "critical",
                    "org_id": "org-1",
                },
                "annotations": {"summary": "suppressed"},
                "status": {"state": "suppressed", "silencedBy": ["s1"], "inhibitedBy": []},
            }
        ],
        resolve_missing=False,
    )

    with SessionLocal() as db:
        incidents = db.query(AlertIncident).filter(AlertIncident.tenant_id == tenant_id).all()
        assert len(incidents) == 0
