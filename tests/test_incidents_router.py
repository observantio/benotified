"""
Tests for the incidents router, mostly focused on side effects such as
notification dispatch when an incident is assigned.
"""

import pytest

# ensure configuration is initialized with safe test environment before
# importing modules that reference `config`.
from tests._env import ensure_test_env
ensure_test_env()

from models.access.auth_models import TokenData
from models.alerting.incidents import (
    AlertIncident,
    AlertIncidentUpdateRequest,
    IncidentStatus,
)

# import the incidents router module directly by file path so we don't
# trigger the package-level imports in routers/observability/__init__
import importlib.util
import sys
from pathlib import Path

incidents_path = Path(__file__).resolve().parents[1] / "routers" / "observability" / "incidents.py"
spec = importlib.util.spec_from_file_location("incidents_module", incidents_path)
incidents_mod = importlib.util.module_from_spec(spec)
sys.modules["incidents_module"] = incidents_mod
spec.loader.exec_module(incidents_mod)

patch_incident = incidents_mod.patch_incident
storage_service = incidents_mod.storage_service
notification_service = incidents_mod.notification_service


@pytest.mark.asyncio
async def test_patch_incident_sends_assignment_email(monkeypatch):
    # prepare fake existing and updated incidents
    existing = AlertIncident(
        id="i1",
        fingerprint="fp",
        alertName="Alert1",
        severity="critical",
        status=IncidentStatus.OPEN,
        assignee=None,
        notes=[],
        labels={},
        annotations={},
        visibility="public",
        sharedGroupIds=[],
        lastSeenAt="2023-01-01T00:00:00Z",
        createdAt="2023-01-01T00:00:00Z",
        updatedAt="2023-01-01T00:00:00Z",
        userManaged=False,
        hideWhenResolved=False,
    )
    updated = existing.model_copy(update={"assignee": "bob@example.com"})

    monkeypatch.setattr(storage_service, "get_incident_for_user", lambda *args, **kwargs: existing)
    monkeypatch.setattr(storage_service, "update_incident", lambda *args, **kwargs: updated)

    called = {}

    async def fake_email(recipient_email, incident_title, incident_status, incident_severity, actor):
        called['args'] = (recipient_email, incident_title, incident_status, incident_severity, actor)
        return True

    monkeypatch.setattr(notification_service, "send_incident_assignment_email", fake_email)

    user = TokenData(
        user_id="u1",
        username="alice",
        tenant_id="t1",
        org_id="o1",
        role="user",
        permissions=[],
        group_ids=[],
        is_superuser=False,
    )

    payload = AlertIncidentUpdateRequest(assignee="bob@example.com")
    result = await patch_incident("i1", payload, current_user=user)

    assert result.assignee == "bob@example.com"
    assert 'args' in called
    assert called['args'][0] == "bob@example.com"
    assert called['args'][1] == "Alert1"
    assert called['args'][3] == "critical"
