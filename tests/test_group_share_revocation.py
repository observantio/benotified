"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
"""

import json
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/observantio_test")

from db_models import AlertIncident, AlertRule, Base, Group, NotificationChannel, Tenant
from services.common.meta import INCIDENT_META_KEY, parse_meta
from services.storage.revocation import prune_removed_member_group_shares


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_prune_removed_member_group_shares_revokes_visibility_across_resources():
    db = _session()
    db.add_all(
        [
            Tenant(
                id="t1",
                name="tenant-1",
                display_name="Tenant 1",
                settings={
                    "jira_integrations": [
                        {
                            "id": "jira-1",
                            "name": "Jira",
                            "createdBy": "u1",
                            "visibility": "group",
                            "sharedGroupIds": ["g1"],
                        }
                    ]
                },
            ),
            Group(id="g1", tenant_id="t1", name="Team A"),
            Group(id="g2", tenant_id="t1", name="Team B"),
        ]
    )
    db.commit()

    g1 = db.query(Group).filter_by(id="g1", tenant_id="t1").first()
    assert g1 is not None

    rule = AlertRule(
        id="r1",
        tenant_id="t1",
        created_by="u1",
        name="Rule",
        group="default",
        expr="up == 0",
        visibility="group",
    )
    rule.shared_groups.append(g1)

    channel = NotificationChannel(
        id="c1",
        tenant_id="t1",
        created_by="u1",
        name="Channel",
        type="slack",
        config={"webhook_url": "https://hooks.slack.test/abc"},
        enabled=True,
        visibility="group",
    )
    channel.shared_groups.append(g1)

    incident = AlertIncident(
        id="i1",
        tenant_id="t1",
        fingerprint="fp-1",
        alert_name="HighErrorRate",
        severity="critical",
        status="open",
        labels={},
        annotations={
            INCIDENT_META_KEY: json.dumps(
                {
                    "visibility": "group",
                    "shared_group_ids": ["g1"],
                    "created_by": "u1",
                }
            )
        },
    )

    db.add_all([rule, channel, incident])
    db.commit()

    counts = prune_removed_member_group_shares(
        db,
        tenant_id="t1",
        group_id="g1",
        removed_user_ids=["u1"],
    )
    db.commit()

    db_rule = db.query(AlertRule).filter_by(id="r1", tenant_id="t1").first()
    db_channel = db.query(NotificationChannel).filter_by(id="c1", tenant_id="t1").first()
    db_incident = db.query(AlertIncident).filter_by(id="i1", tenant_id="t1").first()
    db_tenant = db.query(Tenant).filter_by(id="t1").first()

    assert db_rule is not None and db_rule.visibility == "private" and len(db_rule.shared_groups or []) == 0
    assert db_channel is not None and db_channel.visibility == "private" and len(db_channel.shared_groups or []) == 0
    assert db_incident is not None
    inc_meta = parse_meta(db_incident.annotations or {})
    assert inc_meta.get("visibility") == "private"
    assert inc_meta.get("shared_group_ids") == []
    assert db_tenant is not None
    jira_items = ((db_tenant.settings or {}).get("jira_integrations") or [])
    assert isinstance(jira_items, list) and jira_items
    assert jira_items[0].get("visibility") == "private"
    assert jira_items[0].get("sharedGroupIds") == []

    assert counts["rules"] == 1
    assert counts["channels"] == 1
    assert counts["incidents"] == 1
    assert counts["jira_integrations"] == 1


def test_prune_removed_member_group_shares_matches_username_creators():
    db = _session()
    db.add_all(
        [
            Tenant(
                id="t1",
                name="tenant-1",
                display_name="Tenant 1",
                settings={
                    "jira_integrations": [
                        {
                            "id": "jira-1",
                            "name": "Jira",
                            "createdBy": "alice",
                            "visibility": "group",
                            "sharedGroupIds": ["g1"],
                        }
                    ]
                },
            ),
            Group(id="g1", tenant_id="t1", name="Team A"),
        ]
    )
    db.commit()

    g1 = db.query(Group).filter_by(id="g1", tenant_id="t1").first()
    assert g1 is not None

    rule = AlertRule(
        id="r1",
        tenant_id="t1",
        created_by="alice",
        name="Rule",
        group="default",
        expr="up == 0",
        visibility="group",
    )
    rule.shared_groups.append(g1)

    channel = NotificationChannel(
        id="c1",
        tenant_id="t1",
        created_by="alice",
        name="Channel",
        type="slack",
        config={"webhook_url": "https://hooks.slack.test/abc"},
        enabled=True,
        visibility="group",
    )
    channel.shared_groups.append(g1)

    incident = AlertIncident(
        id="i1",
        tenant_id="t1",
        fingerprint="fp-1",
        alert_name="HighErrorRate",
        severity="critical",
        status="open",
        labels={},
        annotations={
            INCIDENT_META_KEY: json.dumps(
                {
                    "visibility": "group",
                    "shared_group_ids": ["g1"],
                    "created_by": "alice",
                }
            )
        },
    )

    db.add_all([rule, channel, incident])
    db.commit()

    counts = prune_removed_member_group_shares(
        db,
        tenant_id="t1",
        group_id="g1",
        removed_user_ids=["u1"],
        removed_usernames=["ALICE"],
    )
    db.commit()

    db_rule = db.query(AlertRule).filter_by(id="r1", tenant_id="t1").first()
    db_channel = db.query(NotificationChannel).filter_by(id="c1", tenant_id="t1").first()
    db_incident = db.query(AlertIncident).filter_by(id="i1", tenant_id="t1").first()
    db_tenant = db.query(Tenant).filter_by(id="t1").first()

    assert db_rule is not None and db_rule.visibility == "private" and len(db_rule.shared_groups or []) == 0
    assert db_channel is not None and db_channel.visibility == "private" and len(db_channel.shared_groups or []) == 0
    assert db_incident is not None
    inc_meta = parse_meta(db_incident.annotations or {})
    assert inc_meta.get("visibility") == "private"
    assert inc_meta.get("shared_group_ids") == []
    assert db_tenant is not None
    jira_items = ((db_tenant.settings or {}).get("jira_integrations") or [])
    assert isinstance(jira_items, list) and jira_items
    assert jira_items[0].get("visibility") == "private"
    assert jira_items[0].get("sharedGroupIds") == []

    assert counts["rules"] == 1
    assert counts["channels"] == 1
    assert counts["incidents"] == 1
    assert counts["jira_integrations"] == 1
