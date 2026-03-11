"""
SQLAlchemy models for Be Notified Service, defining the schema for tenants, groups, alert rules, incidents, notification channels, and purged silences.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Index, String, Table, Text, JSON,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from config import config
from custom_types.json import JSONDict, JSONList


class Base(DeclarativeBase):
    pass


FK_GROUPS  = "groups.id"
FK_TENANTS = "tenants.id"
CASCADE    = "all, delete-orphan"


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


rule_groups = Table(
    "rule_groups",
    Base.metadata,
    Column("rule_id",  String, ForeignKey("alert_rules.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", String, ForeignKey(FK_GROUPS,       ondelete="CASCADE"), primary_key=True),
    Index("idx_rule_groups_rule",  "rule_id"),
    Index("idx_rule_groups_group", "group_id"),
)

channel_groups = Table(
    "channel_groups",
    Base.metadata,
    Column("channel_id", String, ForeignKey("notification_channels.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id",   String, ForeignKey(FK_GROUPS,                 ondelete="CASCADE"), primary_key=True),
    Index("idx_channel_groups_channel", "channel_id"),
    Index("idx_channel_groups_group",   "group_id"),
)


class Tenant(Base):
    __tablename__ = "tenants"

    id:           Mapped[str]            = mapped_column(String,      primary_key=True, default=_uuid)
    name:         Mapped[str]            = mapped_column(String(100), unique=True, nullable=False, index=True)
    display_name: Mapped[Optional[str]]  = mapped_column(String(200))
    is_active:    Mapped[bool]           = mapped_column(Boolean,     default=True, nullable=False)
    settings:     Mapped[JSONDict] = mapped_column(JSON,        default=dict)
    created_at:   Mapped[datetime]       = mapped_column(DateTime,    default=_now, nullable=False)
    updated_at:   Mapped[datetime]       = mapped_column(DateTime,    default=_now, onupdate=_now, nullable=False)

    groups:                Mapped[List["Group"]]               = relationship("Group",               back_populates="tenant", cascade=CASCADE)
    alert_rules:           Mapped[List["AlertRule"]]           = relationship("AlertRule",           back_populates="tenant", cascade=CASCADE)
    alert_incidents:       Mapped[List["AlertIncident"]]       = relationship("AlertIncident",       back_populates="tenant", cascade=CASCADE)
    notification_channels: Mapped[List["NotificationChannel"]] = relationship("NotificationChannel", back_populates="tenant", cascade=CASCADE)

    __table_args__ = (
        Index("idx_tenants_active", "is_active"),
    )


class Group(Base):
    __tablename__ = "groups"

    id:          Mapped[str]           = mapped_column(String,      primary_key=True, default=_uuid)
    tenant_id:   Mapped[str]           = mapped_column(String,      ForeignKey(FK_TENANTS, ondelete="CASCADE"), nullable=False, index=True)
    name:        Mapped[str]           = mapped_column(String(100), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text)
    is_active:   Mapped[bool]          = mapped_column(Boolean,     default=True, nullable=False)
    created_at:  Mapped[datetime]      = mapped_column(DateTime,    default=_now, nullable=False)
    updated_at:  Mapped[datetime]      = mapped_column(DateTime,    default=_now, onupdate=_now, nullable=False)

    tenant:          Mapped["Tenant"]                    = relationship("Tenant",               back_populates="groups")
    shared_channels: Mapped[List["NotificationChannel"]] = relationship("NotificationChannel", secondary=channel_groups, back_populates="shared_groups")
    shared_rules:    Mapped[List["AlertRule"]]           = relationship("AlertRule",            secondary=rule_groups,    back_populates="shared_groups")

    __table_args__ = (
        Index("idx_groups_tenant_active", "tenant_id", "is_active"),
        Index("idx_groups_tenant_name",   "tenant_id", "name", unique=True),
    )


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id:                    Mapped[str]            = mapped_column(String,      primary_key=True, default=_uuid)
    tenant_id:             Mapped[str]            = mapped_column(String,      ForeignKey(FK_TENANTS, ondelete="CASCADE"), nullable=False, index=True)
    created_by:            Mapped[Optional[str]]  = mapped_column(String,      index=True)
    org_id:                Mapped[Optional[str]]  = mapped_column(String,      index=True)
    name:                  Mapped[str]            = mapped_column(String(200), nullable=False, index=True)
    group:                 Mapped[str]            = mapped_column(String(100), nullable=False, default=config.DEFAULT_RULE_GROUP)
    expr:                  Mapped[str]            = mapped_column(Text,        nullable=False)
    duration:              Mapped[str]            = mapped_column(String(20),  nullable=False, default="5m")
    severity:              Mapped[str]            = mapped_column(String(20),  nullable=False, default="warning", index=True)
    labels:                Mapped[JSONDict] = mapped_column(JSON,        default=dict)
    annotations:           Mapped[JSONDict] = mapped_column(JSON,        default=dict)
    enabled:               Mapped[bool]           = mapped_column(Boolean,     default=True, nullable=False)
    notification_channels: Mapped[JSONList]      = mapped_column(JSON,        default=list)
    visibility:            Mapped[str]            = mapped_column(String(20),  nullable=False, default="private", index=True)
    created_at:            Mapped[datetime]       = mapped_column(DateTime,    default=_now, nullable=False)
    updated_at:            Mapped[datetime]       = mapped_column(DateTime,    default=_now, onupdate=_now, nullable=False)

    tenant:        Mapped["Tenant"]      = relationship("Tenant", back_populates="alert_rules")
    shared_groups: Mapped[List["Group"]] = relationship("Group",  secondary=rule_groups, back_populates="shared_rules")

    __table_args__ = (
        Index("idx_alert_rules_tenant_enabled", "tenant_id", "enabled"),
        Index("idx_alert_rules_severity",       "severity"),
        Index("idx_alert_rules_visibility",     "visibility"),
    )


class AlertIncident(Base):
    __tablename__ = "alert_incidents"

    id:           Mapped[str]               = mapped_column(String,      primary_key=True, default=_uuid)
    tenant_id:    Mapped[str]               = mapped_column(String,      ForeignKey(FK_TENANTS, ondelete="CASCADE"), nullable=False, index=True)
    fingerprint:  Mapped[str]               = mapped_column(String(255), nullable=False, index=True)
    alert_name:   Mapped[str]               = mapped_column(String(200), nullable=False, index=True)
    severity:     Mapped[str]               = mapped_column(String(20),  nullable=False, default="warning", index=True)
    status:       Mapped[str]               = mapped_column(String(20),  nullable=False, default="open",    index=True)
    assignee:     Mapped[Optional[str]]     = mapped_column(String(200))
    notes:        Mapped[JSONList]         = mapped_column(JSON,        default=list)
    labels:       Mapped[JSONDict]    = mapped_column(JSON,        default=dict)
    annotations:  Mapped[JSONDict]    = mapped_column(JSON,        default=dict)
    starts_at:    Mapped[Optional[datetime]] = mapped_column(DateTime,   index=True)
    last_seen_at: Mapped[datetime]          = mapped_column(DateTime,    nullable=False, default=_now, index=True)
    resolved_at:  Mapped[Optional[datetime]] = mapped_column(DateTime,   index=True)
    created_at:   Mapped[datetime]          = mapped_column(DateTime,    default=_now, nullable=False)
    updated_at:   Mapped[datetime]          = mapped_column(DateTime,    default=_now, onupdate=_now, nullable=False)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="alert_incidents")

    __table_args__ = (
        Index("idx_alert_incidents_tenant_status",      "tenant_id", "status"),
        Index("idx_alert_incidents_tenant_fingerprint", "tenant_id", "fingerprint", unique=True),
    )


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id:         Mapped[str]            = mapped_column(String,      primary_key=True, default=_uuid)
    tenant_id:  Mapped[str]            = mapped_column(String,      ForeignKey(FK_TENANTS, ondelete="CASCADE"), nullable=False, index=True)
    created_by: Mapped[Optional[str]]  = mapped_column(String,      index=True)
    name:       Mapped[str]            = mapped_column(String(200), nullable=False, index=True)
    type:       Mapped[str]            = mapped_column(String(50),  nullable=False, index=True)
    config:     Mapped[JSONDict] = mapped_column(JSON,        nullable=False, default=dict)
    enabled:    Mapped[bool]           = mapped_column(Boolean,     default=True, nullable=False)
    visibility: Mapped[str]            = mapped_column(String(20),  nullable=False, default="private", index=True)
    created_at: Mapped[datetime]       = mapped_column(DateTime,    default=_now, nullable=False)
    updated_at: Mapped[datetime]       = mapped_column(DateTime,    default=_now, onupdate=_now, nullable=False)

    tenant:        Mapped["Tenant"]      = relationship("Tenant", back_populates="notification_channels")
    shared_groups: Mapped[List["Group"]] = relationship("Group",  secondary=channel_groups, back_populates="shared_channels")

    __table_args__ = (
        Index("idx_notification_channels_tenant_enabled", "tenant_id", "enabled"),
        Index("idx_notification_channels_type",           "type"),
        Index("idx_notification_channels_visibility",     "visibility"),
    )


class PurgedSilence(Base):
    __tablename__ = "purged_silences"

    id:         Mapped[str]           = mapped_column(String,   primary_key=True)
    tenant_id:  Mapped[Optional[str]] = mapped_column(String,   ForeignKey(FK_TENANTS, ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime]      = mapped_column(DateTime, default=_now, nullable=False)


class HiddenAlertRule(Base):
    __tablename__ = "hidden_alert_rules"

    id:         Mapped[str]      = mapped_column(String, primary_key=True, default=_uuid)
    tenant_id:  Mapped[str]      = mapped_column(String, ForeignKey(FK_TENANTS, ondelete="CASCADE"), nullable=False, index=True)
    user_id:    Mapped[str]      = mapped_column(String, nullable=False, index=True)
    rule_id:    Mapped[str]      = mapped_column(String, ForeignKey("alert_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    __table_args__ = (
        Index("idx_hidden_alert_rules_tenant_user", "tenant_id", "user_id"),
        Index("idx_hidden_alert_rules_unique", "tenant_id", "user_id", "rule_id", unique=True),
    )


class HiddenSilence(Base):
    __tablename__ = "hidden_silences"

    id:         Mapped[str]      = mapped_column(String, primary_key=True, default=_uuid)
    tenant_id:  Mapped[str]      = mapped_column(String, ForeignKey(FK_TENANTS, ondelete="CASCADE"), nullable=False, index=True)
    user_id:    Mapped[str]      = mapped_column(String, nullable=False, index=True)
    silence_id: Mapped[str]      = mapped_column(String, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    __table_args__ = (
        Index("idx_hidden_silences_tenant_user", "tenant_id", "user_id"),
        Index("idx_hidden_silences_unique", "tenant_id", "user_id", "silence_id", unique=True),
    )


class HiddenNotificationChannel(Base):
    __tablename__ = "hidden_notification_channels"

    id:         Mapped[str]      = mapped_column(String, primary_key=True, default=_uuid)
    tenant_id:  Mapped[str]      = mapped_column(String, ForeignKey(FK_TENANTS, ondelete="CASCADE"), nullable=False, index=True)
    user_id:    Mapped[str]      = mapped_column(String, nullable=False, index=True)
    channel_id: Mapped[str]      = mapped_column(String, ForeignKey("notification_channels.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    __table_args__ = (
        Index("idx_hidden_channels_tenant_user", "tenant_id", "user_id"),
        Index("idx_hidden_channels_unique", "tenant_id", "user_id", "channel_id", unique=True),
    )


class HiddenJiraIntegration(Base):
    __tablename__ = "hidden_jira_integrations"

    id:             Mapped[str]      = mapped_column(String, primary_key=True, default=_uuid)
    tenant_id:      Mapped[str]      = mapped_column(String, ForeignKey(FK_TENANTS, ondelete="CASCADE"), nullable=False, index=True)
    user_id:        Mapped[str]      = mapped_column(String, nullable=False, index=True)
    integration_id: Mapped[str]      = mapped_column(String, nullable=False, index=True)
    created_at:     Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    __table_args__ = (
        Index("idx_hidden_jira_tenant_user", "tenant_id", "user_id"),
        Index("idx_hidden_jira_unique", "tenant_id", "user_id", "integration_id", unique=True),
    )
