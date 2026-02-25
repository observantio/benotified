"""
Storage service for managing alert incidents, providing functions to synchronize incidents from alerts, list incidents with filtering options, retrieve specific incidents with access control, and update incident details. This module interacts with the database to persist incident information and ensures that users can only access or modify incidents they have permission to view or edit based on their user ID and group memberships. The service also includes functionality to filter alerts based on user permissions when associating them with incidents, ensuring that users only see relevant information in the context of their access rights.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""


from typing import Any, Dict, List, Optional

from models.alerting.incidents import AlertIncident, AlertIncidentUpdateRequest


class IncidentStorageService:
    def __init__(self, backend):
        self._backend = backend

    def sync_incidents_from_alerts(self, tenant_id: str, alerts: List[Dict[str, Any]], resolve_missing: bool = True) -> None:
        self._backend.sync_incidents_from_alerts(tenant_id, alerts, resolve_missing)

    def list_incidents(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]] = None,
        status: Optional[str] = None,
        visibility: Optional[str] = None,
        group_id: Optional[str] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[AlertIncident]:
        return self._backend.list_incidents(
            tenant_id, user_id,
            group_ids=group_ids, status=status, visibility=visibility,
            group_id=group_id, limit=limit, offset=offset,
        )

    def get_incident_for_user(
        self,
        incident_id: str,
        tenant_id: str,
        user_id: Optional[str] = None,
        group_ids: Optional[List[str]] = None,
        require_write: bool = False,
    ) -> Optional[AlertIncident]:
        return self._backend.get_incident_for_user(
            incident_id, tenant_id,
            user_id=user_id, group_ids=group_ids, require_write=require_write,
        )

    def update_incident(
        self,
        incident_id: str,
        tenant_id: str,
        user_id: str,
        payload: AlertIncidentUpdateRequest,
    ) -> Optional[AlertIncident]:
        return self._backend.update_incident(incident_id, tenant_id, user_id, payload)

    def filter_alerts_for_user(
        self,
        tenant_id: str,
        user_id: str,
        group_ids: Optional[List[str]],
        alerts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        return self._backend.filter_alerts_for_user(tenant_id, user_id, group_ids, alerts)
