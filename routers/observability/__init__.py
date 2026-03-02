"""
Routers for observability-related endpoints, including AlertManager alerts, silences, status, receivers, alert rules, notification channels, and Jira integrations.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from .alerts import router as alertmanager_alerts_router, webhook_router as alertmanager_webhook_router
from .incidents import router as alertmanager_incidents_router
from .jira import router as alertmanager_jira_router

__all__ = [
    "alertmanager_alerts_router",
    "alertmanager_webhook_router",
    "alertmanager_incidents_router",
    "alertmanager_jira_router",
]