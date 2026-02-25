"""
Rule operations for synchronizing alert rules with Mimir, including resolving organization IDs, listing existing rules, and upserting new rules based on the desired configuration.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
from typing import List, Optional
from urllib.parse import quote

import httpx

from models.access.auth_models import TokenData
from models.alerting.rules import AlertRule

logger = logging.getLogger(__name__)


def resolve_rule_org_id(service, rule_org_id: Optional[str], current_user: TokenData) -> str:
    return rule_org_id or getattr(current_user, "org_id", None) or service.config.DEFAULT_ORG_ID


async def sync_mimir_rules_for_org(service, org_id: str, rules: List[AlertRule]) -> None:
    desired_groups = service._group_enabled_rules(rules)
    base_url = service.config.MIMIR_URL.rstrip("/")
    namespace = quote(service.MIMIR_RULES_NAMESPACE, safe="")
    namespace_url = f"{base_url}{service.MIMIR_RULER_CONFIG_BASEPATH}/{namespace}"
    org_header = {"X-Scope-OrgID": org_id}

    existing_group_names: List[str] = []
    try:
        response = await service._mimir_client.get(namespace_url, headers=org_header)
        if response.status_code == 200:
            existing_group_names = service._extract_mimir_group_names(response.text)
        elif response.status_code != 404:
            logger.warning(
                "Failed to list Mimir groups for org %s (status %s); stale groups will not be pruned",
                org_id,
                response.status_code,
            )
    except httpx.HTTPError as exc:
        logger.warning("HTTP error listing Mimir groups for org %s: %s; stale groups will not be pruned", org_id, exc)

    for group_name in existing_group_names:
        if group_name in desired_groups:
            continue
        delete_url = f"{namespace_url}/{quote(group_name, safe='')}"
        delete_response = await service._mimir_client.delete(delete_url, headers=org_header)
        if delete_response.status_code not in {200, 202, 204, 404}:
            raise httpx.HTTPStatusError(
                f"Unexpected Mimir delete response: {delete_response.status_code}",
                request=delete_response.request,
                response=delete_response,
            )

    for group_name, group_rules in desired_groups.items():
        payload = service._build_ruler_group_yaml(group_name, group_rules)
        post_response = await service._mimir_client.post(
            namespace_url,
            content=payload,
            headers={**org_header, "Content-Type": "application/yaml"},
        )
        if post_response.status_code not in {200, 201, 202, 204}:
            raise httpx.HTTPStatusError(
                f"Unexpected Mimir upsert response: {post_response.status_code}",
                request=post_response.request,
                response=post_response,
            )
