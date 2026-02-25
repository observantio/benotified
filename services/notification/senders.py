"""
Senders for notification services, providing functions to send notifications to various channels such as Slack, Microsoft Teams, generic webhooks, and PagerDuty based on alert data and channel configurations. This module includes logic to validate webhook URLs, construct payloads for each channel using the payload construction utilities, and perform HTTP requests to send the notifications while handling errors and implementing retry logic for transient failures. The senders ensure that notifications are sent securely and efficiently, with proper logging of successes and failures to facilitate monitoring and troubleshooting of notification delivery.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
from typing import Any

import httpx

from . import payloads, transport
from services.common.url_utils import is_safe_http_url

logger = logging.getLogger(__name__)

PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

ALLOWED_HEADERS = {
    "Authorization",
    "Content-Type",
    "X-Custom-Header",
}

SLACK_ALLOWED_HOSTS = {"hooks.slack.com"}
TEAMS_ALLOWED_SUFFIXES = (".webhook.office.com",)


def _is_allowed_host(url: str, allowed_hosts=None, allowed_suffixes=None) -> bool:
    try:
        host = httpx.URL(url).host
        if allowed_hosts and host in allowed_hosts:
            return True
        if allowed_suffixes and host.endswith(allowed_suffixes):
            return True
        return False
    except Exception:
        return False


def _safe_headers(headers: dict[str, Any]) -> dict[str, str]:
    return {k: str(v) for k, v in headers.items() if k in ALLOWED_HEADERS}


def _serialize_alert(alert) -> dict[str, Any]:
    if hasattr(alert, "model_dump"):
        return alert.model_dump(mode="json")

    return {
        "labels": getattr(alert, "labels", {}),
        "annotations": getattr(alert, "annotations", {}),
        "startsAt": getattr(alert, "starts_at", None),
        "endsAt": getattr(alert, "ends_at", None),
        "fingerprint": getattr(alert, "fingerprint", None),
    }


async def _send_json(
    client: httpx.AsyncClient,
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> bool:
    if not is_safe_http_url(url):
        logger.warning("Blocked unsafe URL: %s", url)
        return False

    try:
        await transport.post_with_retry(client, url, json=payload, headers=headers)
        return True
    except httpx.HTTPStatusError as exc:
        logger.warning("Webhook failed [%s]: %s", exc.response.status_code, url)
        return False
    except Exception:
        logger.exception("Unexpected webhook error: %s", url)
        return False


async def send_slack(
    client: httpx.AsyncClient,
    channel_config: dict[str, Any],
    alert,
    action: str,
) -> bool:
    url = channel_config.get("webhook_url") or channel_config.get("webhookUrl")
    if not url or not _is_allowed_host(url, allowed_hosts=SLACK_ALLOWED_HOSTS):
        logger.warning("Rejected Slack webhook URL")
        return False

    payload = payloads.build_slack_payload(alert, action)
    return await _send_json(client, url, payload)


async def send_teams(
    client: httpx.AsyncClient,
    channel_config: dict[str, Any],
    alert,
    action: str,
) -> bool:
    url = channel_config.get("webhook_url") or channel_config.get("webhookUrl")
    if not url or not _is_allowed_host(url, allowed_suffixes=TEAMS_ALLOWED_SUFFIXES):
        logger.warning("Rejected Teams webhook URL")
        return False

    payload = payloads.build_teams_payload(alert, action)
    return await _send_json(client, url, payload)


async def send_webhook(
    client: httpx.AsyncClient,
    channel_config: dict[str, Any],
    alert,
    action: str,
) -> bool:
    url = (
        channel_config.get("url")
        or channel_config.get("webhook_url")
        or channel_config.get("webhookUrl")
    )
    if not url:
        return False

    payload = {
        "action": action,
        "alert": _serialize_alert(alert),
    }

    headers = _safe_headers(channel_config.get("headers", {}))
    return await _send_json(client, url, payload, headers=headers)


async def send_pagerduty(
    client: httpx.AsyncClient,
    channel_config: dict[str, Any],
    alert,
    action: str,
) -> bool:
    routing_key = (
        channel_config.get("routing_key")
        or channel_config.get("integrationKey")
    )
    if not routing_key:
        logger.warning("PagerDuty routing key missing")
        return False

    payload = payloads.build_pagerduty_payload(alert, action, routing_key)
    return await _send_json(client, PAGERDUTY_EVENTS_URL, payload)
