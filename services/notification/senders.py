"""
Senders for notification services, providing functions to send notifications to various channels such as Slack, Microsoft Teams, generic webhooks, and PagerDuty based on alert data and channel configurations. This module includes logic to validate webhook URLs, construct payloads for each channel using the payload construction utilities, and perform HTTP requests to send the notifications while handling errors and implementing retry logic for transient failures. The senders ensure that notifications are sent securely and efficiently, with proper logging of successes and failures to facilitate monitoring and troubleshooting of notification delivery.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
from collections.abc import Mapping
import httpx
from models.alerting.alerts import Alert
from . import payloads, transport
from custom_types.json import JSONDict, JSONValue
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


def _is_allowed_host(
    url: str,
    allowed_hosts: set[str] | None = None,
    allowed_suffixes: tuple[str, ...] | None = None,
) -> bool:
    try:
        host = httpx.URL(url).host
        if allowed_hosts and host in allowed_hosts:
            return True
        if allowed_suffixes and host.endswith(allowed_suffixes):
            return True
        return False
    except (TypeError, ValueError):
        return False


def _safe_headers(headers: Mapping[str, object]) -> dict[str, str]:
    return {k: str(v) for k, v in headers.items() if k in ALLOWED_HEADERS}


def _string_value(value: object) -> str:
    return value if isinstance(value, str) else ""


def _serialize_alert(alert: object) -> JSONDict:
    if isinstance(alert, Alert):
        return {
            "labels": dict(alert.labels),
            "annotations": dict(alert.annotations),
            "startsAt": alert.starts_at,
            "endsAt": alert.ends_at,
            "generatorURL": alert.generator_url,
            "fingerprint": alert.fingerprint,
        }

    return {
        "labels": getattr(alert, "labels", {}),
        "annotations": getattr(alert, "annotations", {}),
        "startsAt": getattr(alert, "starts_at", None),
        "endsAt": getattr(alert, "ends_at", None),
        "fingerprint": getattr(alert, "fingerprint", None),
    }


def _coerce_alert(alert: object) -> Alert:
    if isinstance(alert, Alert):
        return alert
    return Alert.model_validate(_serialize_alert(alert))


async def _send_json(
    client: httpx.AsyncClient,
    url: str,
    payload: Mapping[str, JSONValue],
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
    except httpx.HTTPError:
        logger.exception("Unexpected webhook error: %s", url)
        return False


async def send_slack(
    client: httpx.AsyncClient,
    channel_config: JSONDict,
    alert: object,
    action: str,
) -> bool:
    url = _string_value(channel_config.get("webhook_url") or channel_config.get("webhookUrl"))
    if not url or not _is_allowed_host(url, allowed_hosts=SLACK_ALLOWED_HOSTS):
        logger.warning("Rejected Slack webhook URL")
        return False

    payload = payloads.build_slack_payload(_coerce_alert(alert), action)
    return await _send_json(client, url, payload)


async def send_teams(
    client: httpx.AsyncClient,
    channel_config: JSONDict,
    alert: object,
    action: str,
) -> bool:
    url = _string_value(channel_config.get("webhook_url") or channel_config.get("webhookUrl"))
    if not url or not _is_allowed_host(url, allowed_suffixes=TEAMS_ALLOWED_SUFFIXES):
        logger.warning("Rejected Teams webhook URL")
        return False

    payload = payloads.build_teams_payload(_coerce_alert(alert), action)
    return await _send_json(client, url, payload)


async def send_webhook(
    client: httpx.AsyncClient,
    channel_config: JSONDict,
    alert: object,
    action: str,
) -> bool:
    url = _string_value((
        channel_config.get("url")
        or channel_config.get("webhook_url")
        or channel_config.get("webhookUrl")
    ))
    if not url:
        return False

    payload: JSONDict = {
        "action": action,
        "alert": _serialize_alert(alert),
    }

    raw_headers = channel_config.get("headers")
    headers = _safe_headers(raw_headers if isinstance(raw_headers, dict) else {})
    return await _send_json(client, url, payload, headers=headers)


async def send_pagerduty(
    client: httpx.AsyncClient,
    channel_config: JSONDict,
    alert: object,
    action: str,
) -> bool:
    routing_key = _string_value((
        channel_config.get("routing_key")
        or channel_config.get("integrationKey")
    ))
    if not routing_key:
        logger.warning("PagerDuty routing key missing")
        return False

    payload = payloads.build_pagerduty_payload(_coerce_alert(alert), action, routing_key)
    return await _send_json(client, PAGERDUTY_EVENTS_URL, payload)
