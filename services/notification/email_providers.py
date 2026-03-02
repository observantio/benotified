"""
Email provider utilities for sending notifications via different email services, including SendGrid, Resend, and SMTP. This module provides functions to build email messages, validate recipient email addresses, and send emails using the respective APIs or protocols while handling errors and implementing retry logic for transient failures. The utilities ensure that email sending operations are performed securely and efficiently, with proper logging and error handling to facilitate troubleshooting and monitoring of email delivery performance.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
from email.message import EmailMessage
from email.utils import parseaddr

import httpx

from . import transport

logger = logging.getLogger(__name__)

def _is_valid_email(addr: str) -> bool:
    return "@" in parseaddr(addr)[1]

def _sanitize_recipients(recipients: list[str]) -> list[str]:
    valid = [r.strip() for r in recipients if _is_valid_email(r)]
    if not valid:
        raise ValueError("No valid recipient email addresses provided")
    return valid

def build_smtp_message(subject: str, body: str, smtp_from: str, recipients: list[str]) -> EmailMessage:
    recipients = _sanitize_recipients(recipients)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    return msg

async def send_via_sendgrid(
    client: httpx.AsyncClient,
    api_key: str,
    subject: str,
    body: str,
    recipients: list[str],
    smtp_from: str,
) -> bool:
    recipients = _sanitize_recipients(recipients)

    payload = {
        "personalizations": [{"to": [{"email": r} for r in recipients]}],
        "from": {"email": smtp_from},
        "subject": subject,
        "content": [{"type": "text/plain", "value": body}],
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        await transport.post_with_retry(
            client,
            "https://api.sendgrid.com/v3/mail/send",
            json=payload,
            headers=headers,
            retry_on_status={429, 500, 502, 503, 504},
        )
        return True
    except httpx.HTTPStatusError as e:
        logger.error("SendGrid rejected request", extra={"status": e.response.status_code})
    except httpx.HTTPError:
        logger.exception("SendGrid transport failure")
    except Exception:
        logger.exception("Unexpected SendGrid error")

    return False

async def send_via_resend(
    client: httpx.AsyncClient,
    api_key: str,
    subject: str,
    body: str,
    recipients: list[str],
    smtp_from: str,
) -> bool:
    recipients = _sanitize_recipients(recipients)

    payload = {
        "from": smtp_from,
        "to": recipients,
        "subject": subject,
        "text": body,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        await transport.post_with_retry(
            client,
            "https://api.resend.com/emails",
            json=payload,
            headers=headers,
            retry_on_status={429, 500, 502, 503, 504},
        )
        return True
    except httpx.HTTPStatusError as e:
        logger.error("Resend rejected request", extra={"status": e.response.status_code})
    except httpx.HTTPError:
        logger.exception("Resend transport failure")
    except Exception:
        logger.exception("Unexpected Resend error")

    return False

async def send_via_smtp(
    message: EmailMessage,
    hostname: str,
    port: int,
    username: str | None,
    password: str | None,
    start_tls: bool,
    use_tls: bool,
) -> bool:
    if (username or password) and not (start_tls or use_tls):
        raise ValueError("SMTP authentication without TLS is insecure")

    try:
        await transport.send_smtp_with_retry(
            message,
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            start_tls=start_tls,
            use_tls=use_tls,
        )
        return True
    except Exception:
        logger.exception("SMTP delivery failed")
        return False