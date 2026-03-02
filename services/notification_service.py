"""
Service for managing notifications, providing functions to send notifications through various channels such as email, Slack, and Microsoft Teams.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
import re
from datetime import datetime
from email.message import EmailMessage

import httpx

from config import config
from models.alerting.alerts import Alert
from models.alerting.channels import ChannelType, NotificationChannel
from services.common.http_client import create_async_client
from services.notification import email_providers as notification_email
from services.notification import payloads as notification_payloads
from services.notification import senders as notification_senders
from services.notification import transport as notification_transport
from services.notification import validators as notification_validators

logger = logging.getLogger(__name__)

class NotificationService:

    def __init__(self):
        self.timeout = config.DEFAULT_TIMEOUT
        self._client = create_async_client(self.timeout)

    @staticmethod
    def _as_bool(value) -> bool:
        try:
            return notification_validators._as_bool(value)
        except AttributeError:
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return value != 0
            if isinstance(value, str):
                return value.strip().lower() in ("1", "true", "yes", "on")
            return False

    def validate_channel_config(self, channel_type: str, channel_config: dict | None) -> list[str]:
        return notification_validators.validate_channel_config(channel_type, channel_config)

    async def _post_with_retry(
        self,
        url: str,
        json: dict | None = None,
        headers: dict | None = None,
        params: dict | None = None,
    ) -> httpx.Response:
        return await notification_transport.post_with_retry(self._client, url, json=json, headers=headers, params=params)

    async def _send_smtp_with_retry(
        self,
        message: EmailMessage,
        hostname: str,
        port: int,
        username: str | None = None,
        password: str | None = None,
        start_tls: bool = False,
        use_tls: bool = False,
    ):
        return await notification_transport.send_smtp_with_retry(
            message,
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            start_tls=start_tls,
            use_tls=use_tls,
        )

    async def send_notification(self, channel: NotificationChannel, alert: Alert, action: str = "firing") -> bool:
        if not channel.enabled:
            logger.info("Channel %s is disabled, skipping notification", channel.name)
            return False
        try:
            if channel.type == ChannelType.EMAIL:
                return await self._send_email(channel, alert, action)
            senders = {
                ChannelType.SLACK:     self._send_slack,
                ChannelType.TEAMS:     self._send_teams,
                ChannelType.WEBHOOK:   self._send_webhook,
                ChannelType.PAGERDUTY: self._send_pagerduty,
            }
            sender = senders.get(channel.type)
            if not sender:
                logger.error("Unknown channel type: %s", channel.type)
                return False
            return await sender(channel, alert, action)
        except Exception as exc:
            logger.exception("Error sending notification via %s: %s", channel.name, exc)
            return False

    async def send_incident_assignment_email(
        self,
        recipient_email: str,
        incident_title: str,
        incident_status: str,
        incident_severity: str,
        actor: str,
    ) -> bool:
        enabled = str(config.get_secret("INCIDENT_ASSIGNMENT_EMAIL_ENABLED") or "false").strip().lower() in {"1", "true", "yes", "on"}
        if not enabled:
            return False
        smtp_host = (config.get_secret("INCIDENT_ASSIGNMENT_SMTP_HOST") or "").strip()
        if not smtp_host:
            logger.info("Incident assignment email skipped: INCIDENT_ASSIGNMENT_SMTP_HOST not set")
            return False
        try:
            smtp_port = int(config.get_secret("INCIDENT_ASSIGNMENT_SMTP_PORT") or "587")
        except ValueError:
            smtp_port = 587
        smtp_user = config.get_secret("INCIDENT_ASSIGNMENT_SMTP_USERNAME")
        smtp_pass = config.get_secret("INCIDENT_ASSIGNMENT_SMTP_PASSWORD")
        smtp_from = config.get_secret("INCIDENT_ASSIGNMENT_FROM") or config.DEFAULT_ADMIN_EMAIL
        use_starttls = self._as_bool(config.get_secret("INCIDENT_ASSIGNMENT_SMTP_STARTTLS") or "true")
        use_ssl = self._as_bool(config.get_secret("INCIDENT_ASSIGNMENT_SMTP_USE_SSL") or "false")
        msg = EmailMessage()
        msg["Subject"] = f"[Incident Assigned] {incident_title}"
        msg["From"] = smtp_from
        msg["To"] = recipient_email
        msg.set_content(
            f"You have been assigned an incident in Be Observant.\n\n"
            f"Title: {incident_title}\n"
            f"Status: {incident_status}\n"
            f"Severity: {incident_severity}\n"
            f"Updated by: {actor}\n"
            f"Timestamp: {datetime.utcnow().isoformat()}Z\n"
        )
        try:
            await self._send_smtp_with_retry(
                message=msg,
                hostname=smtp_host,
                port=smtp_port,
                username=smtp_user,
                password=smtp_pass,
                start_tls=use_starttls,
                use_tls=use_ssl,
            )
            logger.info("Incident assignment email sent to %s", recipient_email)
            return True
        except Exception as exc:
            logger.warning("Failed to send incident assignment email to %s: %s", recipient_email, exc)
            return False

    async def _send_email(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        cfg = channel.config or {}
        to_field = cfg.get("to") or cfg.get("recipient")
        if not to_field:
            logger.error("Email channel '%s' has no 'to' address configured", channel.name)
            return False
        recipients = [r.strip() for r in re.split(r"[,;\s]+", str(to_field)) if r.strip()]
        if not recipients:
            logger.error("No valid recipient addresses for channel %s", channel.name)
            return False
        subject = f"[{action.upper()}] {alert.labels.get('alertname', 'Alert')}"
        body = notification_payloads.format_alert_body(alert, action)
        provider = (cfg.get("email_provider") or cfg.get("emailProvider") or "smtp").strip().lower()
        smtp_from = cfg.get("smtp_from") or cfg.get("smtpFrom") or cfg.get("from") or config.DEFAULT_ADMIN_EMAIL

        if provider == "sendgrid":
            api_key = cfg.get("sendgrid_api_key") or cfg.get("sendgridApiKey") or cfg.get("api_key") or cfg.get("apiKey")
            if not api_key:
                logger.error("SendGrid API key not configured for email channel %s", channel.name)
                return False
            sent = await notification_email.send_via_sendgrid(self._client, api_key, subject, body, recipients, smtp_from)
            if sent:
                logger.info("Email notification sent via SendGrid (channel=%s)", channel.name)
            else:
                logger.error("Failed SendGrid email for channel %s", channel.name)
            return sent

        if provider == "resend":
            api_key = cfg.get("resend_api_key") or cfg.get("resendApiKey") or cfg.get("api_key") or cfg.get("apiKey")
            if not api_key:
                logger.error("Resend API key not configured for email channel %s", channel.name)
                return False
            sent = await notification_email.send_via_resend(self._client, api_key, subject, body, recipients, smtp_from)
            if sent:
                logger.info("Email notification sent via Resend (channel=%s)", channel.name)
            else:
                logger.error("Failed Resend email for channel %s", channel.name)
            return sent

        if provider != "smtp":
            logger.error("Unsupported email provider '%s' for channel %s", provider, channel.name)
            return False

        smtp_host = cfg.get("smtp_host") or cfg.get("smtpHost")
        smtp_port = int(cfg.get("smtp_port") or cfg.get("smtpPort") or 0)
        smtp_user = cfg.get("smtp_username") or cfg.get("smtpUsername") or cfg.get("username")
        smtp_pass = cfg.get("smtp_password") or cfg.get("smtpPassword") or cfg.get("password")
        smtp_api_key = cfg.get("smtp_api_key") or cfg.get("smtpApiKey") or cfg.get("api_key") or cfg.get("apiKey")
        smtp_auth_type = (cfg.get("smtp_auth_type") or cfg.get("smtpAuthType") or "password").strip().lower()
        use_starttls = self._as_bool(cfg.get("smtp_starttls") or cfg.get("smtpStartTLS") or cfg.get("starttls") or False)
        use_ssl = self._as_bool(cfg.get("smtp_use_ssl") or cfg.get("smtpUseSSL") or False)

        if not smtp_host:
            logger.error("SMTP host not configured for email channel %s", channel.name)
            return False
        if smtp_port == 0:
            smtp_port = 465 if use_ssl else 587 if use_starttls else 25

        if smtp_auth_type == "none":
            smtp_user = None
            smtp_pass = None
        elif smtp_auth_type == "api_key":
            smtp_user = smtp_user or "apikey"
            smtp_pass = smtp_api_key
            if not smtp_pass:
                logger.error("SMTP API key not configured for email channel %s", channel.name)
                return False
        elif smtp_user and not smtp_pass and smtp_api_key:
            smtp_pass = smtp_api_key

        msg = notification_email.build_smtp_message(subject, body, smtp_from, recipients)
        logger.info("Sending email to %s via %s:%s (channel=%s)", recipients, smtp_host, smtp_port, channel.name)
        sent = await notification_email.send_via_smtp(msg, smtp_host, smtp_port, smtp_user, smtp_pass, use_starttls, use_ssl)
        if sent:
            logger.info("Email notification sent (channel=%s)", channel.name)
        else:
            logger.error("Failed to send email for channel %s after retries", channel.name)
        return sent

    async def _send_slack(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        return await notification_senders.send_slack(self._client, channel.config or {}, alert, action)

    async def _send_teams(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        return await notification_senders.send_teams(self._client, channel.config or {}, alert, action)

    async def _send_webhook(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        return await notification_senders.send_webhook(self._client, channel.config or {}, alert, action)

    async def _send_pagerduty(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        return await notification_senders.send_pagerduty(self._client, channel.config or {}, alert, action)