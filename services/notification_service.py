"""
Service for managing notifications, providing functions to send notifications through various channels such as email, Slack, and Microsoft Teams. This module includes logic to construct notification payloads based on alert information, to handle the formatting of messages for different notification platforms, and to implement retry mechanisms for failed notification attempts. The service also includes functionality to manage notification templates and to integrate with external services for sending notifications securely and efficiently.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import httpx
import logging
import os
from typing import Optional
from datetime import datetime
import re
from email.message import EmailMessage

from models.alerting.channels import NotificationChannel, ChannelType
from models.alerting.alerts import Alert
from config import config
from services.common.http_client import create_async_client

from services.notification import payloads as notification_payloads
from services.notification import validators as notification_validators
from services.notification import transport as notification_transport
from services.notification import email_providers as notification_email
from services.notification import senders as notification_senders

logger = logging.getLogger(__name__)
NO_VALUE = "(none)"

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
                val = value.strip().lower()
                return val in ("1", "true", "yes", "on")
            return False

    def validate_channel_config(self, channel_type: str, channel_config: dict | None) -> list[str]:
        return notification_validators.validate_channel_config(channel_type, channel_config)


    async def _post_with_retry(self, url: str, json: dict | None = None, headers: dict | None = None, params: dict | None = None) -> httpx.Response:
        return await notification_transport.post_with_retry(self._client, url, json=json, headers=headers, params=params)

    async def _send_smtp_with_retry(self, message: EmailMessage, hostname: str, port: int, username: str | None = None, password: str | None = None, start_tls: bool = False, use_tls: bool = False):
        return await notification_transport.send_smtp_with_retry(
            message,
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            start_tls=start_tls,
            use_tls=use_tls,
            timeout=self.timeout,
        )

    async def send_notification(
        self,
        channel: NotificationChannel,
        alert: Alert,
        action: str = "firing"
    ) -> bool:
        if not channel.enabled:
            logger.info(f"Channel {channel.name} is disabled, skipping notification")
            return False

        try:
            async_senders = {
                ChannelType.SLACK: self._send_slack,
                ChannelType.TEAMS: self._send_teams,
                ChannelType.WEBHOOK: self._send_webhook,
                ChannelType.PAGERDUTY: self._send_pagerduty,
            }
            if channel.type == ChannelType.EMAIL:
                return await self._send_email(channel, alert, action)
            sender = async_senders.get(channel.type)
            if not sender:
                logger.error(f"Unknown channel type: {channel.type}")
                return False
            return await sender(channel, alert, action)
        except Exception as e:
            logger.exception("Error sending notification via %s: %s", channel.name, e)
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

        smtp_port_raw = config.get_secret("INCIDENT_ASSIGNMENT_SMTP_PORT") or "587"
        try:
            smtp_port = int(smtp_port_raw)
        except ValueError:
            smtp_port = 587

        smtp_user = config.get_secret("INCIDENT_ASSIGNMENT_SMTP_USERNAME")
        smtp_pass = config.get_secret("INCIDENT_ASSIGNMENT_SMTP_PASSWORD")
        smtp_from = config.get_secret("INCIDENT_ASSIGNMENT_FROM") or config.DEFAULT_ADMIN_EMAIL
        use_starttls = self._as_bool(config.get_secret("INCIDENT_ASSIGNMENT_SMTP_STARTTLS") or "true")
        use_ssl = self._as_bool(config.get_secret("INCIDENT_ASSIGNMENT_SMTP_USE_SSL") or "false")

        subject = f"[Incident Assigned] {incident_title}"
        body = (
            f"You have been assigned an incident in Be Observant.\n\n"
            f"Title: {incident_title}\n"
            f"Status: {incident_status}\n"
            f"Severity: {incident_severity}\n"
            f"Updated by: {actor}\n"
            f"Timestamp: {datetime.utcnow().isoformat()}Z\n"
        )

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = recipient_email
        msg.set_content(body)

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

    async def send_user_welcome_email(
        self,
        recipient_email: str,
        username: str,
        full_name: Optional[str] = None,
        login_url: Optional[str] = None,
    ) -> bool:
        enabled = str(config.get_secret("USER_WELCOME_EMAIL_ENABLED") or "false").strip().lower() in {"1", "true", "yes", "on"}
        if not enabled:
            return False

        smtp_host = (config.get_secret("USER_WELCOME_SMTP_HOST") or "").strip()
        if not smtp_host:
            logger.info("User welcome email skipped: USER_WELCOME_SMTP_HOST not set")
            return False

        smtp_port_raw = config.get_secret("USER_WELCOME_SMTP_PORT") or "587"
        try:
            smtp_port = int(smtp_port_raw)
        except ValueError:
            smtp_port = 587

        smtp_user = config.get_secret("USER_WELCOME_SMTP_USERNAME")
        smtp_pass = config.get_secret("USER_WELCOME_SMTP_PASSWORD")
        smtp_from = config.get_secret("USER_WELCOME_FROM") or config.DEFAULT_ADMIN_EMAIL
        use_starttls = self._as_bool(config.get_secret("USER_WELCOME_SMTP_STARTTLS") or "true")
        use_ssl = self._as_bool(config.get_secret("USER_WELCOME_SMTP_USE_SSL") or "false")

        user_label = full_name or username
        app_login_url = (login_url or config.get_secret("APP_LOGIN_URL") or "").strip()
        login_line = f"Login URL: {app_login_url}\n" if app_login_url else ""
        subject = "Welcome to Be Observant"
        body = (
            f"Hello {user_label},\n\n"
            f"Your account was created in Be Observant.\n"
            f"Username: {username}\n"
            f"{login_line}"
            "If this is your first login, follow your administrator's instructions for credentials and MFA setup.\n"
        )

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = recipient_email
        msg.set_content(body)

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
            logger.info("User welcome email sent to %s", recipient_email)
            return True
        except Exception as exc:
            logger.warning("Failed to send user welcome email to %s: %s", recipient_email, exc)
            return False

    async def _send_email(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        channel_config = channel.config or {}

        to_field = channel_config.get('to') or channel_config.get('recipient')
        if not to_field:
            logger.error("Email channel '%s' has no 'to' address configured", channel.name)
            return False
        recipients = [r.strip() for r in re.split(r"[,;\s]+", str(to_field)) if r.strip()]
        if not recipients:
            logger.error("No valid recipient addresses for channel %s", channel.name)
            return False

        subject = f"[{action.upper()}] {alert.labels.get('alertname', 'Alert')}"
        body = self._format_alert_body(alert, action)

        provider = (channel_config.get('email_provider') or channel_config.get('emailProvider') or 'smtp').strip().lower()
        smtp_from = (
            channel_config.get('smtp_from')
            or channel_config.get('smtpFrom')
            or channel_config.get('from')
            or config.DEFAULT_ADMIN_EMAIL
        )

        if provider == 'sendgrid':
            api_key = channel_config.get('sendgrid_api_key') or channel_config.get('sendgridApiKey') or channel_config.get('api_key') or channel_config.get('apiKey')
            if not api_key:
                logger.error("SendGrid API key not configured for email channel %s", channel.name)
                return False
            sent = await notification_email.send_via_sendgrid(self._client, api_key, subject, body, recipients, smtp_from)
            if sent:
                logger.info("Email notification sent via SendGrid (channel=%s)", channel.name)
                return True
            logger.error("Failed SendGrid email for channel %s", channel.name)
            return False

        if provider == 'resend':
            api_key = channel_config.get('resend_api_key') or channel_config.get('resendApiKey') or channel_config.get('api_key') or channel_config.get('apiKey')
            if not api_key:
                logger.error("Resend API key not configured for email channel %s", channel.name)
                return False
            sent = await notification_email.send_via_resend(self._client, api_key, subject, body, recipients, smtp_from)
            if sent:
                logger.info("Email notification sent via Resend (channel=%s)", channel.name)
                return True
            logger.error("Failed Resend email for channel %s", channel.name)
            return False

        if provider != 'smtp':
            logger.error("Unsupported email provider '%s' for channel %s", provider, channel.name)
            return False

        # SMTP connection params (accept multiple key names)
        smtp_host = channel_config.get('smtp_host') or channel_config.get('smtpHost')
        smtp_port = int(channel_config.get('smtp_port') or channel_config.get('smtpPort') or 0)
        smtp_user = channel_config.get('smtp_username') or channel_config.get('smtpUsername') or channel_config.get('username')
        smtp_pass = channel_config.get('smtp_password') or channel_config.get('smtpPassword') or channel_config.get('password')
        smtp_api_key = channel_config.get('smtp_api_key') or channel_config.get('smtpApiKey') or channel_config.get('api_key') or channel_config.get('apiKey')
        smtp_auth_type = (channel_config.get('smtp_auth_type') or channel_config.get('smtpAuthType') or 'password').strip().lower()
        use_starttls = self._as_bool(channel_config.get('smtp_starttls') or channel_config.get('smtpStartTLS') or channel_config.get('starttls') or False)
        use_ssl = self._as_bool(channel_config.get('smtp_use_ssl') or channel_config.get('smtpUseSSL') or False)

        if not smtp_host:
            logger.error("SMTP host not configured for email channel %s", channel.name)
            return False
        if smtp_port == 0:
            # sensible defaults
            smtp_port = 465 if use_ssl else 587 if use_starttls else 25

        if smtp_auth_type == 'none':
            smtp_user = None
            smtp_pass = None
        elif smtp_auth_type == 'api_key':
            smtp_user = smtp_user or 'apikey'
            smtp_pass = smtp_api_key
            if not smtp_pass:
                logger.error("SMTP API key not configured for email channel %s", channel.name)
                return False
        else:
            if smtp_user and not smtp_pass and smtp_api_key:
                smtp_pass = smtp_api_key

        # Build message
        msg = notification_email.build_smtp_message(subject, body, smtp_from, recipients)

        logger.info("Sending email notification to %s via %s:%s (channel=%s)", recipients, smtp_host, smtp_port, channel.name)

        sent = await notification_email.send_via_smtp(msg, smtp_host, smtp_port, smtp_user, smtp_pass, use_starttls, use_ssl, timeout=self.timeout)
        if sent:
            logger.info("Email notification sent (channel=%s)", channel.name)
            return True
        logger.error("Failed to send email for channel %s after retries", channel.name)
        return False

    async def _send_slack(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        channel_config = (channel.config or {})
        return await notification_senders.send_slack(self._client, channel_config, alert, action)

    async def _send_teams(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        channel_config = (channel.config or {})
        return await notification_senders.send_teams(self._client, channel_config, alert, action)

    async def _send_webhook(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        channel_config = (channel.config or {})
        return await notification_senders.send_webhook(self._client, channel_config, alert, action)

    async def _send_pagerduty(self, channel: NotificationChannel, alert: Alert, action: str) -> bool:
        channel_config = (channel.config or {})
        return await notification_senders.send_pagerduty(self._client, channel_config, alert, action)


    def _format_alert_body(self, alert: Alert, action: str) -> str:
        return notification_payloads.format_alert_body(alert, action)

    def _get_label(self, alert: Alert, key: str, default: str = "") -> str:
        return notification_payloads.get_label(alert, key, default)

    def _get_annotation(self, alert: Alert, key: str) -> Optional[str]:
        return notification_payloads.get_annotation(alert, key)

    def _get_alert_text(self, alert: Alert) -> str:
        return notification_payloads.get_alert_text(alert)
