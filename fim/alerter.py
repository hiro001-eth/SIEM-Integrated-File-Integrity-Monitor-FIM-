"""
alerter.py — Email & Webhook Alert Engine for SIEM-Integrated File Integrity Monitor

Sends real-time notifications when CRITICAL or RANSOMWARE_PATTERN events occur.
SOC professionals need instant alerts — waiting for the next Kibana dashboard
refresh is too slow when an attacker is actively on the system.

Supports:
  * SMTP email (Gmail, corporate Exchange, any SMTP server)
  * Webhook HTTP POST (Slack, Microsoft Teams, PagerDuty, custom)

Both channels run in background threads so monitoring is never blocked
by a slow email server or network timeout.

All configuration is via environment variables (in config.py).
If no alerting vars are set, this module does nothing — safe by default.
"""

from __future__ import annotations

import json
import logging
import smtplib
import threading
from email.mime.text import MIMEText
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

from . import config

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Alert severity filter
# ──────────────────────────────────────────────────────────────────────────────
# Only CRITICAL and RANSOMWARE events trigger external alerts.
# HIGH / MEDIUM / LOW are visible in Elasticsearch / local log only.

_ALERT_SEVERITIES = {"CRITICAL"}
_ALERT_EVENT_TYPES = {"RANSOMWARE_PATTERN"}


def should_alert(doc: dict) -> bool:
    """Determine if an event document warrants an external alert."""
    return (
        doc.get("severity") in _ALERT_SEVERITIES
        or doc.get("event.type") in _ALERT_EVENT_TYPES
    )


# ──────────────────────────────────────────────────────────────────────────────
# Email alerting (SMTP)
# ──────────────────────────────────────────────────────────────────────────────


def _build_email_body(doc: dict) -> str:
    """Build a human-readable email body from an ECS document."""
    lines = [
        "⚠️  SIEM-Integrated File Integrity Monitor — ALERT",
        "",
        f"  Event Type : {doc.get('event.type', 'UNKNOWN')}",
        f"  Severity   : {doc.get('severity', 'UNKNOWN')}",
        f"  File Path  : {doc.get('file.path', 'N/A')}",
        f"  Timestamp  : {doc.get('@timestamp', 'N/A')}",
        f"  Host       : {doc.get('host.name', 'N/A')} ({doc.get('host.ip', 'N/A')})",
        f"  Old Hash   : {doc.get('hash.old', 'N/A')}",
        f"  New Hash   : {doc.get('hash.new', 'N/A')}",
        "",
        "This alert was generated automatically by the FIM.",
        "Investigate immediately if this change was not authorized.",
    ]
    return "\n".join(lines)


def _send_email(doc: dict) -> None:
    """Send an alert email via SMTP (runs in background thread)."""
    if not config.ALERT_EMAIL_ENABLED or not config.ALERT_EMAIL_TO:
        return

    try:
        subject = (
            f"[FIM ALERT] {doc.get('severity', 'CRITICAL')}: "
            f"{doc.get('event.type', 'UNKNOWN')} — {doc.get('file.path', 'N/A')}"
        )
        body = _build_email_body(doc)

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = config.ALERT_EMAIL_FROM
        msg["To"] = config.ALERT_EMAIL_TO

        # Connect to SMTP server (single constructor, conditional STARTTLS)
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as server:
            if config.SMTP_TLS:
                server.ehlo()       # Required before STARTTLS per RFC 3207
                server.starttls()
                server.ehlo()       # Re-identify after TLS upgrade

            # Authenticate if credentials are provided
            if config.SMTP_USER and config.SMTP_PASS:
                server.login(config.SMTP_USER, config.SMTP_PASS)

            server.sendmail(
                config.ALERT_EMAIL_FROM,
                config.ALERT_EMAIL_TO.split(","),
                msg.as_string(),
            )
        logger.info("Email alert sent to %s", config.ALERT_EMAIL_TO)

    except smtplib.SMTPException as exc:
        logger.error("Failed to send email alert: %s", exc)
    except OSError as exc:
        logger.error("SMTP connection failed: %s", exc)


# ──────────────────────────────────────────────────────────────────────────────
# Webhook alerting (Slack / Teams / PagerDuty / custom)
# ──────────────────────────────────────────────────────────────────────────────


def _build_webhook_payload(doc: dict) -> dict:
    """Build a JSON payload compatible with Slack, Teams, and custom webhooks.

    Slack and Teams both accept a 'text' field for simple messages.
    """
    severity = doc.get("severity", "UNKNOWN")
    event = doc.get("event.type", "UNKNOWN")
    path = doc.get("file.path", "N/A")
    host = doc.get("host.name", "N/A")
    timestamp = doc.get("@timestamp", "N/A")

    text = (
        f"🚨 *FIM ALERT* — {severity}\n"
        f"Event: `{event}`\n"
        f"File: `{path}`\n"
        f"Host: `{host}`\n"
        f"Time: `{timestamp}`"
    )
    return {"text": text}


def _send_webhook(doc: dict) -> None:
    """Send an alert via HTTP POST to the configured webhook URL."""
    if not config.WEBHOOK_URL:
        return

    try:
        payload = json.dumps(_build_webhook_payload(doc)).encode("utf-8")
        req = Request(
            config.WEBHOOK_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=config.WEBHOOK_TIMEOUT) as resp:
            status = resp.getcode()
            if status and status < 300:
                logger.info("Webhook alert sent (HTTP %d)", status)
            else:
                logger.warning("Webhook returned HTTP %d", status)

    except URLError as exc:
        logger.error("Webhook delivery failed: %s", exc)
    except OSError as exc:
        logger.error("Webhook connection error: %s", exc)


# ──────────────────────────────────────────────────────────────────────────────
# Public API — non-blocking alert dispatch
# ──────────────────────────────────────────────────────────────────────────────


def send_alert(doc: dict) -> None:
    """Fire email and/or webhook alerts for a critical event document.

    Alerts are sent in background threads so the main monitoring loop
    is never blocked by slow networks or email servers.

    This function is safe to call for ANY event — it checks
    :func:`should_alert` internally and returns immediately if
    the event does not qualify.
    """
    if not should_alert(doc):
        return

    logger.warning(
        "🔔 Dispatching alerts for %s event on %s",
        doc.get("event.type"),
        doc.get("file.path"),
    )

    # Fire email in background thread (non-blocking)
    if config.ALERT_EMAIL_ENABLED and config.ALERT_EMAIL_TO:
        threading.Thread(
            target=_send_email, args=(doc,), daemon=True, name="alert-email"
        ).start()

    # Fire webhook in background thread (non-blocking)
    if config.WEBHOOK_URL:
        threading.Thread(
            target=_send_webhook, args=(doc,), daemon=True, name="alert-webhook"
        ).start()
