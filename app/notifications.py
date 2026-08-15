"""Notification helpers for Fortis Intelligence Hub (Slack + Email)."""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urlparse

import requests


def send_slack_notification(message: str, finding_id: str | None = None) -> bool:
    """Send a Slack notification via webhook.

    Args:
        message: Message text to send.
        finding_id: Optional finding ID for context.

    Returns:
        True if sent successfully.
    """
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("[WARN] SLACK_WEBHOOK_URL not configured, skipping Slack notification")
        return False

    # SECURITY: Validate webhook URL to prevent SSRF attacks
    allowed_domains = ["hooks.slack.com", "hooks.slack-gov.com"]
    try:
        parsed = urlparse(webhook_url)
        if parsed.hostname not in allowed_domains:
            print(f"[SECURITY] Invalid Slack webhook domain: {parsed.hostname}")
            print(f"[SECURITY] Only {', '.join(allowed_domains)} are allowed")
            return False
    except Exception as e:
        print(f"[SECURITY] Malformed webhook URL: {e}")
        return False

    try:
        payload = {
            "text": message,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": message
                    }
                }
            ]
        }

        if finding_id:
            payload["blocks"].append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Finding ID: `{finding_id}`"
                    }
                ]
            })

        response = requests.post(
            webhook_url,
            json=payload,
            timeout=5,
        )
        response.raise_for_status()
        return True
    except Exception as exc:
        print(f"[ERROR] Slack notification failed: {exc}")
        return False


def send_email_notification(subject: str, body: str, to_email: str | None = None) -> bool:
    """Send email notification via SMTP.

    Args:
        subject: Email subject.
        body: Email body (plain text).
        to_email: Recipient email (defaults to FORTIS_NOTIFY_EMAIL env var).

    Returns:
        True if sent successfully.
    """
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_use_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
    from_address = os.getenv("SMTP_FROM_ADDRESS", smtp_user)

    if not all([smtp_host, smtp_user, smtp_password]):
        print("[WARN] SMTP not configured, skipping email notification")
        return False

    recipient = to_email or os.getenv("FORTIS_NOTIFY_EMAIL")
    if not recipient:
        print("[WARN] No recipient email configured")
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = from_address
        msg["To"] = recipient
        msg["Subject"] = f"[Fortis OSINT] {subject}"
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            if smtp_use_tls:
                server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)

        return True
    except Exception as exc:
        print(f"[ERROR] Email notification failed: {exc}")
        return False


# ---------------------------------------------------------------------------
# OSINT monitor event notifiers
# ---------------------------------------------------------------------------

def notify_new_finding(
    identifier: str, monitor_type: str, finding_id: str
) -> None:
    """Notify analysts that a new OSINT finding is pending review.

    Args:
        identifier: The monitored identifier (domain, IP, username, etc.).
        monitor_type: Monitor category (e.g. domain, ip, username, email).
        finding_id: Unique finding ID.
    """
    message = (
        f":bell: *New OSINT Finding Ready for Review*\n"
        f"* Identifier: `{identifier}`\n"
        f"* Monitor: {monitor_type.upper()}\n"
        f"* Status: Pending Review\n"
        f"* Action: Review in Fortis Intelligence Hub"
    )

    email_body = f"""A new OSINT finding is pending review:

Identifier: {identifier}
Monitor Type: {monitor_type.upper()}
Finding ID: {finding_id}

Please review the finding in the Fortis Intelligence Hub and approve or dismiss it.

This is an automated notification from Fortis Intelligence Hub.
"""

    send_slack_notification(message, finding_id)
    send_email_notification(
        subject=f"New Finding for {identifier}",
        body=email_body,
    )


def notify_finding_approved(
    identifier: str, approved_by: str, finding_id: str
) -> None:
    """Notify that a finding was approved and escalated.

    Args:
        identifier: The monitored identifier.
        approved_by: Email or name of the approver.
        finding_id: Unique finding ID.
    """
    message = (
        f":white_check_mark: *OSINT Finding Approved*\n"
        f"* Identifier: `{identifier}`\n"
        f"* Approved by: {approved_by}\n"
        f"* Status: Escalated"
    )

    email_body = f"""An OSINT finding was approved and escalated:

Identifier: {identifier}
Approved By: {approved_by}
Finding ID: {finding_id}

The finding has been marked as confirmed and escalated for action.

This is an automated notification from Fortis Intelligence Hub.
"""

    send_slack_notification(message, finding_id)
    send_email_notification(
        subject=f"Finding Approved for {identifier}",
        body=email_body,
    )


def notify_finding_dismissed(
    identifier: str, dismissed_by: str, reason: str, finding_id: str
) -> None:
    """Notify that a finding was dismissed.

    Args:
        identifier: The monitored identifier.
        dismissed_by: Email or name of the person who dismissed.
        reason: Dismissal reason.
        finding_id: Unique finding ID.
    """
    message = (
        f":x: *OSINT Finding Dismissed*\n"
        f"* Identifier: `{identifier}`\n"
        f"* Dismissed by: {dismissed_by}\n"
        f"* Reason: {reason}"
    )

    email_body = f"""An OSINT finding was dismissed:

Identifier: {identifier}
Dismissed By: {dismissed_by}
Reason: {reason}
Finding ID: {finding_id}

No further action will be taken on this finding.

This is an automated notification from Fortis Intelligence Hub.
"""

    send_slack_notification(message, finding_id)
    send_email_notification(
        subject=f"Finding Dismissed for {identifier}",
        body=email_body,
    )


def notify_monitor_error(identifier: str, error_message: str) -> None:
    """Notify analysts of an OSINT monitor error.

    Args:
        identifier: The monitored identifier that triggered the error.
        error_message: Error description.
    """
    message = (
        f":warning: *OSINT Monitor Error*\n"
        f"* Identifier: `{identifier}`\n"
        f"* Error: {error_message}\n"
        f"* Action: Manual investigation may be required"
    )

    email_body = f"""An OSINT monitor encountered an error:

Identifier: {identifier}
Error: {error_message}

Manual investigation may be required for this identifier.

This is an automated notification from Fortis Intelligence Hub.
"""

    send_slack_notification(message)
    send_email_notification(
        subject=f"Monitor Error for {identifier}",
        body=email_body,
    )
