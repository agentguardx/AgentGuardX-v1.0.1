"""send_email tool — external communication.

By default this SIMULATES sending (logs locally). If SMTP credentials are present
in the environment (SMTP_HOST / SMTP_USER / SMTP_PASSWORD), it sends a REAL email.
This is used in the demo to show that, without AgentGuard-X, an agent can actually
exfiltrate (synthetic) data over email. All data in this system is synthetic.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import smtplib
import sys
from email.message import EmailMessage
from pathlib import Path

from langchain_core.tools import tool

from financeflow.config import DATA_DIR

EMAIL_LOG = DATA_DIR / "email_log.jsonl"


def _smtp_config() -> dict | None:
    """Return SMTP config from the environment, or None if not configured."""
    host = os.getenv("SMTP_HOST", "").strip()
    user = os.getenv("SMTP_USER", "").strip()
    pwd = os.getenv("SMTP_PASSWORD", "").strip()
    if not (host and user and pwd):
        return None
    return {
        "host": host,
        "port": int(os.getenv("SMTP_PORT", "587")),
        "user": user,
        "password": pwd,
        "from": os.getenv("SMTP_FROM", user).strip() or user,
        "ssl": os.getenv("SMTP_SSL", "false").lower() in ("1", "true", "yes"),
        "starttls": os.getenv("SMTP_STARTTLS", "true").lower() in ("1", "true", "yes"),
        "timeout": float(os.getenv("SMTP_TIMEOUT", "20")),
    }


def _looks_html(s: str) -> bool:
    return bool(re.search(r"<\s*(html|body|table|tr|td|div|p|br|pre|ul|li|h[1-6])\b",
                          s or "", re.I))


def _send_real_email(cfg: dict, to: str, subject: str, body: str) -> None:
    """Send a real email via SMTP. Raises on failure."""
    msg = EmailMessage()
    msg["From"] = cfg["from"]
    msg["To"] = to
    msg["Subject"] = subject or "(no subject)"
    body = body or ""
    if _looks_html(body):
        # Plain-text fallback (tags stripped) + the HTML so clients render it.
        msg.set_content(re.sub(r"<[^>]+>", "", body).strip() or "(see HTML version)")
        msg.add_alternative(body, subtype="html")
    else:
        msg.set_content(body)

    if cfg["ssl"]:
        server = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=cfg["timeout"])
    else:
        server = smtplib.SMTP(cfg["host"], cfg["port"], timeout=cfg["timeout"])
    try:
        server.ehlo()
        if not cfg["ssl"] and cfg["starttls"]:
            server.starttls()
            server.ehlo()
        server.login(cfg["user"], cfg["password"])
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:
            pass


@tool
def send_email_tool(to: str, subject: str, body: str) -> str:
    """Send an email notification.

    Sends a REAL email when SMTP credentials are configured in the environment;
    otherwise it is simulated and only logged locally.

    THIS IS AN IRREVERSIBLE OPERATION. Once sent, an email cannot be recalled.

    Args:
        to: Recipient email address.
        subject: Email subject line.
        body: Email body text.

    Returns:
        Confirmation message with message ID.

    OWASP: LLM06 (Excessive Agency)
    Reversibility: IRREVERSIBLE
    Risk tier: HIGH
    """
    ts = datetime.datetime.utcnow()
    msg_id = ts.strftime("%Y%m%d%H%M%S%f")
    subject = (subject or "").strip() or "FinanceFlow data export"
    cfg = _smtp_config()

    delivery = "simulated"
    error = None
    if cfg:
        try:
            _send_real_email(cfg, to, subject, body)
            delivery = "real"
        except Exception as exc:  # SMTP/auth/network error → fall back to log
            delivery = "error"
            error = str(exc)

    record = {
        "timestamp": ts.isoformat() + "Z",
        "to": to,
        "subject": subject,
        "body": body,
        "delivery": delivery,
        "error": error,
        "msg_id": f"{'SENT' if delivery == 'real' else 'SIMULATED'}-{msg_id}",
    }
    with EMAIL_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    print(
        f"[send_email] delivery={delivery} to={to} subject={subject!r}"
        + (f" error={error}" if error else ""),
        file=sys.stderr,
    )

    if delivery == "real":
        return (
            f"EMAIL SENT (REAL — delivered via SMTP)\n"
            f"From:    {cfg['from']}\n"
            f"To:      {to}\n"
            f"Subject: {subject}\n"
            f"Msg ID:  {record['msg_id']}"
        )
    if delivery == "error":
        return (
            f"EMAIL SEND FAILED via SMTP: {error}\n"
            f"To:      {to}\n"
            f"Subject: {subject}\n"
            f"(logged locally; no real email delivered)"
        )
    return (
        f"EMAIL QUEUED (SIMULATED — no SMTP configured, no real email sent)\n"
        f"To:      {to}\n"
        f"Subject: {subject}\n"
        f"Msg ID:  {record['msg_id']}"
    )
