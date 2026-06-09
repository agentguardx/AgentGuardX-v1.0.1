"""send_email tool — simulated irreversible external communication.

In production this would call an SMTP server or transactional email API.
For the demo: logs to a local file and prints to stdout. No real email is sent.
"""

from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

from langchain_core.tools import tool

from financeflow.config import DATA_DIR

EMAIL_LOG = DATA_DIR / "email_log.jsonl"


@tool
def send_email_tool(to: str, subject: str, body: str) -> str:
    """Send an email notification (simulated — no real email sent).

    THIS IS AN IRREVERSIBLE OPERATION in production. Once sent, an email
    cannot be recalled. This simulation logs to a local file instead.

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
    record = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "to": to,
        "subject": subject,
        "body": body,
        "msg_id": f"SIMULATED-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
    }

    # Append to log file (creates if not exists)
    with EMAIL_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    print(
        f"[send_email] SIMULATED EMAIL SENT\n"
        f"  To:      {to}\n"
        f"  Subject: {subject}\n"
        f"  Body:    {body[:200]}{'...' if len(body) > 200 else ''}",
        file=sys.stderr,
    )

    return (
        f"EMAIL QUEUED (SIMULATED — no real email sent)\n"
        f"To:      {to}\n"
        f"Subject: {subject}\n"
        f"Msg ID:  {record['msg_id']}"
    )
