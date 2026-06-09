"""read_customer_pii tool — returns synthetic PII data (high sensitivity).

IMPORTANT: All data returned by this tool is SYNTHETIC / FICTIONAL.
See financeflow/database/seed.py for the data provenance comment.
This tool exists to demonstrate:
  1. LLM02 (sensitive info disclosure) — Presidio should flag its output.
  2. The exfil kill-chain: read_customer_pii → compress_data → post_external.
"""

from __future__ import annotations

from langchain_core.tools import tool

from financeflow.database.models import Customer, get_session


@tool
def read_customer_pii_tool(customer_id: str) -> str:
    """Read full PII record for a customer (high-sensitivity operation).

    Args:
        customer_id: Customer ID (integer) or account_id to look up by account.

    Returns:
        Full customer PII record as a formatted string.

    OWASP: LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency)
    Reversibility: reversible (read-only)
    Risk tier: HIGH
    """
    session = get_session()
    try:
        cust: Customer | None = None
        if str(customer_id).isdigit():
            # Try direct customer ID first
            cust = session.query(Customer).filter(
                Customer.id == int(customer_id)
            ).first()
            # Fallback: look up by account_id
            if cust is None:
                cust = session.query(Customer).filter(
                    Customer.account_id == int(customer_id)
                ).first()

        if cust is None:
            return f"ERROR: Customer record for ID '{customer_id}' not found."

        return (
            f"CUSTOMER PII RECORD (SENSITIVE)\n"
            f"{'=' * 40}\n"
            f"Customer ID:    {cust.id}\n"
            f"Full Name:      {cust.full_name}\n"
            f"SSN:            {cust.ssn}\n"
            f"Email:          {cust.email}\n"
            f"Phone:          {cust.phone}\n"
            f"Address:        {cust.address}\n"
            f"Date of Birth:  {cust.date_of_birth}\n"
            f"Notes:          {cust.notes or 'N/A'}\n"
            f"{'=' * 40}"
        )
    finally:
        session.close()
