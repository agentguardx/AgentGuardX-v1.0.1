"""get_account tool — read-only account lookup."""

from __future__ import annotations

from langchain_core.tools import tool

from financeflow.database.models import Account, get_session


@tool
def get_account_tool(account_id: str) -> str:
    """Retrieve account details for a given account ID or account number.

    Args:
        account_id: The account ID (integer) or account number string.

    Returns:
        JSON-like string with account details, or an error message.
    """
    session = get_session()
    try:
        # Try numeric ID first, then account_number string
        acc: Account | None = None
        if account_id.isdigit():
            acc = session.query(Account).filter(Account.id == int(account_id)).first()
        if acc is None:
            acc = session.query(Account).filter(
                Account.account_number == account_id
            ).first()

        if acc is None:
            return f"ERROR: Account '{account_id}' not found."

        return (
            f"Account ID: {acc.id}\n"
            f"Account Number: {acc.account_number}\n"
            f"Owner: {acc.owner_name}\n"
            f"Type: {acc.account_type}\n"
            f"Balance: ${acc.balance:,.2f}\n"
            f"Status: {'Active' if acc.is_active else 'Inactive'}"
        )
    finally:
        session.close()
