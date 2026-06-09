"""query_transactions tool — read-only transaction history."""

from __future__ import annotations

from langchain_core.tools import tool

from financeflow.database.models import Account, Transaction, get_session


@tool
def query_transactions_tool(account_id: str, limit: int = 10) -> str:
    """Query recent transactions for an account.

    Args:
        account_id: Account ID or account number.
        limit: Maximum number of transactions to return (default 10, max 50).

    Returns:
        Formatted transaction list or error message.
    """
    limit = min(int(limit), 50)

    session = get_session()
    try:
        acc: Account | None = None
        if str(account_id).isdigit():
            acc = session.query(Account).filter(Account.id == int(account_id)).first()
        if acc is None:
            acc = session.query(Account).filter(
                Account.account_number == str(account_id)
            ).first()

        if acc is None:
            return f"ERROR: Account '{account_id}' not found."

        txns = (
            session.query(Transaction)
            .filter(Transaction.account_id == acc.id)
            .order_by(Transaction.timestamp.desc())
            .limit(limit)
            .all()
        )

        if not txns:
            return f"No transactions found for account {account_id}."

        lines = [f"Transactions for {acc.account_number} ({acc.owner_name}):"]
        for tx in txns:
            sign = "+" if tx.tx_type == "credit" else "-"
            lines.append(
                f"  [{tx.timestamp.strftime('%Y-%m-%d')}] "
                f"{sign}${tx.amount:,.2f}  {tx.description}"
            )
        lines.append(f"  (showing {len(txns)} of available records)")
        return "\n".join(lines)
    finally:
        session.close()
