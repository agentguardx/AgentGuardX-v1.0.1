"""Financial tools: transfer_funds (irreversible) and run_report (reversible)."""

from __future__ import annotations

import json
import random
from typing import Literal

from langchain_core.tools import tool

from financeflow.database.models import Account, Transaction, get_session

# Simulated transfer log (in-memory, resets on restart — demo only)
_transfer_log: list[dict] = []


@tool
def transfer_funds_tool(
    from_account: str, to_account: str, amount: float, memo: str = ""
) -> str:
    """Transfer funds between two accounts.

    THIS IS AN IRREVERSIBLE OPERATION. Once executed, it cannot be undone.
    In a real system this would initiate an ACH/wire transfer.
    For the demo, it updates the in-memory balance and logs the transfer.

    Args:
        from_account: Source account ID or number.
        to_account: Destination account ID or number.
        amount: Dollar amount to transfer (must be positive).
        memo: Optional transfer memo.

    Returns:
        Confirmation or error message.

    OWASP: LLM06 (Excessive Agency)
    Reversibility: IRREVERSIBLE
    Risk tier: CRITICAL
    Cheap-gate threshold: $10,000
    """
    if float(amount) <= 0:
        return "ERROR: Transfer amount must be positive."

    session = get_session()
    try:
        def _find_account(aid: str) -> Account | None:
            if str(aid).isdigit():
                acc = session.query(Account).filter(Account.id == int(aid)).first()
                if acc:
                    return acc
            return session.query(Account).filter(Account.account_number == str(aid)).first()

        src = _find_account(str(from_account))
        dst = _find_account(str(to_account))

        if src is None:
            return f"ERROR: Source account '{from_account}' not found."
        if dst is None:
            return f"ERROR: Destination account '{to_account}' not found."
        if src.id == dst.id:
            return "ERROR: Cannot transfer to the same account."
        if src.balance < float(amount):
            return f"ERROR: Insufficient funds. Available: ${src.balance:,.2f}"

        # Execute the transfer (simulation — updates SQLite balance)
        src.balance = round(src.balance - float(amount), 2)
        dst.balance = round(dst.balance + float(amount), 2)

        import datetime
        for acc, tx_type, desc in [
            (src, "debit", f"Transfer to {dst.account_number}: {memo}"),
            (dst, "credit", f"Transfer from {src.account_number}: {memo}"),
        ]:
            session.add(Transaction(
                account_id=acc.id,
                amount=float(amount),
                description=desc,
                tx_type=tx_type,
                merchant="Internal Transfer",
                timestamp=datetime.datetime.utcnow(),
            ))

        session.commit()

        record = {
            "from": src.account_number,
            "to": dst.account_number,
            "amount": float(amount),
            "memo": memo,
        }
        _transfer_log.append(record)

        return (
            f"TRANSFER EXECUTED (IRREVERSIBLE)\n"
            f"From:   {src.account_number} ({src.owner_name})\n"
            f"To:     {dst.account_number} ({dst.owner_name})\n"
            f"Amount: ${float(amount):,.2f}\n"
            f"Memo:   {memo or 'N/A'}\n"
            f"New balance ({src.account_number}): ${src.balance:,.2f}"
        )
    finally:
        session.close()


# Deterministic RNG for report values (reproducible demo)
_report_rng = random.Random(99)

REPORT_TYPES = {
    "monthly_summary": "Monthly Account Summary",
    "risk_exposure": "Portfolio Risk Exposure",
    "transaction_volume": "Transaction Volume Report",
    "compliance_check": "Compliance Status Report",
}


@tool
def run_report_tool(report_type: str, account_id: str = "all") -> str:
    """Generate a financial report.

    Args:
        report_type: One of: monthly_summary, risk_exposure,
                     transaction_volume, compliance_check.
        account_id: Account to scope the report to, or 'all' for all accounts.

    Returns:
        Formatted report output.

    OWASP: LLM06
    Reversibility: reversible
    Risk tier: LOW
    """
    name = REPORT_TYPES.get(report_type, f"Custom Report ({report_type})")

    session = get_session()
    try:
        if account_id.lower() == "all":
            accounts = session.query(Account).all()
        else:
            if account_id.isdigit():
                acc = session.query(Account).filter(Account.id == int(account_id)).first()
            else:
                acc = session.query(Account).filter(
                    Account.account_number == account_id
                ).first()
            accounts = [acc] if acc else []

        if not accounts:
            return f"ERROR: No accounts found for scope '{account_id}'."

        total_balance = sum(a.balance for a in accounts)
        lines = [
            f"REPORT: {name}",
            f"{'=' * 50}",
            f"Accounts in scope: {len(accounts)}",
            f"Total balance:     ${total_balance:,.2f}",
            "",
        ]

        if report_type == "monthly_summary":
            for acc in accounts:
                tx_count = session.query(Transaction).filter(
                    Transaction.account_id == acc.id
                ).count()
                lines.append(f"  {acc.account_number}: ${acc.balance:,.2f} ({tx_count} transactions)")

        elif report_type == "risk_exposure":
            for acc in accounts:
                risk_score = round(_report_rng.uniform(0.1, 0.9), 2)
                tier = "LOW" if risk_score < 0.4 else "MEDIUM" if risk_score < 0.7 else "HIGH"
                lines.append(f"  {acc.account_number}: Risk score {risk_score} [{tier}]")

        elif report_type == "transaction_volume":
            for acc in accounts:
                vol = session.query(Transaction).filter(
                    Transaction.account_id == acc.id
                ).count()
                lines.append(f"  {acc.account_number}: {vol} transactions")

        elif report_type == "compliance_check":
            lines.append("  Status: COMPLIANT (simulated)")
            lines.append("  Last audit: 2024-12-01")
            lines.append("  Next audit: 2025-06-01")

        lines.append(f"\nGenerated at: {__import__('datetime').datetime.utcnow().isoformat()}Z")
        return "\n".join(lines)
    finally:
        session.close()
