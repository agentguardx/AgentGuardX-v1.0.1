"""DataAgent — read/query data role.

Allowed tools: get_account, query_transactions, run_report,
               fetch_market_data, read_customer_pii
Disallowed:    transfer_funds, send_email, post_external, execute_code

Mid-privilege agent. Can access PII (high-sensitivity) but cannot
initiate irreversible financial or communication operations.
"""

from __future__ import annotations

from financeflow.agents.base import FinanceFlowAgent
from financeflow.tools import DATA_TOOLS


class DataAgent(FinanceFlowAgent):
    """Data access and query agent.

    Scope: transaction history, customer records, reporting.
    Cannot initiate financial transfers or external communications.
    """

    role = "data"
    tools = DATA_TOOLS
