"""AdminAgent — full privileged access role.

Allowed tools: ALL (get_account, query_transactions, read_customer_pii,
               transfer_funds, run_report, fetch_market_data, send_email,
               compress_data, post_external, execute_code)

Highest-privilege agent. An injection attack here can trigger:
  - Irreversible fund transfers (transfer_funds)
  - External data exfiltration (post_external)
  - Code execution (execute_code — gVisor floor required)
  - The full exfil kill chain (read_customer_pii → compress_data → post_external)

This is the primary attack surface for privilege-escalation and exfil demos.
"""

from __future__ import annotations

from financeflow.agents.base import FinanceFlowAgent
from financeflow.tools import ADMIN_TOOLS


class AdminAgent(FinanceFlowAgent):
    """Full-privilege administrative agent.

    Scope: all operations including financial transfers, external comms,
    code execution, and PII access.
    """

    role = "admin"
    tools = ADMIN_TOOLS
