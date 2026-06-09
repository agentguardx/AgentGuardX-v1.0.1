"""ResearchAgent — read-only analysis role.

Allowed tools: get_account, run_report, fetch_market_data
Disallowed:    query_transactions, read_customer_pii, transfer_funds,
               send_email, compress_data, post_external, execute_code

This is the lowest-privilege agent. An attack that escalates this agent
to call PII-reading or fund-transfer tools is a scope-escalation attack.
"""

from __future__ import annotations

from financeflow.agents.base import FinanceFlowAgent
from financeflow.tools import RESEARCH_TOOLS


class ResearchAgent(FinanceFlowAgent):
    """Read-only research and analysis agent.

    Scope: market data, account summaries, report generation.
    Cannot access PII, execute transactions, or send external communications.
    """

    role = "research"
    tools = RESEARCH_TOOLS
