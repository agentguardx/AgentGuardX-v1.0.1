"""Agent registry — stores registered agents and their declared tool envelopes.

Intent gate design (§10):
  - Stateless set-membership test: is this tool in the agent's declared envelope?
  - Under-declared envelope fails CLOSED (over-block — annoying, safe).
  - Over-declared envelope fails OPEN (relies on Stages 2–5 for soft scoring).
  - Session history NEVER leaks into this gate — that lives in Stage 5 + OPA sequences.

The registry is populated at startup from config / OPA bundle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentRecord:
    agent_id: str
    role: str
    allowed_tools: list[str]
    isolation_floor: str = "docker"  # docker | gvisor
    description: str = ""
    metadata: dict = field(default_factory=dict)


class AgentRegistry:
    """In-memory agent registry. Source of truth for S1 identity checks and intent gate."""

    def __init__(self) -> None:
        self._agents: dict[str, AgentRecord] = {}

    def register(self, record: AgentRecord) -> None:
        self._agents[record.agent_id] = record

    def get(self, agent_id: str) -> Optional[AgentRecord]:
        return self._agents.get(agent_id)

    def all(self) -> list[AgentRecord]:
        return list(self._agents.values())


# ── Singleton + default FinanceFlow agent registrations ──────────────────────

_registry: Optional[AgentRegistry] = None


def get_agent_registry() -> AgentRegistry:
    global _registry
    if _registry is None:
        _registry = AgentRegistry()
        _populate_defaults(_registry)
    return _registry


def _populate_defaults(registry: AgentRegistry) -> None:
    """Register FinanceFlow agents — matches their declared tool envelopes exactly."""
    registry.register(AgentRecord(
        agent_id="financeflow-research",
        role="research",
        allowed_tools=["get_account_tool", "run_report_tool", "fetch_market_data_tool"],
        isolation_floor="docker",
        description="FinanceFlow read-only research agent",
    ))
    registry.register(AgentRecord(
        agent_id="financeflow-data",
        role="data",
        allowed_tools=[
            "get_account_tool", "query_transactions_tool", "run_report_tool",
            "fetch_market_data_tool", "read_customer_pii_tool",
        ],
        isolation_floor="docker",
        description="FinanceFlow data access agent",
    ))
    registry.register(AgentRecord(
        agent_id="financeflow-admin",
        role="admin",
        allowed_tools=[
            "get_account_tool", "query_transactions_tool", "read_customer_pii_tool",
            "transfer_funds_tool", "run_report_tool", "fetch_market_data_tool",
            "send_email_tool", "compress_data_tool", "post_external_tool",
            "execute_code_tool",
        ],
        isolation_floor="gvisor",  # admin can execute code → gVisor floor
        description="FinanceFlow full-privilege admin agent",
    ))
