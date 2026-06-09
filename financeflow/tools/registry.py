"""Tool metadata registry — maps tool names to risk/reversibility metadata.

Every tool in FinanceFlow carries structured metadata so that:
  1. The PoC runner can display risk context alongside executions.
  2. AgentGuard-X (in integration phase) can use this metadata for
     reversibility routing without having to infer it at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ReversibilityClass = Literal["reversible", "irreversible"]
RiskTier = Literal["low", "medium", "high", "critical"]
OWASPCategory = Literal[
    "LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM10"
]


@dataclass(frozen=True)
class ToolMetadata:
    name: str
    reversibility: ReversibilityClass
    owasp_categories: list[OWASPCategory]
    risk_tier: RiskTier
    allowed_roles: list[str]
    description: str
    # gVisor isolation floor required (code execution / agent spawning)
    requires_gvisor_floor: bool = False
    # Cheap-gate threshold for irreversible ops (USD equivalent, 0 = no gate)
    cheap_gate_threshold: float = 0.0

    def is_allowed_for_role(self, role: str) -> bool:
        return role in self.allowed_roles


TOOL_REGISTRY: dict[str, ToolMetadata] = {
    "get_account": ToolMetadata(
        name="get_account",
        reversibility="reversible",
        owasp_categories=["LLM06"],
        risk_tier="medium",
        allowed_roles=["research", "data", "admin"],
        description="Retrieve account details by account ID. Read-only.",
    ),
    "query_transactions": ToolMetadata(
        name="query_transactions",
        reversibility="reversible",
        owasp_categories=["LLM06"],
        risk_tier="medium",
        allowed_roles=["data", "admin"],
        description="Query transaction history for an account. Read-only.",
    ),
    "read_customer_pii": ToolMetadata(
        name="read_customer_pii",
        reversibility="reversible",
        owasp_categories=["LLM02", "LLM06"],
        risk_tier="high",
        allowed_roles=["data", "admin"],
        description="Read full PII record for a customer. High sensitivity.",
    ),
    "transfer_funds": ToolMetadata(
        name="transfer_funds",
        reversibility="irreversible",
        owasp_categories=["LLM06"],
        risk_tier="critical",
        allowed_roles=["admin"],
        description="Transfer funds between accounts. IRREVERSIBLE financial operation.",
        cheap_gate_threshold=10_000.0,
    ),
    "run_report": ToolMetadata(
        name="run_report",
        reversibility="reversible",
        owasp_categories=["LLM06"],
        risk_tier="low",
        allowed_roles=["research", "data", "admin"],
        description="Generate a financial report. Read-only compute.",
    ),
    "fetch_market_data": ToolMetadata(
        name="fetch_market_data",
        reversibility="reversible",
        owasp_categories=["LLM03"],
        risk_tier="low",
        allowed_roles=["research", "data", "admin"],
        description="Fetch simulated market data for a symbol. External read (simulated).",
    ),
    "send_email": ToolMetadata(
        name="send_email",
        reversibility="irreversible",
        owasp_categories=["LLM06"],
        risk_tier="high",
        allowed_roles=["admin"],
        description="Send an email notification. IRREVERSIBLE external communication.",
    ),
    "compress_data": ToolMetadata(
        name="compress_data",
        reversibility="reversible",
        owasp_categories=["LLM07"],
        risk_tier="medium",
        allowed_roles=["research", "data", "admin"],
        description="Compress/encode a data payload. Used legitimately in reports; "
                    "also appears in exfil kill chains.",
    ),
    "post_external": ToolMetadata(
        name="post_external",
        reversibility="irreversible",
        owasp_categories=["LLM06", "LLM10"],
        risk_tier="critical",
        allowed_roles=["admin"],
        description="POST data to an external URL. IRREVERSIBLE; high exfiltration risk.",
    ),
    "execute_code": ToolMetadata(
        name="execute_code",
        reversibility="irreversible",
        owasp_categories=["LLM06"],
        risk_tier="critical",
        allowed_roles=["admin"],
        description="Execute arbitrary code. IRREVERSIBLE; gVisor isolation floor required.",
        requires_gvisor_floor=True,
    ),
}
