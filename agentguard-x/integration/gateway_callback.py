"""AgentGuard-X gateway callback — thin integration attachment point.

Injected into FinanceFlow agents via extra_callbacks without modifying any
FinanceFlow source file. Calls the AgentGuard-X gateway HTTP API for
pre- and post-execution enforcement.

Dependencies: httpx + langchain-core (both already in financeflow/requirements.txt).
No heavy AgentGuard-X packages (sentence-transformers, presidio, etc.) are
loaded inside the FinanceFlow container.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any, Optional

import httpx
from langchain_core.callbacks import BaseCallbackHandler

logger = logging.getLogger(__name__)

_GATEWAY_TIMEOUT = 5.0
_POSTHOOK_TIMEOUT = 3.0

# Mirrors agentguard.registry.agent_registry._populate_defaults exactly.
_ROLE_TOOLS: dict[str, list[str]] = {
    "research": [
        "get_account_tool",
        "run_report_tool",
        "fetch_market_data_tool",
    ],
    "data": [
        "get_account_tool",
        "query_transactions_tool",
        "run_report_tool",
        "fetch_market_data_tool",
        "read_customer_pii_tool",
    ],
    "admin": [
        "get_account_tool",
        "query_transactions_tool",
        "read_customer_pii_tool",
        "transfer_funds_tool",
        "run_report_tool",
        "fetch_market_data_tool",
        "send_email_tool",
        "compress_data_tool",
        "post_external_tool",
        "execute_code_tool",
    ],
}

# Mirrors agentguard.gateway.hooks._get_reversibility exactly.
_REVERSIBLE_TOOLS: frozenset[str] = frozenset({
    "get_account_tool",
    "query_transactions_tool",
    "read_customer_pii_tool",
    "run_report_tool",
    "fetch_market_data_tool",
    "compress_data_tool",
})


def declared_tools_for_role(role: str) -> list[str]:
    return _ROLE_TOOLS.get(role, [])


def reversibility(tool_name: str) -> str:
    return "reversible" if tool_name in _REVERSIBLE_TOOLS else "irreversible"


class AgentGuardGatewayCallback(BaseCallbackHandler):
    """Thin LangChain callback handler — enforces via gateway HTTP API.

    Pre-execution  (on_tool_start): POST /check
                                    403 + enforcement=on  → raise PermissionError
                                    unreachable + enforcement=on → raise PermissionError (fail-closed)

    Post-execution (on_tool_end):   POST /v1/posthook/scan
                                    quarantined + enforcement=on → raise ValueError
                                    unreachable → logged, never raises (non-fatal)
    """

    def __init__(
        self,
        agent_id: str,
        agent_role: str,
        gateway_url: str,
        enforcement: bool = True,
        session_id: Optional[str] = None,
    ) -> None:
        super().__init__()
        self._agent_id = agent_id
        self._agent_role = agent_role
        self._gateway_url = gateway_url.rstrip("/")
        self._enforcement = enforcement
        self._session_id = session_id or str(uuid.uuid4())
        self._call_seq: list[str] = []
        self._declared_tools = declared_tools_for_role(agent_role)

    @property
    def enforcement(self) -> bool:
        return self._enforcement

    # ── Pre-execution ─────────────────────────────────────────────────────────

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", "unknown")
        self._call_seq.append(tool_name)

        payload = {
            "session_id": self._session_id,
            "agent_id": self._agent_id,
            "agent_role": self._agent_role,
            "tool_name": tool_name,
            "tool_input": {"input": input_str},
            "raw_payload": (
                f"agent={self._agent_id} role={self._agent_role} "
                f"tool={tool_name} input={input_str} "
                f"history={' '.join(self._call_seq[-10:])}"
            ),
            "declared_tools": self._declared_tools,
            "reversibility": reversibility(tool_name),
        }

        try:
            resp = httpx.post(
                f"{self._gateway_url}/check",
                json=payload,
                timeout=_GATEWAY_TIMEOUT,
            )
        except Exception as exc:
            logger.error(
                "agentguard.gateway_unreachable tool=%s enforcement=%s error=%s",
                tool_name, self._enforcement, exc,
            )
            if self._enforcement:
                raise PermissionError(
                    f"[AgentGuard-X] BLOCKED (gateway unreachable, fail-closed): {exc}"
                ) from exc
            return

        if resp.status_code == 403:
            body = resp.json()
            logger.warning(
                "agentguard.block tool=%s verdict=%s r=%s enforcement=%s",
                tool_name,
                body.get("verdict"),
                body.get("r"),
                self._enforcement,
            )
            if self._enforcement:
                raise PermissionError(
                    f"[AgentGuard-X] BLOCKED: {body.get('reason', 'enforcement')} "
                    f"(verdict={body.get('verdict', '?')}, R={body.get('r', '?')})"
                )
        else:
            logger.debug(
                "agentguard.allow tool=%s verdict=%s r=%s",
                tool_name,
                resp.json().get("verdict") if resp.status_code == 200 else "?",
                resp.json().get("r") if resp.status_code == 200 else "?",
            )

    # ── Post-execution ────────────────────────────────────────────────────────

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        tool_name = self._call_seq[-1] if self._call_seq else "unknown"

        try:
            resp = httpx.post(
                f"{self._gateway_url}/v1/posthook/scan",
                json={
                    "output": str(output),
                    "tool_name": tool_name,
                    "agent_id": self._agent_id,
                    "session_id": self._session_id,
                },
                timeout=_POSTHOOK_TIMEOUT,
            )
        except Exception as exc:
            # Posthook is best-effort — never raise on unreachable
            logger.debug("agentguard.posthook_unreachable tool=%s error=%s", tool_name, exc)
            return

        if resp.status_code != 200:
            return

        body = resp.json()
        if not body.get("clean"):
            logger.warning(
                "agentguard.posthook_findings tool=%s findings=%s enforcement=%s",
                tool_name,
                body.get("findings"),
                self._enforcement,
            )
            if self._enforcement and body.get("quarantined"):
                raise ValueError(
                    f"[AgentGuard-X] QUARANTINED tool output from '{tool_name}': "
                    f"{body.get('sanitized_output', 'output blocked')}"
                )
