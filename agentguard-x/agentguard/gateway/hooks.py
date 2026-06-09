"""LangChain callback handler — cognitive gateway hook (§12).

This is the zero-client-modification attachment point.
FinanceFlow agents know nothing about this class.
It attaches as a LangChain BaseCallbackHandler and intercepts:

  PRE-EXECUTION (on_tool_start):
    1. Stateless intent/envelope check
    2. Build StageInput and invoke triage pipeline
    3. Enforce result: block, hold, sandbox, or allow
    4. Sequence analyzer: rolling per-session call buffer for kill-chain detection

  POST-EXECUTION (on_tool_end):
    - Presidio PII scan
    - Credential/secret scan (regex + entropy)
    - Indirect injection detection
    - Quarantine if anything found

NOTE: When enforcement toggle is OFF, hooks REGISTER but pass through.
Observability STAYS ON — attacks are logged and visible in Grafana.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from typing import Any, Optional, Union

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult

from agentguard.gateway.intent_gate import IntentGate
from agentguard.gateway.post_hook import PostHookProcessor
from agentguard.registry.agent_registry import get_agent_registry
from agentguard.scoring.model import RouteDecision, TriageVerdict

logger = logging.getLogger(__name__)


class AgentGuardCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that attaches AgentGuard-X to any agent.

    Usage (integration phase — zero FinanceFlow source modification):
        from agentguard.gateway.hooks import AgentGuardCallbackHandler
        handler = AgentGuardCallbackHandler(agent_id="financeflow-admin")
        agent = AdminAgent(extra_callbacks=[handler])
    """

    def __init__(
        self,
        agent_id: str,
        agent_role: str,
        triage_pipeline=None,
        post_processor: Optional[PostHookProcessor] = None,
        enforcement: bool = True,
    ) -> None:
        super().__init__()
        self._agent_id = agent_id
        self._agent_role = agent_role
        self._pipeline = triage_pipeline
        self._post = post_processor or PostHookProcessor()
        self._intent = IntentGate()
        self._registry = get_agent_registry()
        self._enforcement = enforcement
        self._session_id = str(uuid.uuid4())
        self._call_sequence: list[str] = []  # rolling buffer for sequence analyzer

    @property
    def enforcement(self) -> bool:
        return self._enforcement

    @enforcement.setter
    def enforcement(self, value: bool) -> None:
        self._enforcement = value

    # ── Pre-execution hook ────────────────────────────────────────────────────
    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", "unknown")
        self._call_sequence.append(tool_name)

        logger.info(
            "agentguard.pre_hook",
            extra={
                "agent_id": self._agent_id,
                "tool": tool_name,
                "enforcement": self._enforcement,
                "session_id": self._session_id,
            },
        )

        # ── Intent gate (stateless) ───────────────────────────────────────────
        agent_record = self._registry.get(self._agent_id)
        declared_tools = agent_record.allowed_tools if agent_record else []
        intent_decision = self._intent.check(self._agent_role, tool_name, declared_tools)

        if not intent_decision.allowed and self._enforcement:
            raise PermissionError(
                f"[AgentGuard-X] BLOCKED (intent gate): {intent_decision.reason}"
            )
        elif not intent_decision.allowed:
            logger.warning(
                "agentguard.intent_gate_deny (enforcement=off — logged only)",
                extra={"reason": intent_decision.reason},
            )

        # ── Triage pipeline ───────────────────────────────────────────────────
        if self._pipeline is None:
            return  # triage not wired in this instance (e.g. test)

        try:
            reversibility = self._get_reversibility(tool_name)
            stage_input = self._build_stage_input(tool_name, input_str)
            # Run triage in a new event loop if none is running (sync callback context)
            result = asyncio.run(
                self._pipeline.evaluate(stage_input, reversibility=reversibility)
            )
        except Exception as e:
            logger.error(f"Triage error (fail-closed): {e}")
            if self._enforcement:
                raise PermissionError(f"[AgentGuard-X] BLOCKED (triage error, fail-closed): {e}")
            return

        self._enforce_or_observe(result, tool_name)

    # ── Post-execution hook ───────────────────────────────────────────────────
    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        tool_name = self._call_sequence[-1] if self._call_sequence else "unknown"

        scan = self._post.scan(str(output), tool_name)
        if not scan.clean:
            logger.warning(
                "agentguard.post_hook_quarantine",
                extra={
                    "tool": tool_name,
                    "findings": scan.findings,
                    "enforcement": self._enforcement,
                },
            )
            if self._enforcement and scan.quarantined:
                raise ValueError(
                    f"[AgentGuard-X] QUARANTINED tool output: {scan.sanitized_output}"
                )
        else:
            logger.debug("agentguard.post_hook_clean", extra={"tool": tool_name})

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _enforce_or_observe(self, result, tool_name: str) -> None:
        verdict = result.verdict
        route = result.route

        log_extra = {
            "verdict": verdict.value,
            "route": route.value,
            "r": result.r,
            "k": result.k,
            "tool": tool_name,
            "enforcement": self._enforcement,
            "session_id": self._session_id,
            "block_reason": result.block_reason,
        }

        if verdict in (TriageVerdict.BLOCK, TriageVerdict.BLOCK_SHORT_CIRCUIT,
                       TriageVerdict.BLOCK_STAGE1):
            logger.warning("agentguard.block", extra=log_extra)
            if self._enforcement:
                raise PermissionError(
                    f"[AgentGuard-X] BLOCKED: {result.block_reason} "
                    f"(R={result.r:.3f}, verdict={verdict.value})"
                )

        elif verdict == TriageVerdict.GREY_BAND:
            logger.info("agentguard.grey_band", extra=log_extra)
            if route == RouteDecision.HOLD_SYNC and self._enforcement:
                # Irreversible op in grey band → synchronous hold
                self._trigger_hold(tool_name, result)

        else:  # ALLOW
            logger.debug("agentguard.allow", extra=log_extra)

    def _trigger_hold(self, tool_name: str, result) -> None:
        """Synchronous hold for irreversible operations.

        Hold timeout → BLOCK (fail-closed). NEVER allow-on-timeout.
        """
        hold_timeout = int(os.getenv("HOLD_TIMEOUT_SECONDS", "300"))
        logger.warning(
            "agentguard.hold_triggered",
            extra={
                "tool": tool_name,
                "r": result.r,
                "timeout_s": hold_timeout,
            },
        )
        # In the full stack, this would POST to the analyst queue and block.
        # In the PoC this raises immediately with a hold message.
        raise PermissionError(
            f"[AgentGuard-X] HELD: irreversible operation '{tool_name}' "
            f"(R={result.r:.3f}) queued for analyst review. "
            f"Timeout in {hold_timeout}s → BLOCK (fail-closed). "
            f"Analyst queue: http://localhost:8083"
        )

    def _build_stage_input(self, tool_name: str, input_str: str) -> Any:
        from agentguard.stages.base import StageInput
        agent_record = self._registry.get(self._agent_id)
        return StageInput(
            request_id=str(uuid.uuid4()),
            session_id=self._session_id,
            agent_id=self._agent_id,
            agent_role=self._agent_role,
            tool_name=tool_name,
            tool_input={"input": input_str},
            raw_payload=f"agent={self._agent_id} role={self._agent_role} "
                        f"tool={tool_name} input={input_str} "
                        f"history={' '.join(self._call_sequence[-10:])}",
            declared_tools=agent_record.allowed_tools if agent_record else [],
        )

    def _get_reversibility(self, tool_name: str) -> str:
        reversible_tools = {
            "get_account_tool", "query_transactions_tool", "read_customer_pii_tool",
            "run_report_tool", "fetch_market_data_tool", "compress_data_tool",
        }
        return "reversible" if tool_name in reversible_tools else "irreversible"
