"""Stage 3 — OPA Policy (Rego).

Weight: 0.30

Evaluates:
  - Tool permissions per role (RBAC)
  - Resource access per role
  - Per-identity rate limits
  - Allowed/blocked call sequences

OPA runs as a sidecar container; policies version-controlled in /policies.
Bundle polling enables hot reload.
A bad bundle FAILS CLOSED — uses last valid bundle, rejects all if none available.
"""

from __future__ import annotations

import time
from typing import Any, Optional

import httpx

from .base import StageInput, StageOutput, StageRunner


class Stage3OPA(StageRunner):
    """OPA sidecar client for policy evaluation."""

    def __init__(self, opa_url: str = "http://localhost:8181") -> None:
        self._opa_url = opa_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=2.0)

    @property
    def stage_id(self) -> str:
        return "s3_opa"

    async def run(self, inp: StageInput) -> StageOutput:
        t0 = time.monotonic()
        try:
            score, explanation, meta = await self._evaluate(inp)
        except httpx.ConnectError:
            # OPA unreachable → stage unavailable → score=None (fail-closed: more scrutiny)
            return StageOutput(
                stage_id=self.stage_id, score=None, available=False,
                explanation="OPA unreachable — stage unavailable (fail-closed: score=0, no renorm)",
            )
        except Exception as e:
            return StageOutput(
                stage_id=self.stage_id, score=None, available=False,
                explanation=f"OPA error: {e}",
            )

        return StageOutput(
            stage_id=self.stage_id,
            score=score,
            available=True,
            explanation=explanation,
            metadata=meta,
            latency_ms=(time.monotonic() - t0) * 1000,
        )

    async def _evaluate(
        self, inp: StageInput
    ) -> tuple[float, str, dict[str, Any]]:
        """Query OPA for RBAC + sequence policy decision."""
        payload = {
            "input": {
                "agent_id": inp.agent_id,
                "agent_role": inp.agent_role,
                "tool_name": inp.tool_name,
                "tool_input": inp.tool_input,
                "session_id": inp.session_id,
                "declared_tools": inp.declared_tools,
            }
        }

        # Query RBAC policy
        response = await self._client.post(
            f"{self._opa_url}/v1/data/agentguard/rbac/decision",
            json=payload,
        )
        response.raise_for_status()
        result = response.json().get("result", {})

        allowed: bool = result.get("allow", False)
        violations: list[str] = result.get("violations", [])
        risk_score: float = result.get("risk_score", 0.0)

        # OPA returns a structured decision:
        # allow=False + risk_score → high score (threat)
        # allow=True → low score
        if not allowed:
            score = max(0.75, float(risk_score))
            explanation = f"OPA DENY: {'; '.join(violations) or 'policy violation'}"
        else:
            score = float(risk_score)  # allowed but may still have non-zero risk
            explanation = f"OPA ALLOW (risk_score={score:.2f})"

        return score, explanation, {
            "opa_allow": allowed,
            "violations": violations,
            "risk_score": risk_score,
        }
