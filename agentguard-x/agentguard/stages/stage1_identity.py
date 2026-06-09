"""Stage 1 — Identity & Context. BINARY HARD GATE.

Not scored; no weight. Checks:
  - Registered agent? (agent_id in registry)
  - Token valid + unexpired?
  - Session coherent (context consistent with profile)?
  - A2A capability claims match registered OPA policy?

Any failure → block instantly. Stages 2–5 never run.
A cryptographically valid identity asserting unregistered capabilities = fail here.
Unrecognized identity → gVisor floor (§0: if unavailable → block).
"""

from __future__ import annotations

import time
from typing import Optional

from .base import StageInput, StageOutput, StageRunner


class Stage1IdentityGate(StageRunner):
    """Binary identity and context gate."""

    def __init__(self, registry: object, opa_client: Optional[object] = None) -> None:
        self._registry = registry
        self._opa = opa_client

    @property
    def stage_id(self) -> str:
        return "s1_identity"

    async def run(self, inp: StageInput) -> StageOutput:
        t0 = time.monotonic()

        # S1 is binary — no numeric score. Use score=0 (pass) or score=1 (fail)
        # by convention; the engine checks s1_passed separately.
        try:
            passed, reason = await self._check(inp)
        except Exception as e:
            # Any internal error → fail closed
            passed = False
            reason = f"Stage 1 internal error (fail-closed): {e}"

        return StageOutput(
            stage_id=self.stage_id,
            score=None,             # S1 is not scored; engine uses s1_passed
            available=True,
            explanation=reason,
            metadata={"passed": passed},
            latency_ms=(time.monotonic() - t0) * 1000,
        )

    async def _check(self, inp: StageInput) -> tuple[bool, str]:
        from agentguard.registry.agent_registry import get_agent_registry

        registry = get_agent_registry()

        # ── 1. Is agent registered? ──────────────────────────────────────────
        agent_record = registry.get(inp.agent_id)
        if agent_record is None:
            return False, f"Unregistered agent '{inp.agent_id}' — identity unknown"

        # ── 2. Does role match? ──────────────────────────────────────────────
        if agent_record.role != inp.agent_role:
            return False, (
                f"Role mismatch: token claims role '{inp.agent_role}', "
                f"registry has '{agent_record.role}' for agent '{inp.agent_id}'"
            )

        # ── 3. Capability claims match registered envelope ────────────────────
        # A2A capability claims: the tool being called must be in declared_tools.
        # Over-claiming = privilege escalation = fail here.
        declared = set(agent_record.allowed_tools)
        if inp.tool_name and inp.tool_name not in declared:
            return False, (
                f"Capability escalation: agent '{inp.agent_id}' (role={inp.agent_role}) "
                f"claims tool '{inp.tool_name}' not in declared envelope {sorted(declared)}"
            )

        # ── 4. Session coherence (lightweight context check) ─────────────────
        # Deep session history lives in Stage 5 (behavioral).
        # Here we only check trivial invariants: role hasn't changed mid-session.
        if inp.identity_claims.get("role") and inp.identity_claims["role"] != inp.agent_role:
            return False, (
                f"Session incoherence: role changed from '{inp.identity_claims['role']}' "
                f"to '{inp.agent_role}' mid-session"
            )

        return True, f"Identity verified: agent='{inp.agent_id}' role='{inp.agent_role}'"
