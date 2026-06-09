"""Intent gate — stateless envelope membership check (§10).

This gate answers one question: could this agent EVER legitimately call this tool?
It is a PURE set-membership lookup: declared envelope vs. requested tool.

Design constraints (§10, NON-NEGOTIABLE):
  - STATELESS: same tool call + same role → same decision, always.
  - Session history NEVER enters here — that's Stage 5 (behavioral) + OPA (S3).
  - Under-declared envelope fails CLOSED (over-block — annoying, safe).
  - Over-declared envelope fails OPEN (relies on Stages 2–5 scoring).
  - Documented failure asymmetry: bad config → over-blocking, never silent pass.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IntentDecision:
    allowed: bool
    reason: str


class IntentGate:
    """Stateless tool-envelope membership check.

    Failure asymmetry (documented per §10):
      - Under-declared: agent misses legitimate tool → over-block → annoying but SAFE.
      - Over-declared: agent granted too much → relies on S2–S5 scoring → still defensible.
    The PoC's failure mode under misconfiguration is over-blocking.
    """

    def check(
        self,
        agent_role: str,
        tool_name: str,
        declared_tools: list[str],
    ) -> IntentDecision:
        """Pure stateless membership check.

        Args:
            agent_role: The agent's role (research/data/admin).
            tool_name: The tool being called.
            declared_tools: The agent's declared tool envelope (from registry).

        Returns:
            IntentDecision(allowed=True/False, reason=...).
        """
        if not declared_tools:
            return IntentDecision(
                allowed=False,
                reason=(
                    f"Intent gate DENY: no declared envelope for role '{agent_role}'. "
                    "Under-declared envelope fails closed — safe, but over-blocking. "
                    "Fix: register agent with correct allowed_tools."
                ),
            )

        if tool_name in declared_tools:
            return IntentDecision(
                allowed=True,
                reason=f"Intent gate ALLOW: '{tool_name}' in declared envelope for '{agent_role}'",
            )

        return IntentDecision(
            allowed=False,
            reason=(
                f"Intent gate DENY: '{tool_name}' NOT in declared envelope for '{agent_role}'. "
                f"Envelope: {sorted(declared_tools)}"
            ),
        )
