"""Grey-band hybrid router (§11).

2-axis routing matrix:
  Axis A: reversibility (physical constraint — can we observe-then-decide?)
  Axis B: isolation floor (Docker vs gVisor, only relevant for replayable branch)

Grey-band branch logic:
  REPLAYABLE ops  → SANDBOX + async review. Sandbox verdict is authoritative at decision time.
  IRREVERSIBLE ops → cheap-gate pre-filter → synchronous hold-with-timeout → BLOCK on expiry.

INVARIANTS:
  - Reversibility is a ROUTER INPUT, not a score term. Score formula is unchanged.
  - Unknown reversibility → IRREVERSIBLE (fail-closed default).
  - Hold timeout → BLOCK. NEVER allow-on-timeout.
  - Cheap-gate runs BEFORE human queue (not after).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ReversibilityClass(str, Enum):
    REVERSIBLE = "reversible"
    IRREVERSIBLE = "irreversible"
    UNKNOWN = "unknown"  # → treated as IRREVERSIBLE (fail-closed)


class GreybandRoute(str, Enum):
    SANDBOX_ASYNC = "sandbox_async"     # Replayable → sandbox + async review
    CHEAP_GATE_ALLOW = "cheap_gate_allow"  # Irreversible, trivially safe end
    CHEAP_GATE_BLOCK = "cheap_gate_block"  # Irreversible, egregious end
    HOLD_SYNC = "hold_sync"             # Irreversible, ambiguous → analyst hold
    PASS_THROUGH = "pass_through"       # Enforcement off — observability only


@dataclass
class GreybandDecision:
    route: GreybandRoute
    reason: str
    hold_timeout_seconds: int = 0
    isolation_tier: str = "docker"  # docker | gvisor


class ReversibilityTable:
    """Static reversibility lookup for the PoC.

    Default for unclassified operations → IRREVERSIBLE (fail-closed).
    Unknown biases toward synchronous hold — correct-but-slow, never an unintended fire.
    """

    _TABLE: dict[str, ReversibilityClass] = {
        # Reversible (read / compute)
        "get_account_tool": ReversibilityClass.REVERSIBLE,
        "query_transactions_tool": ReversibilityClass.REVERSIBLE,
        "read_customer_pii_tool": ReversibilityClass.REVERSIBLE,
        "run_report_tool": ReversibilityClass.REVERSIBLE,
        "fetch_market_data_tool": ReversibilityClass.REVERSIBLE,
        "compress_data_tool": ReversibilityClass.REVERSIBLE,
        # Irreversible (external writes, financial ops, comms)
        "transfer_funds_tool": ReversibilityClass.IRREVERSIBLE,
        "send_email_tool": ReversibilityClass.IRREVERSIBLE,
        "post_external_tool": ReversibilityClass.IRREVERSIBLE,
        "execute_code_tool": ReversibilityClass.IRREVERSIBLE,
    }

    def classify(self, tool_name: str) -> ReversibilityClass:
        cls = self._TABLE.get(tool_name)
        if cls is None:
            # Unknown → IRREVERSIBLE (fail-closed default per §11)
            return ReversibilityClass.IRREVERSIBLE
        return cls


class GreybandRouter:
    """Hybrid grey-band router — implements §11 2-axis routing matrix."""

    def __init__(
        self,
        reversibility_table: Optional[ReversibilityTable] = None,
        sandbox_mode: str = "docker_only",  # from capability report
        enforcement: bool = True,
    ) -> None:
        self._rev_table = reversibility_table or ReversibilityTable()
        self._sandbox_mode = sandbox_mode
        self._enforcement = enforcement

        # Cheap-gate thresholds (one gate per §11 PoC spec)
        self._auto_allow_usd = float(
            os.getenv("CHEAP_GATE_AUTO_ALLOW_THRESHOLD", "100.0")
        )
        self._auto_block_usd = float(
            os.getenv("CHEAP_GATE_AUTO_BLOCK_THRESHOLD", "1000000.0")
        )
        self._hold_timeout = int(os.getenv("HOLD_TIMEOUT_SECONDS", "300"))

    def route(
        self,
        tool_name: str,
        r_score: float,
        operation_value_usd: float = 0.0,
        requires_gvisor_floor: bool = False,
    ) -> GreybandDecision:
        """Determine the grey-band route for an operation.

        Args:
            tool_name: Name of the tool being called.
            r_score: Composite risk score R from triage engine.
            operation_value_usd: Financial value (for cheap-gate). 0 = not applicable.
            requires_gvisor_floor: True for code execution / agent spawning.

        Returns:
            GreybandDecision with route and reason.
        """
        if not self._enforcement:
            return GreybandDecision(
                route=GreybandRoute.PASS_THROUGH,
                reason="Enforcement OFF — observability only",
            )

        rev = self._rev_table.classify(tool_name)
        # Unknown reversibility → treat as IRREVERSIBLE (fail-closed)
        is_irreversible = rev in (ReversibilityClass.IRREVERSIBLE, ReversibilityClass.UNKNOWN)

        if not is_irreversible:
            # ── Replayable path: sandbox + async review ───────────────────────
            isolation = self._isolation_tier(requires_gvisor_floor)
            return GreybandDecision(
                route=GreybandRoute.SANDBOX_ASYNC,
                reason=(
                    f"Replayable op '{tool_name}' (R={r_score:.3f}) → "
                    f"sandbox + async review ({isolation} tier)"
                ),
                isolation_tier=isolation,
            )

        # ── Irreversible path ──────────────────────────────────────────────────
        # 1. Cheap-gate pre-filter runs FIRST (before human queue)
        if operation_value_usd > 0:
            if operation_value_usd <= self._auto_allow_usd:
                return GreybandDecision(
                    route=GreybandRoute.CHEAP_GATE_ALLOW,
                    reason=(
                        f"Cheap-gate ALLOW: value ${operation_value_usd:.2f} "
                        f"<= auto-allow threshold ${self._auto_allow_usd:.2f}"
                    ),
                )
            if operation_value_usd >= self._auto_block_usd:
                return GreybandDecision(
                    route=GreybandRoute.CHEAP_GATE_BLOCK,
                    reason=(
                        f"Cheap-gate BLOCK: value ${operation_value_usd:.2f} "
                        f">= auto-block threshold ${self._auto_block_usd:.2f}"
                    ),
                )

        # 2. Ambiguous → synchronous hold with timeout (fail-closed on expiry)
        return GreybandDecision(
            route=GreybandRoute.HOLD_SYNC,
            reason=(
                f"Irreversible op '{tool_name}' (R={r_score:.3f}) → "
                f"synchronous hold for analyst review. "
                f"Timeout {self._hold_timeout}s → BLOCK (fail-closed, never allow-on-timeout)."
            ),
            hold_timeout_seconds=self._hold_timeout,
        )

    def _isolation_tier(self, requires_gvisor_floor: bool) -> str:
        """Determine sandbox isolation tier.

        If gVisor required but unavailable (WSL2 default) → operation is BLOCKED,
        not downgraded to Docker. This is documented as the expected WSL2 behavior.
        """
        if requires_gvisor_floor:
            if self._sandbox_mode == "gvisor":
                return "gvisor"
            # gVisor unavailable → block (not downgrade)
            return "blocked_gvisor_unavailable"
        return "docker"
