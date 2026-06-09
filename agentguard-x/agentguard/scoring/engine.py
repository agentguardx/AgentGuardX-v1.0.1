"""Triage scoring engine — implements §9 formula exactly.

This module is PURE: no I/O, no external dependencies.
It is the mathematical heart of AgentGuard-X.

CRITICAL INVARIANTS (each enforced by a failing unit test):
  1. Headline invariant: S2=1.0, S3=S4=S5=0 → R=0.35 → GREY_BAND, never BLOCK.
     Composite block is mathematically impossible with < 2 voting stages.
  2. No-renormalization: unavailable stage (score=None) contributes 0 to base
     and does NOT vote. Score can only go down, never up.
  3. Short-circuit is a SEPARATE kill path (S2 >= 0.95), not part of composite R.
  4. Routing thresholds: R < 0.25 → ALLOW; 0.25 ≤ R ≤ 0.85 → GREY_BAND; R > 0.85 → BLOCK.

GOLDEN TEST VALUES (see tests/unit/test_scoring.py):
  Clean:       S2=.05 S3=.10 S4=.10 S5=.05 → R≈0.08  ALLOW
  Single mod.: S2=.90 S3=.10 S4=.10 S5=.10 → R≈0.38  GREY_BAND
  Two indep.:  S2=.70 S3=.20 S4=.65 S5=.20 → R≈0.61  GREY_BAND
  Three agree: S2=.80 S3=.70 S4=.40 S5=.75 → R≈0.87  BLOCK
"""

from __future__ import annotations

import time
from typing import Optional

from .model import RouteDecision, StageScores, TriageResult, TriageVerdict

# ── Constants (§9) ────────────────────────────────────────────────────────────
TAU_C: float = 0.5    # vote threshold — stage scores >= this "vote"
GAMMA: float = 0.4    # corroboration gain factor

# Stage weights (must sum to 1.0)
W_S2: float = 0.35
W_S3: float = 0.30
W_S4: float = 0.20
W_S5: float = 0.15

# Routing thresholds
THRESHOLD_ALLOW: float = 0.25   # R < this → ALLOW
THRESHOLD_BLOCK: float = 0.85   # R > this → BLOCK (composite)

# Short-circuit — intentionally higher than composite block line
# One signal must be CERTAIN to kill alone; multiple only need to agree.
SHORT_CIRCUIT_THRESHOLD: float = 0.95


class TriageEngine:
    """Pure scoring engine — takes StageScores, returns TriageResult.

    Thread-safe: all state is in the input/output objects.
    Instantiate once and call `score()` concurrently from any thread.
    """

    def score(
        self,
        scores: StageScores,
        *,
        reversibility: Optional[str] = None,
        isolation_floor: Optional[str] = None,
    ) -> TriageResult:
        """Compute triage result for a set of stage scores.

        Stage 1 is a binary gate checked BEFORE calling this method.
        If scores.s1_passed is False, call score() is unnecessary —
        use score_stage1_failure() instead.

        Args:
            scores: Sub-scores from stages 2-5. None = stage unavailable.
            reversibility: 'reversible' | 'irreversible' | None.
                Used by RouteDecision logic in grey-band; NOT part of score.
            isolation_floor: 'docker' | 'gvisor' | None.
                Used for sandbox tier selection; NOT part of score.
        """
        t0 = time.monotonic()

        result = TriageResult(scores=scores)

        # ── Stage 1: binary hard gate (not scored) ───────────────────────────
        if not scores.s1_passed:
            return self._stage1_failure(result, t0)

        # ── Stage 2 short-circuit check (separate from composite R) ─────────
        # S2 >= SHORT_CIRCUIT_THRESHOLD → block immediately; skip 3–5.
        # This is the ONLY single-signal kill path.
        s2_eff = scores.effective_s2()
        if s2_eff >= SHORT_CIRCUIT_THRESHOLD:
            result.short_circuited = True
            result.r = s2_eff
            result.verdict = TriageVerdict.BLOCK_SHORT_CIRCUIT
            result.route = RouteDecision.BLOCKED
            result.block_reason = (
                f"Stage-2 short-circuit: S2={s2_eff:.3f} >= {SHORT_CIRCUIT_THRESHOLD}"
            )
            result.triggered_stages = ["s2_short_circuit"]
            result.latency_ms = (time.monotonic() - t0) * 1000
            return result

        # ── Stages 2–5 composite scoring ────────────────────────────────────
        s3_eff = scores.effective_s3()
        s4_eff = scores.effective_s4()
        s5_eff = scores.effective_s5()

        # base = weighted sum (unavailable stages contribute 0, NO renormalization)
        base = W_S2 * s2_eff + W_S3 * s3_eff + W_S4 * s4_eff + W_S5 * s5_eff

        # Voting: stages with score >= tau_c
        stage_scores = {
            "s2": s2_eff,
            "s3": s3_eff,
            "s4": s4_eff,
            "s5": s5_eff,
        }
        # A stage only votes if it was AVAILABLE (not None) AND score >= tau_c.
        # Unavailable stages (None) CANNOT vote even if their effective score (0) < tau_c.
        voting_stages = {
            name: val
            for name, val in stage_scores.items()
            if val >= TAU_C
            and getattr(scores, name) is not None  # must be available to vote
        }
        k = len(voting_stages)
        a_bar = sum(voting_stages.values()) / k if k > 0 else 0.0

        # Corroboration bonus
        bonus = GAMMA * max(0, k - 1) * a_bar * (1.0 - base)

        r = min(1.0, base + bonus)

        # ── Routing ──────────────────────────────────────────────────────────
        triggered = [name for name, val in stage_scores.items() if val >= TAU_C
                     and getattr(scores, name) is not None]

        if r > THRESHOLD_BLOCK:
            verdict = TriageVerdict.BLOCK
            route = RouteDecision.BLOCKED
            block_reason = (
                f"Composite R={r:.3f} > {THRESHOLD_BLOCK} "
                f"(k={k} voting stages: {', '.join(triggered)})"
            )
        elif r >= THRESHOLD_ALLOW:
            verdict = TriageVerdict.GREY_BAND
            # Grey-band routing is reversibility-dependent (§11).
            # The engine returns GREY_BAND; the caller decides the physical route.
            # For convenience, pre-populate based on reversibility if provided.
            if reversibility == "irreversible":
                route = RouteDecision.HOLD_SYNC
            else:
                route = RouteDecision.SANDBOX_ASYNC
            block_reason = None
        else:
            verdict = TriageVerdict.ALLOW
            route = RouteDecision.FAST_PATH
            block_reason = None

        result.base = base
        result.k = k
        result.a_bar = a_bar
        result.corroboration_bonus = bonus
        result.r = r
        result.verdict = verdict
        result.route = route
        result.triggered_stages = triggered
        result.block_reason = block_reason
        result.latency_ms = (time.monotonic() - t0) * 1000
        return result

    @staticmethod
    def _stage1_failure(result: TriageResult, t0: float) -> TriageResult:
        result.verdict = TriageVerdict.BLOCK_STAGE1
        result.route = RouteDecision.STAGE1_GATE
        result.block_reason = "Stage 1 hard gate: identity/context verification failed"
        result.r = 1.0
        result.latency_ms = (time.monotonic() - t0) * 1000
        return result

    @staticmethod
    def score_stage1_failure() -> TriageResult:
        """Convenience constructor for Stage 1 failures (skips scoring entirely)."""
        engine = TriageEngine()
        scores = StageScores(s1_passed=False)
        return engine._stage1_failure(TriageResult(scores=scores), time.monotonic())
