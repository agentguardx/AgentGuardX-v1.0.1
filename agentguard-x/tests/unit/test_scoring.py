"""Triage scoring unit tests — §9 specification made executable.

THESE TESTS ARE NON-NEGOTIABLE. They encode the specification.
Failing any of these means the implementation violates the spec.

Tests covered:
  1. Four golden test cases (R to 2 decimal tolerance ±0.005)
  2. Headline invariant (S2=1.0, others=0 → grey band, NEVER block)
  3. No-renormalization rule (unavailable stage → score drops, vote count drops)
  4. Short-circuit (S2 >= 0.95 → block_short_circuit; below → normal path)
  5. Stage-1 failure (binary gate → block, no scoring)
  6. Routing thresholds (allow / grey / block boundaries)
  7. Fail-closed edges (unavailable stage → more scrutiny, never less)
"""

from __future__ import annotations

import pytest

from agentguard.scoring.engine import (
    GAMMA,
    SHORT_CIRCUIT_THRESHOLD,
    TAU_C,
    THRESHOLD_ALLOW,
    THRESHOLD_BLOCK,
    TriageEngine,
)
from agentguard.scoring.model import (
    RouteDecision,
    StageScores,
    TriageVerdict,
)


@pytest.fixture
def engine() -> TriageEngine:
    return TriageEngine()


# ── Helper ────────────────────────────────────────────────────────────────────
def approx(val: float, expected: float, tol: float = 0.005) -> bool:
    return abs(val - expected) <= tol


def assert_r(result, expected_r: float) -> None:
    assert approx(result.r, expected_r), (
        f"R={result.r:.4f} not within ±0.005 of expected {expected_r}. "
        f"base={result.base:.4f} k={result.k} a_bar={result.a_bar:.4f} "
        f"bonus={result.corroboration_bonus:.4f}"
    )


# ── Golden test cases (§9, mandatory) ─────────────────────────────────────────
class TestGoldenCases:
    def test_clean_fast_path(self, engine):
        """Clean: S2=.05 S3=.10 S4=.10 S5=.05 → R≈0.08 ALLOW"""
        scores = StageScores(s2=0.05, s3=0.10, s4=0.10, s5=0.05)
        result = engine.score(scores)
        assert_r(result, 0.08)
        assert result.verdict == TriageVerdict.ALLOW
        assert result.route == RouteDecision.FAST_PATH
        assert result.k == 0

    def test_single_moderate_grey_band(self, engine):
        """Single mod.: S2=.90 S3=.10 S4=.10 S5=.10 → R≈0.38 GREY_BAND"""
        scores = StageScores(s2=0.90, s3=0.10, s4=0.10, s5=0.10)
        result = engine.score(scores)
        assert_r(result, 0.38)
        assert result.verdict == TriageVerdict.GREY_BAND
        assert result.k == 1
        # Only S2 votes; bonus requires k >= 2, so bonus = 0
        assert approx(result.corroboration_bonus, 0.0)

    def test_two_independent_grey_band(self, engine):
        """Two indep.: S2=.70 S3=.20 S4=.65 S5=.20 → R≈0.61 GREY_BAND"""
        scores = StageScores(s2=0.70, s3=0.20, s4=0.65, s5=0.20)
        result = engine.score(scores)
        assert_r(result, 0.61)
        assert result.verdict == TriageVerdict.GREY_BAND
        assert result.k == 2

    def test_three_agree_block(self, engine):
        """Three agree: S2=.80 S3=.70 S4=.40 S5=.75 → R≈0.87 BLOCK"""
        scores = StageScores(s2=0.80, s3=0.70, s4=0.40, s5=0.75)
        result = engine.score(scores)
        assert_r(result, 0.87)
        assert result.verdict == TriageVerdict.BLOCK
        assert result.route == RouteDecision.BLOCKED
        assert result.k == 3  # S4=0.40 < TAU_C, does not vote


# ── Headline invariant (§9, NON-NEGOTIABLE) ───────────────────────────────────
class TestHeadlineInvariant:
    """A composite block is mathematically impossible with < 2 voting stages.

    S2=1.0, S3=S4=S5=0 → base=0.35, k=1, bonus=0, R=0.35 → GREY_BAND.
    This MUST fail with TriageVerdict.GREY_BAND, NEVER BLOCK.
    The only single-signal kill is the Stage-2 short-circuit (S2 >= 0.95).
    """

    def test_s2_max_others_zero_is_grey_not_block(self, engine):
        # SHORT CIRCUIT THRESHOLD is 0.95; S2=1.0 WOULD trigger short-circuit.
        # The headline invariant is about the COMPOSITE SCORING PATH.
        # We test composite scoring by using S2=0.94 (just below short-circuit)
        # to verify the formula never produces a composite block from one voter.
        scores = StageScores(s2=0.94, s3=0.0, s4=0.0, s5=0.0)
        result = engine.score(scores)
        assert result.short_circuited is False, "S2=0.94 must NOT short-circuit"
        # base = 0.35 * 0.94 = 0.329
        assert result.r == pytest.approx(0.35 * 0.94, abs=0.01), \
            "base must be 0.35*S2 = 0.329"
        # k=1 → bonus=0 → R=base → must be GREY_BAND
        assert result.k == 1
        assert approx(result.corroboration_bonus, 0.0)
        assert result.verdict == TriageVerdict.GREY_BAND, (
            "INVARIANT VIOLATED: single-voter composite score must be GREY_BAND, not BLOCK"
        )

    def test_spec_exact_s2_1_others_0_composite_path(self, engine):
        """Verify base=0.35 when S2=1.0 (even though short-circuit would fire separately)."""
        # We test via direct formula, not via engine.score() which would short-circuit.
        s2, s3, s4, s5 = 1.0, 0.0, 0.0, 0.0
        base = 0.35 * s2 + 0.30 * s3 + 0.20 * s4 + 0.15 * s5
        assert approx(base, 0.35)
        # k=1 (only S2 votes), bonus = gamma * max(0, k-1) * a_bar * (1-base) = 0
        k = sum(1 for x in [s2, s3, s4, s5] if x >= TAU_C)
        assert k == 1
        bonus = GAMMA * max(0, k - 1) * s2 * (1.0 - base)
        assert approx(bonus, 0.0)
        r = min(1.0, base + bonus)
        assert approx(r, 0.35)
        # R=0.35 → GREY_BAND (not BLOCK which requires R > 0.85)
        assert THRESHOLD_ALLOW <= r <= THRESHOLD_BLOCK

    def test_two_voters_required_for_composite_block(self, engine):
        """Verify that ≥2 voting stages are necessary for a composite block."""
        # With k=1 and the max possible base (S2=1.0, others near-max),
        # R must not reach THRESHOLD_BLOCK unless another stage also votes.
        scores = StageScores(s2=0.94, s3=0.49, s4=0.49, s5=0.49)
        result = engine.score(scores)
        assert result.k == 1, "Only S2 should vote (others < TAU_C=0.5)"
        assert approx(result.corroboration_bonus, 0.0), "Single voter has no bonus"
        assert result.verdict != TriageVerdict.BLOCK, (
            "Composite block impossible with k=1"
        )


# ── No-renormalization rule (§9, NON-NEGOTIABLE) ──────────────────────────────
class TestNoRenormalization:
    """Unavailable stage (None) contributes 0 with NO weight renormalization.

    A missing detector can only LOWER a score, never raise it.
    This ensures degradation routes more traffic to scrutiny, not toward allow.
    """

    def test_unavailable_s5_lowers_score(self, engine):
        """S5=None should produce LOWER or EQUAL R than S5=0.8."""
        base_scores = StageScores(s2=0.70, s3=0.60, s4=0.65, s5=0.80)
        degraded = StageScores(s2=0.70, s3=0.60, s4=0.65, s5=None)

        r_base = engine.score(base_scores).r
        r_degraded = engine.score(degraded).r

        assert r_degraded <= r_base + 0.001, (
            f"Unavailable S5 raised score: base={r_base:.4f} degraded={r_degraded:.4f}"
        )

    def test_unavailable_stage_cannot_vote(self, engine):
        """A stage with score=None must not contribute a vote even though effective=0 < TAU_C."""
        # With S4=0.80: all 4 stages vote (s2, s3, s4, s5 all >= TAU_C=0.5) → k=4
        # With S4=None: s2, s3, s5 vote; S4 unavailable → k=3 (not 4)
        scores_with_s4 = StageScores(s2=0.80, s3=0.75, s4=0.80, s5=0.75)
        scores_without_s4 = StageScores(s2=0.80, s3=0.75, s4=None, s5=0.75)

        r_with = engine.score(scores_with_s4)
        r_without = engine.score(scores_without_s4)

        # S4 is unavailable → it does NOT vote → k drops from 4 to 3
        assert r_with.k == 4, f"All stages available → k=4, got {r_with.k}"
        assert r_without.k == 3, (
            f"S4=None → only s2, s3, s5 vote → k=3, got {r_without.k}"
        )
        # Score with S4=None must be <= score with S4=0.80 (less info → lower/equal score)
        assert r_without.r <= r_with.r + 0.001

    def test_all_stages_unavailable_scores_zero(self, engine):
        """All stages None → R=0.0 → ALLOW."""
        scores = StageScores(s2=None, s3=None, s4=None, s5=None)
        result = engine.score(scores)
        assert result.r == pytest.approx(0.0)
        assert result.verdict == TriageVerdict.ALLOW
        assert result.k == 0

    def test_weights_not_renormalized(self, engine):
        """S4=None contributes weight 0, not redistributed to other stages."""
        # If renormalized: remaining weights would be 0.35/(0.35+0.30+0.15)=0.4375
        # Actual: S2 weight stays 0.35
        scores = StageScores(s2=1.0, s3=None, s4=None, s5=None)
        result = engine.score(scores)
        # base should be exactly 0.35*1.0 (not renormalized to 1.0)
        # But S2=1.0 >= SHORT_CIRCUIT_THRESHOLD=0.95 → would short-circuit
        # Use S2=0.94 to test formula without short-circuit
        scores2 = StageScores(s2=0.94, s3=None, s4=None, s5=None)
        result2 = engine.score(scores2)
        expected_base = 0.35 * 0.94  # weight NOT renormalized
        assert approx(result2.base, expected_base)


# ── Short-circuit (§9) ────────────────────────────────────────────────────────
class TestShortCircuit:
    def test_s2_above_threshold_short_circuits(self, engine):
        """S2 >= 0.95 → block_short_circuit in <2ms, no composite R."""
        scores = StageScores(s2=0.95, s3=0.0, s4=0.0, s5=0.0)
        result = engine.score(scores)
        assert result.short_circuited is True
        assert result.verdict == TriageVerdict.BLOCK_SHORT_CIRCUIT
        assert result.route == RouteDecision.BLOCKED
        assert result.latency_ms < 2.0, (
            f"Short-circuit took {result.latency_ms:.2f}ms, must be <2ms class"
        )

    def test_s2_exactly_at_threshold(self, engine):
        scores = StageScores(s2=SHORT_CIRCUIT_THRESHOLD, s3=0.0, s4=0.0, s5=0.0)
        result = engine.score(scores)
        assert result.short_circuited is True

    def test_s2_just_below_threshold_no_short_circuit(self, engine):
        """S2=0.949 must NOT short-circuit — falls through to composite scoring."""
        scores = StageScores(s2=0.94, s3=0.50, s4=0.50, s5=0.50)
        result = engine.score(scores)
        assert result.short_circuited is False
        assert result.verdict != TriageVerdict.BLOCK_SHORT_CIRCUIT

    def test_short_circuit_higher_than_composite_block_threshold(self):
        """SHORT_CIRCUIT_THRESHOLD > THRESHOLD_BLOCK — by design (§9)."""
        assert SHORT_CIRCUIT_THRESHOLD > THRESHOLD_BLOCK, (
            "Short-circuit threshold must be higher than composite block line: "
            f"{SHORT_CIRCUIT_THRESHOLD} vs {THRESHOLD_BLOCK}"
        )


# ── Stage 1 binary gate ────────────────────────────────────────────────────────
class TestStage1Gate:
    def test_stage1_failure_blocks_immediately(self, engine):
        scores = StageScores(s1_passed=False, s2=0.0, s3=0.0, s4=0.0, s5=0.0)
        result = engine.score(scores)
        assert result.verdict == TriageVerdict.BLOCK_STAGE1
        assert result.route == RouteDecision.STAGE1_GATE
        assert result.r == 1.0

    def test_stage1_failure_skips_stages_2_to_5(self, engine):
        """Stage 1 failure must not even compute composite scores."""
        scores = StageScores(s1_passed=False, s2=0.0, s3=0.0, s4=0.0, s5=0.0)
        result = engine.score(scores)
        assert result.base == 0.0  # not computed
        assert result.k == 0


# ── Routing thresholds ────────────────────────────────────────────────────────
class TestRoutingThresholds:
    def test_r_below_allow_threshold(self, engine):
        scores = StageScores(s2=0.10, s3=0.10, s4=0.10, s5=0.10)
        result = engine.score(scores)
        assert result.r < THRESHOLD_ALLOW
        assert result.verdict == TriageVerdict.ALLOW

    def test_r_just_above_allow_threshold_is_grey(self, engine):
        """R slightly above 0.25 should be GREY_BAND, not ALLOW."""
        # Construct scores that produce R clearly in grey band (> 0.25)
        # base=0.30: 0.35*0.30 + 0.30*0.30 + 0.20*0.30 + 0.15*0.30 = 0.30
        # All < TAU_C → no votes → k=0 → bonus=0 → R=0.30
        scores = StageScores(s2=0.30, s3=0.30, s4=0.30, s5=0.30)
        result = engine.score(scores)
        assert result.k == 0  # all below TAU_C
        assert approx(result.r, 0.30)
        assert result.verdict == TriageVerdict.GREY_BAND

    def test_r_below_allow_threshold_boundary(self, engine):
        """R slightly below 0.25 must be ALLOW."""
        # base=0.20: uniform 0.20 across all stages
        scores = StageScores(s2=0.20, s3=0.20, s4=0.20, s5=0.20)
        result = engine.score(scores)
        assert result.verdict == TriageVerdict.ALLOW

    def test_r_above_block_threshold(self, engine):
        scores = StageScores(s2=0.90, s3=0.90, s4=0.90, s5=0.90)
        result = engine.score(scores)
        assert result.verdict == TriageVerdict.BLOCK
        assert result.r > THRESHOLD_BLOCK

    def test_reversibility_routes_to_hold(self, engine):
        """Irreversible ops in grey band → HOLD_SYNC."""
        scores = StageScores(s2=0.60, s3=0.60, s4=0.10, s5=0.10)
        result = engine.score(scores, reversibility="irreversible")
        assert result.verdict == TriageVerdict.GREY_BAND
        assert result.route == RouteDecision.HOLD_SYNC

    def test_reversible_routes_to_sandbox_async(self, engine):
        """Reversible ops in grey band → SANDBOX_ASYNC."""
        scores = StageScores(s2=0.60, s3=0.60, s4=0.10, s5=0.10)
        result = engine.score(scores, reversibility="reversible")
        assert result.verdict == TriageVerdict.GREY_BAND
        assert result.route == RouteDecision.SANDBOX_ASYNC


# ── Fail-closed edge: hold timeout ────────────────────────────────────────────
class TestFailClosedEdges:
    def test_stage1_fail_closed(self, engine):
        """Unknown identity → Stage 1 failure → block. Never passes."""
        result = TriageEngine.score_stage1_failure()
        assert result.verdict == TriageVerdict.BLOCK_STAGE1
        assert result.route == RouteDecision.STAGE1_GATE

    def test_intent_gate_is_stateless(self, engine):
        """Same scores → same verdict regardless of call order."""
        scores = StageScores(s2=0.40, s3=0.40, s4=0.40, s5=0.40)
        r1 = engine.score(scores)
        r2 = engine.score(scores)
        assert r1.verdict == r2.verdict
        assert approx(r1.r, r2.r, tol=1e-9)

    def test_composite_block_requires_two_voters(self, engine):
        """Composite block can ONLY happen when k >= 2."""
        # Sweep: one voter can never cause composite block
        for s2 in [0.50, 0.60, 0.70, 0.80, 0.90, 0.94]:
            scores = StageScores(s2=s2, s3=0.0, s4=0.0, s5=0.0)
            result = engine.score(scores)
            assert result.verdict != TriageVerdict.BLOCK, (
                f"Single voter S2={s2} produced composite BLOCK — invariant violated"
            )

    def test_corroboration_formula_exact(self, engine):
        """Verify corroboration_bonus formula for two-voter case."""
        # S2=0.70, S3=0.20, S4=0.65, S5=0.20 (two-indep golden case)
        scores = StageScores(s2=0.70, s3=0.20, s4=0.65, s5=0.20)
        result = engine.score(scores)
        expected_base = 0.35 * 0.70 + 0.30 * 0.20 + 0.20 * 0.65 + 0.15 * 0.20
        # = 0.245 + 0.060 + 0.130 + 0.030 = 0.465
        assert approx(result.base, 0.465)
        assert result.k == 2
        expected_a_bar = (0.70 + 0.65) / 2  # 0.675
        assert approx(result.a_bar, expected_a_bar)
        expected_bonus = GAMMA * max(0, 2 - 1) * expected_a_bar * (1.0 - expected_base)
        # = 0.4 * 1 * 0.675 * 0.535 = 0.14445
        assert approx(result.corroboration_bonus, expected_bonus)
        assert approx(result.r, expected_base + expected_bonus)
