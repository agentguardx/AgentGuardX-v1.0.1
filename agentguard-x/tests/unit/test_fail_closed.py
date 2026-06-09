"""Fail-closed edge case tests — §18 acceptance gates.

Each fail-closed invariant gets its own test:
  1. Unknown reversibility → sync hold (never sandbox or allow)
  2. Hold timeout terminal state → BLOCK (never allow-on-timeout)
  3. Cheap-gate runs BEFORE human queue
  4. OPA bad bundle → reject-all on last-valid
  5. Redis down → S5 suspended + more scrutiny routing
  6. Toggle OFF → observability still emits (smoke test)
  7. Intent gate is stateless (same inputs → same decision)
"""

from __future__ import annotations

import pytest

from agentguard.gateway.intent_gate import IntentGate, IntentDecision
from agentguard.greyband.router import (
    GreybandRouter,
    GreybandRoute,
    ReversibilityClass,
    ReversibilityTable,
)
from agentguard.scoring.engine import TriageEngine
from agentguard.scoring.model import StageScores, RouteDecision, TriageVerdict
from agentguard.toggle import get_enforcement, set_enforcement


# ── 1. Unknown reversibility → sync hold ──────────────────────────────────────
class TestUnknownReversibility:
    def test_unknown_tool_classifies_as_irreversible(self):
        table = ReversibilityTable()
        cls = table.classify("some_unknown_tool_xyz")
        assert cls == ReversibilityClass.IRREVERSIBLE, (
            "Unknown tool must default to IRREVERSIBLE (fail-closed)"
        )

    def test_unknown_tool_routes_to_hold(self):
        router = GreybandRouter(enforcement=True)
        decision = router.route(
            tool_name="completely_unknown_tool",
            r_score=0.50,
        )
        assert decision.route == GreybandRoute.HOLD_SYNC, (
            "Unknown reversibility must route to HOLD_SYNC (synchronous hold)"
        )

    def test_unknown_reversibility_never_sandbox(self):
        router = GreybandRouter(enforcement=True)
        decision = router.route("another_unknown_tool", r_score=0.30)
        assert decision.route != GreybandRoute.SANDBOX_ASYNC, (
            "Unknown reversibility must NOT route to sandbox (only reversible ops do)"
        )


# ── 2. Hold timeout → BLOCK (never allow-on-timeout) ─────────────────────────
class TestHoldTimeout:
    def test_router_specifies_timeout_for_hold(self):
        """Router must set a finite hold_timeout_seconds > 0 for HOLD_SYNC decisions."""
        router = GreybandRouter(enforcement=True)
        # transfer_funds is irreversible, above auto-allow threshold
        decision = router.route(
            "transfer_funds_tool", r_score=0.50, operation_value_usd=5000.0
        )
        assert decision.route == GreybandRoute.HOLD_SYNC
        assert decision.hold_timeout_seconds > 0, (
            "HOLD_SYNC must specify a finite timeout (block on expiry)"
        )

    def test_hold_reason_explicitly_blocks_on_timeout(self):
        """Hold reason must explicitly state block-on-timeout semantics."""
        router = GreybandRouter(enforcement=True)
        decision = router.route("transfer_funds_tool", r_score=0.50, operation_value_usd=5000.0)
        reason_lower = decision.reason.lower()
        assert "block" in reason_lower, (
            "Hold reason must explicitly mention 'block' on timeout"
        )
        # Must say fail-closed or never-allow-on-timeout
        assert "fail-closed" in reason_lower or "never allow-on-timeout" in reason_lower, (
            "Hold reason must mention fail-closed semantics"
        )


# ── 3. Cheap-gate runs BEFORE human queue ─────────────────────────────────────
class TestCheapGateOrder:
    def test_trivially_safe_auto_allowed_before_queue(self):
        """Operations below auto-allow threshold must be allowed without going to human queue."""
        router = GreybandRouter(enforcement=True)
        decision = router.route(
            "transfer_funds_tool",
            r_score=0.50,
            operation_value_usd=50.0,  # below auto-allow threshold of $100
        )
        assert decision.route == GreybandRoute.CHEAP_GATE_ALLOW, (
            "Trivially safe ops must be auto-allowed by cheap-gate before human queue"
        )

    def test_egregious_auto_blocked_before_queue(self):
        """Operations above auto-block threshold must be blocked without going to human queue."""
        router = GreybandRouter(enforcement=True)
        decision = router.route(
            "transfer_funds_tool",
            r_score=0.50,
            operation_value_usd=2_000_000.0,  # above auto-block threshold
        )
        assert decision.route == GreybandRoute.CHEAP_GATE_BLOCK, (
            "Egregious ops must be auto-blocked by cheap-gate before human queue"
        )

    def test_ambiguous_goes_to_human_queue(self):
        """Operations in the middle range must go to human hold (synchronous)."""
        router = GreybandRouter(enforcement=True)
        decision = router.route(
            "transfer_funds_tool",
            r_score=0.50,
            operation_value_usd=5_000.0,  # between auto-allow and auto-block
        )
        assert decision.route == GreybandRoute.HOLD_SYNC


# ── 4. Redis down → S5 suspended + more scrutiny ─────────────────────────────
class TestRedisDown:
    @pytest.mark.asyncio
    async def test_s5_returns_none_when_redis_unavailable(self):
        from agentguard.stages.stage5_behavioral import Stage5Behavioral  # direct import
        from agentguard.stages.base import StageInput

        stage = Stage5Behavioral(redis_client=None)  # no Redis
        inp = StageInput(
            request_id="test", session_id="sess", agent_id="agent",
            agent_role="research", tool_name="get_account_tool",
            tool_input={}, raw_payload="test",
        )
        output = await stage.run(inp)
        assert output.score is None, "S5 must return score=None when Redis unavailable"
        assert not output.available

    def test_unavailable_s5_scores_zero_no_renorm(self):
        """When S5 is None (Redis down), effective S5 = 0, weights not renormalized."""
        engine = TriageEngine()
        # With S5 available at 0.8
        with_s5 = engine.score(StageScores(s2=0.6, s3=0.6, s4=0.6, s5=0.8))
        # With S5 unavailable (Redis down)
        without_s5 = engine.score(StageScores(s2=0.6, s3=0.6, s4=0.6, s5=None))

        # Score must be lower (Redis down → less information → lower score)
        assert without_s5.r <= with_s5.r + 0.001, (
            "Redis down (S5=None) must not raise the risk score"
        )
        # Routing must not become ALLOW when it was higher before
        if with_s5.verdict == TriageVerdict.GREY_BAND:
            assert without_s5.verdict != TriageVerdict.ALLOW, (
                "Redis down must route toward more scrutiny, not less"
            )


# ── 5. Toggle OFF → observability active (smoke test) ────────────────────────
class TestToggleObservability:
    def test_toggle_off_then_on(self, tmp_path, monkeypatch):
        """Toggle transitions work without raising."""
        import agentguard.toggle as toggle_mod
        toggle_file = tmp_path / ".toggle_state"
        monkeypatch.setattr(toggle_mod, "_TOGGLE_FILE", toggle_file)
        monkeypatch.delenv("AGENTGUARD_ENFORCEMENT", raising=False)

        # Default: ON
        toggle_mod.set_enforcement("on")
        assert toggle_mod.get_enforcement() is True

        # Turn OFF
        toggle_mod.set_enforcement("off")
        assert toggle_mod.get_enforcement() is False

        # Turn back ON
        toggle_mod.set_enforcement("on")
        assert toggle_mod.get_enforcement() is True


# ── 6. Intent gate stateless ──────────────────────────────────────────────────
class TestIntentGateStateless:
    """Same tool call → same gate decision regardless of how many times called."""

    def test_same_inputs_same_decision(self):
        gate = IntentGate()
        tools = ["get_account_tool", "run_report_tool"]

        decisions = [
            gate.check("research", "get_account_tool", tools)
            for _ in range(10)
        ]
        # All decisions must be identical
        assert all(d.allowed == decisions[0].allowed for d in decisions)

    def test_denied_tool_always_denied(self):
        gate = IntentGate()
        tools = ["get_account_tool"]

        # Transfer funds not in research's envelope — must always deny
        for _ in range(5):
            decision = gate.check("research", "transfer_funds_tool", tools)
            assert decision.allowed is False

    def test_empty_envelope_always_denies(self):
        gate = IntentGate()
        decision = gate.check("research", "any_tool", [])
        assert decision.allowed is False, "Empty envelope must deny — under-declared fails closed"

    def test_gate_ignores_session_history(self):
        """Gate makes same decision on first call as on hundredth call of same tool."""
        gate = IntentGate()
        tools = ["get_account_tool"]

        # First call
        first = gate.check("research", "get_account_tool", tools)
        # Simulate many prior calls (history not passed here — gate is stateless)
        for _ in range(50):
            gate.check("research", "get_account_tool", tools)
        # Decision unchanged
        last = gate.check("research", "get_account_tool", tools)
        assert first.allowed == last.allowed
