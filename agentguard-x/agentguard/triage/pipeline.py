"""Triage pipeline — wires Stage 1 gate + concurrent Stage 2–5 + scoring engine.

Execution order (per §5):
  Gateway pre-hook → TLS proxy → Triage engine → grey-band handling → Gateway post-hook
                     ^─ THIS FILE ─────────────^

Stage 1 runs FIRST (binary gate). If it fails, stages 2–5 are skipped.
Stages 2–5 run CONCURRENTLY after Stage 1 clears.
Short-circuit: if S2 score >= 0.95 after completion, cancel remaining stages.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

from agentguard.scoring.engine import TriageEngine
from agentguard.scoring.model import StageScores, TriageResult, TriageVerdict
from agentguard.stages.base import StageInput
from agentguard.stages.stage1_identity import Stage1IdentityGate
from agentguard.stages.stage2_signatures import Stage2Signatures
from agentguard.stages.stage3_opa import Stage3OPA
from agentguard.stages.stage4_rag import Stage4RAG
from agentguard.stages.stage5_behavioral import Stage5Behavioral


class TriagePipeline:
    """Full 5-stage triage pipeline with concurrency."""

    def __init__(
        self,
        stage1: Optional[Stage1IdentityGate] = None,
        stage2: Optional[Stage2Signatures] = None,
        stage3: Optional[Stage3OPA] = None,
        stage4: Optional[Stage4RAG] = None,
        stage5: Optional[Stage5Behavioral] = None,
    ) -> None:
        self._s1 = stage1 or Stage1IdentityGate(registry=None)
        self._s2 = stage2 or Stage2Signatures()
        self._s3 = stage3
        self._s4 = stage4
        self._s5 = stage5
        self._engine = TriageEngine()

    async def evaluate(
        self,
        inp: StageInput,
        reversibility: Optional[str] = None,
        isolation_floor: Optional[str] = None,
    ) -> TriageResult:
        t0 = time.monotonic()

        # ── Stage 1: binary hard gate ────────────────────────────────────────
        s1_output = await self._s1.run(inp)
        if not s1_output.metadata.get("passed", False):
            result = TriageEngine.score_stage1_failure()
            result.latency_ms = (time.monotonic() - t0) * 1000
            return result

        # ── Stages 2–5 concurrent ────────────────────────────────────────────
        tasks = {}
        tasks["s2"] = asyncio.create_task(self._s2.run(inp))

        if self._s3:
            tasks["s3"] = asyncio.create_task(self._s3.run(inp))
        if self._s4:
            tasks["s4"] = asyncio.create_task(self._s4.run(inp))
        if self._s5:
            tasks["s5"] = asyncio.create_task(self._s5.run(inp))

        # Wait for S2 first (needed for short-circuit check)
        s2_output = await tasks["s2"]
        s2_score = s2_output.score if s2_output.available else None

        # Short-circuit check: if S2 is certain, cancel remaining
        from agentguard.scoring.engine import SHORT_CIRCUIT_THRESHOLD
        if s2_score is not None and s2_score >= SHORT_CIRCUIT_THRESHOLD:
            for name, task in tasks.items():
                if name != "s2":
                    task.cancel()
            scores = StageScores(
                s1_passed=True,
                s2=s2_score,
                s3=None, s4=None, s5=None,
            )
            result = self._engine.score(
                scores, reversibility=reversibility, isolation_floor=isolation_floor
            )
            result.latency_ms = (time.monotonic() - t0) * 1000
            return result

        # Wait for remaining stages
        s3_score = s4_score = s5_score = None
        if "s3" in tasks:
            s3_out = await tasks["s3"]
            s3_score = s3_out.score if s3_out.available else None
        if "s4" in tasks:
            s4_out = await tasks["s4"]
            s4_score = s4_out.score if s4_out.available else None
        if "s5" in tasks:
            s5_out = await tasks["s5"]
            s5_score = s5_out.score if s5_out.available else None

        scores = StageScores(
            s1_passed=True,
            s2=s2_score,
            s3=s3_score,
            s4=s4_score,
            s5=s5_score,
        )
        result = self._engine.score(
            scores, reversibility=reversibility, isolation_floor=isolation_floor
        )
        result.latency_ms = (time.monotonic() - t0) * 1000
        return result
