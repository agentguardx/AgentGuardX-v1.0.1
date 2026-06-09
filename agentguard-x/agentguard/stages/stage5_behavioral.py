"""Stage 5 — Behavioral Context (Redis sorted sets).

Weight: 0.15

Per-session sliding window. Detects:
  - Inconsistency with session so far
  - Reconnaissance pattern: config→credentials→topology
  - Scope escalation: read-only→write/execute
  - Anomalous call rate (loop/attack indicator per §7 LLM10)

Per-agent session lock held <3ms.
If Redis unavailable → score=None, no renormalization (fail-closed: more scrutiny).
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Optional

from .base import StageInput, StageOutput, StageRunner

# Reconnaissance kill-chain patterns (tool name substrings, in order)
RECON_SEQUENCES: list[tuple[str, ...]] = [
    ("read_customer_pii", "compress_data", "post_external"),   # exfil kill chain
    ("get_account", "read_customer_pii", "post_external"),     # PII → exfil
    ("run_report", "compress_data", "post_external"),          # report → exfil
    ("fetch_market", "execute_code", "post_external"),         # code → exfil
]

# Tools representing "escalation" transitions
WRITE_TOOLS = frozenset({"transfer_funds", "send_email", "post_external", "execute_code"})
READ_TOOLS = frozenset({"get_account", "query_transactions", "read_customer_pii",
                        "run_report", "fetch_market_data", "compress_data"})

# Rate limit window (calls per 60-second window)
RATE_WINDOW_SECONDS = 60
RATE_LIMIT_MAX = 50  # default; per-agent limits enforced by OPA

# Session window for behavioral analysis (last N calls)
SESSION_WINDOW = 20


class Stage5Behavioral(StageRunner):
    """Redis-backed per-session behavioral analysis."""

    def __init__(self, redis_client=None) -> None:
        self._redis = redis_client

    @property
    def stage_id(self) -> str:
        return "s5_behavioral"

    async def run(self, inp: StageInput) -> StageOutput:
        t0 = time.monotonic()

        if self._redis is None:
            return StageOutput(
                stage_id=self.stage_id, score=None, available=False,
                explanation="Redis unavailable — S5 suspended (fail-closed: score=0, no renorm)",
            )

        try:
            score, explanation, meta = await asyncio.wait_for(
                self._analyze(inp), timeout=0.003  # <3ms lock
            )
        except asyncio.TimeoutError:
            return StageOutput(
                stage_id=self.stage_id, score=None, available=False,
                explanation="Stage 5 timed out (>3ms) — treated as unavailable",
            )
        except Exception as e:
            return StageOutput(
                stage_id=self.stage_id, score=None, available=False,
                explanation=f"Stage 5 error: {e}",
            )

        return StageOutput(
            stage_id=self.stage_id,
            score=score,
            available=True,
            explanation=explanation,
            metadata=meta,
            latency_ms=(time.monotonic() - t0) * 1000,
        )

    async def _analyze(
        self, inp: StageInput
    ) -> tuple[float, str, dict]:
        session_key = f"agentguard:session:{inp.session_id}"
        rate_key = f"agentguard:rate:{inp.agent_id}"
        now_ms = int(time.time() * 1000)
        window_start = now_ms - RATE_WINDOW_SECONDS * 1000

        # ── 1. Record current call ────────────────────────────────────────────
        entry = json.dumps({
            "tool": inp.tool_name,
            "ts_ms": now_ms,
            "session_id": inp.session_id,
        })
        pipe = self._redis.pipeline()
        pipe.zadd(session_key, {entry: now_ms})
        pipe.expire(session_key, 7200)
        pipe.zadd(rate_key, {str(now_ms): now_ms})
        pipe.zremrangebyscore(rate_key, 0, window_start)
        pipe.expire(rate_key, RATE_WINDOW_SECONDS * 2)
        await asyncio.to_thread(pipe.execute)

        # ── 2. Retrieve session history ───────────────────────────────────────
        raw_entries = await asyncio.to_thread(
            self._redis.zrange, session_key, -SESSION_WINDOW, -1
        )
        history = []
        for raw in raw_entries:
            try:
                rec = json.loads(raw)
                history.append(rec.get("tool", ""))
            except Exception:
                pass

        # ── 3. Rate limit check ───────────────────────────────────────────────
        rate_count = await asyncio.to_thread(
            self._redis.zcount, rate_key, window_start, now_ms
        )
        if rate_count > RATE_LIMIT_MAX:
            return (
                0.80,
                f"Anomalous call rate: {rate_count} calls in {RATE_WINDOW_SECONDS}s window",
                {"rate_count": rate_count, "rate_limit": RATE_LIMIT_MAX},
            )

        # ── 4. Kill-chain / recon detection ───────────────────────────────────
        recent = history[-10:] + [inp.tool_name]  # include current call

        for chain in RECON_SEQUENCES:
            if _sequence_present(recent, chain):
                return (
                    0.90,
                    f"Kill-chain detected: {' → '.join(chain)}",
                    {"kill_chain": list(chain), "history": recent},
                )

        # ── 5. Scope escalation: read→write within session ────────────────────
        prior_ops = set(history[-5:])
        had_only_reads = prior_ops and prior_ops.issubset(READ_TOOLS)
        is_write_now = inp.tool_name in WRITE_TOOLS
        if had_only_reads and is_write_now:
            return (
                0.65,
                f"Scope escalation: read-only session → write/execute tool '{inp.tool_name}'",
                {"prior_tools": list(prior_ops), "current_tool": inp.tool_name},
            )

        # ── 6. Normal / benign ────────────────────────────────────────────────
        score = 0.05 + min(0.15, len(history) * 0.005)  # small baseline noise
        return score, f"Behavioral: {len(history)} calls in session, no anomaly", {}


def _sequence_present(history: list[str], chain: tuple[str, ...]) -> bool:
    """Check if chain appears as a subsequence in history (order matters, not contiguous)."""
    chain_idx = 0
    for tool in history:
        if chain_idx < len(chain) and chain[chain_idx] in tool:
            chain_idx += 1
        if chain_idx == len(chain):
            return True
    return False
