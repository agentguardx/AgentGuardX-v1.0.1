"""Triage scoring data model — pure dataclasses, no external dependencies."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class TriageVerdict(str, Enum):
    """Terminal verdict for a triage decision."""
    ALLOW = "allow"                      # R < 0.25
    GREY_BAND = "grey_band"              # 0.25 <= R <= 0.85
    BLOCK = "block"                      # R > 0.85 OR short-circuit
    BLOCK_SHORT_CIRCUIT = "block_short_circuit"  # S2 >= SHORT_CIRCUIT_THRESHOLD
    BLOCK_STAGE1 = "block_stage1"        # Stage 1 hard gate failure


class RouteDecision(str, Enum):
    """Routing instruction produced by the grey-band router."""
    FAST_PATH = "fast_path"              # ALLOW verdict
    SANDBOX_ASYNC = "sandbox_async"      # Replayable op in grey band
    HOLD_SYNC = "hold_sync"              # Irreversible op in grey band
    BLOCKED = "blocked"                  # BLOCK verdict
    STAGE1_GATE = "stage1_gate"          # Stage 1 failure


@dataclass
class StageScores:
    """Sub-scores from each triage stage.

    Each score is in [0.0, 1.0].
    None means the stage was unavailable (e.g. Redis down for S5).
    An unavailable stage contributes score=0.0 and does NOT vote.
    Weights are NEVER renormalized — a missing stage can only lower R,
    never raise it or cause misrouting toward allow.
    """
    s1_passed: bool = True               # S1 is binary — not scored
    s2: Optional[float] = None           # Signature matching (weight 0.35)
    s3: Optional[float] = None           # OPA policy (weight 0.30)
    s4: Optional[float] = None           # Semantic RAG (weight 0.20)
    s5: Optional[float] = None           # Behavioral context (weight 0.15)

    def effective_s2(self) -> float:
        return self.s2 if self.s2 is not None else 0.0

    def effective_s3(self) -> float:
        return self.s3 if self.s3 is not None else 0.0

    def effective_s4(self) -> float:
        return self.s4 if self.s4 is not None else 0.0

    def effective_s5(self) -> float:
        return self.s5 if self.s5 is not None else 0.0


@dataclass
class TriageResult:
    """Complete result from the triage engine for one request."""
    # Input scores
    scores: StageScores

    # Intermediate values (for observability + explainability)
    base: float = 0.0
    k: int = 0                           # number of voting stages
    a_bar: float = 0.0                   # mean score of voting stages
    corroboration_bonus: float = 0.0
    r: float = 0.0                       # final composite risk score [0,1]

    # Decision
    verdict: TriageVerdict = TriageVerdict.ALLOW
    route: RouteDecision = RouteDecision.FAST_PATH

    # Explanation
    triggered_stages: list[str] = field(default_factory=list)
    block_reason: Optional[str] = None
    short_circuited: bool = False

    # Detection attribution (Phase 5 observability) — set by the pipeline from
    # Stage 2's winning detector. None when nothing triggered.
    detection_category: Optional[str] = None   # injection|concealment|egress|value|entropy|code|killchain
    detection_reason: Optional[str] = None     # human-readable trigger text

    # Performance
    latency_ms: float = 0.0
