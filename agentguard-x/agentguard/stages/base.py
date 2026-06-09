"""Common interface for all triage stages."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class StageInput:
    """Normalized input fed to every stage."""
    request_id: str
    session_id: str
    agent_id: str
    agent_role: str
    tool_name: str
    tool_input: dict[str, Any]
    # Full serialized request payload (for signature + RAG scanning)
    raw_payload: str
    # Tool output (populated in post-hook / response path)
    tool_output: Optional[str] = None
    # Per-agent declared envelope (from registry)
    declared_tools: list[str] = field(default_factory=list)
    # Context passed from Stage 1
    identity_claims: dict[str, Any] = field(default_factory=dict)


@dataclass
class StageOutput:
    """Output from a single stage."""
    stage_id: str
    score: Optional[float]      # None = stage unavailable; do NOT renormalize
    available: bool = True
    explanation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0


class StageRunner(abc.ABC):
    """Abstract base for all triage stages.

    Each stage must:
    - Return StageOutput with score in [0.0, 1.0] or score=None if unavailable.
    - NEVER raise exceptions that escape to the caller (catch internally, return score=None).
    - Be safe to call concurrently (stages 2–5 run concurrently after stage 1).
    """

    @property
    @abc.abstractmethod
    def stage_id(self) -> str:
        ...

    @abc.abstractmethod
    async def run(self, inp: StageInput) -> StageOutput:
        ...
