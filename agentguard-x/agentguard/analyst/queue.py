"""Analyst hold queue — in-memory store for pending grey-band holds.

Lifecycle of a hold:
  1. Hook calls HoldQueue.submit() → returns hold_id and HoldRecord (status=PENDING).
  2. Analyst UI at /holds shows pending holds.
  3. Analyst POSTs /holds/{id}/approve or /holds/{id}/reject.
  4. Background reaper runs every 5s; expired holds → EXPIRED (treated as BLOCK).

INVARIANT: EXPIRED == BLOCK. Timeout never becomes allow-on-timeout.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class HoldStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"   # timeout → BLOCK (fail-closed)


@dataclass
class HoldRecord:
    hold_id: str
    agent_id: str
    agent_role: str
    tool_name: str
    r_score: float
    session_id: str
    raw_payload: str
    operation_value_usd: float
    timeout_seconds: int
    created_at: float = field(default_factory=time.monotonic)
    status: HoldStatus = HoldStatus.PENDING
    analyst_note: str = ""
    resolved_at: Optional[float] = None

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.created_at

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.timeout_seconds - self.elapsed_seconds)

    @property
    def is_expired(self) -> bool:
        return self.elapsed_seconds >= self.timeout_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "hold_id": self.hold_id,
            "agent_id": self.agent_id,
            "agent_role": self.agent_role,
            "tool_name": self.tool_name,
            "r_score": round(self.r_score, 4),
            "session_id": self.session_id,
            "operation_value_usd": self.operation_value_usd,
            "timeout_seconds": self.timeout_seconds,
            "remaining_seconds": round(self.remaining_seconds, 1),
            "status": self.status.value,
            "analyst_note": self.analyst_note,
        }


class HoldQueue:
    """Thread-safe in-memory hold queue with auto-expiry."""

    def __init__(self) -> None:
        self._holds: dict[str, HoldRecord] = {}
        self._lock = asyncio.Lock()

    async def submit(
        self,
        agent_id: str,
        agent_role: str,
        tool_name: str,
        r_score: float,
        session_id: str = "",
        raw_payload: str = "",
        operation_value_usd: float = 0.0,
        timeout_seconds: int = 300,
    ) -> HoldRecord:
        hold = HoldRecord(
            hold_id=str(uuid.uuid4()),
            agent_id=agent_id,
            agent_role=agent_role,
            tool_name=tool_name,
            r_score=r_score,
            session_id=session_id,
            raw_payload=raw_payload,
            operation_value_usd=operation_value_usd,
            timeout_seconds=timeout_seconds,
        )
        async with self._lock:
            self._holds[hold.hold_id] = hold
        return hold

    async def get(self, hold_id: str) -> Optional[HoldRecord]:
        async with self._lock:
            return self._holds.get(hold_id)

    async def resolve(
        self,
        hold_id: str,
        status: HoldStatus,
        analyst_note: str = "",
    ) -> Optional[HoldRecord]:
        async with self._lock:
            hold = self._holds.get(hold_id)
            if hold is None or hold.status != HoldStatus.PENDING:
                return None
            hold.status = status
            hold.analyst_note = analyst_note
            hold.resolved_at = time.monotonic()
            return hold

    async def list_pending(self) -> list[HoldRecord]:
        async with self._lock:
            return [h for h in self._holds.values() if h.status == HoldStatus.PENDING]

    async def list_all(self) -> list[HoldRecord]:
        async with self._lock:
            return sorted(self._holds.values(), key=lambda h: h.created_at, reverse=True)

    async def expire_stale(self) -> int:
        """Mark all expired PENDING holds as EXPIRED. Returns count expired."""
        count = 0
        async with self._lock:
            for hold in self._holds.values():
                if hold.status == HoldStatus.PENDING and hold.is_expired:
                    hold.status = HoldStatus.EXPIRED
                    hold.analyst_note = "Auto-expired (timeout) → BLOCK (fail-closed)"
                    hold.resolved_at = time.monotonic()
                    count += 1
        return count

    async def pending_count(self) -> int:
        async with self._lock:
            return sum(1 for h in self._holds.values() if h.status == HoldStatus.PENDING)


# Module-level singleton used by the FastAPI service
_queue: Optional[HoldQueue] = None


def get_hold_queue() -> HoldQueue:
    global _queue
    if _queue is None:
        _queue = HoldQueue()
    return _queue
