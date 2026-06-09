"""Analyst Hold Queue — Phase 10.

Manages synchronous holds for irreversible grey-band operations.
Analysts approve or reject via the queue UI at port 8083.
Holds that expire (timeout) → BLOCK automatically (fail-closed).
"""

from .queue import HoldQueue, HoldRecord, HoldStatus

__all__ = ["HoldQueue", "HoldRecord", "HoldStatus"]
