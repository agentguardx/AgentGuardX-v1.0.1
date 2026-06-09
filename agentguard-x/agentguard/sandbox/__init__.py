"""Sandbox layer — Phase 7.

Two tiers (Docker and gVisor). gVisor requires KVM; unavailable on WSL2 by default.
When gVisor floor is required but SANDBOX_MODE=docker_only → BLOCKED (not downgraded).

Usage:
    manager = SandboxManager.from_env()
    result = await manager.run_sandboxed(job)
"""

from .model import SandboxJob, SandboxResult, SandboxTier, SandboxVerdict
from .manager import SandboxManager

__all__ = [
    "SandboxJob",
    "SandboxResult",
    "SandboxTier",
    "SandboxVerdict",
    "SandboxManager",
]
