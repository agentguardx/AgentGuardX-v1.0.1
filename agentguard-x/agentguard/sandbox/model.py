"""Sandbox data models — Phase 7."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class SandboxTier(str, Enum):
    DOCKER = "docker"
    GVISOR = "gvisor"
    BLOCKED = "blocked"  # gVisor required but unavailable (WSL2 default)


class SandboxVerdict(str, Enum):
    PROMOTED = "promoted"    # Result looks benign; side-effects accepted
    KILLED = "killed"        # Result suspicious; container destroyed, result discarded
    BLOCKED = "blocked"      # Could not sandbox (gVisor floor, unavailable tier)
    ERROR = "error"          # Unexpected executor error


@dataclass
class SandboxJob:
    """A single sandboxed execution request."""
    tool_name: str
    tool_input: dict[str, Any]
    session_id: str = ""
    agent_id: str = "unknown"
    agent_role: str = "research"
    requires_gvisor_floor: bool = False
    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.monotonic)


@dataclass
class FingerprintDelta:
    """Changes detected in the sandbox container between baseline and post-execution."""
    added: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not (self.added or self.modified or self.deleted)

    def suspicious_paths(self) -> list[str]:
        """Return paths that are suspicious (writes to /bin, /usr, /etc, /tmp execs)."""
        suspicious = []
        for path in self.added + self.modified:
            if any(path.startswith(prefix) for prefix in ("/bin/", "/usr/bin/", "/etc/", "/sbin/")):
                suspicious.append(path)
            if path.startswith("/tmp/") and (path.endswith(".sh") or path.endswith(".py")):
                suspicious.append(path)
        return suspicious


@dataclass
class SandboxResult:
    """Result from a sandboxed tool execution."""
    job: SandboxJob
    tier_used: SandboxTier
    verdict: SandboxVerdict
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    fingerprint_delta: Optional[FingerprintDelta] = None
    block_reason: Optional[str] = None
    container_id: Optional[str] = None
    duration_ms: float = 0.0

    @property
    def promoted(self) -> bool:
        return self.verdict == SandboxVerdict.PROMOTED

    def to_dict(self) -> dict:
        return {
            "job_id": self.job.job_id,
            "tool_name": self.job.tool_name,
            "tier_used": self.tier_used.value,
            "verdict": self.verdict.value,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "block_reason": self.block_reason,
            "duration_ms": self.duration_ms,
            "fingerprint_delta": {
                "added": self.fingerprint_delta.added if self.fingerprint_delta else [],
                "modified": self.fingerprint_delta.modified if self.fingerprint_delta else [],
                "deleted": self.fingerprint_delta.deleted if self.fingerprint_delta else [],
                "is_clean": self.fingerprint_delta.is_clean if self.fingerprint_delta else True,
            } if self.fingerprint_delta else None,
        }
