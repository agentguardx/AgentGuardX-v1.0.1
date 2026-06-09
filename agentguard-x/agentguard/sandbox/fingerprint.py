"""Container filesystem fingerprinting — Phase 7.

Uses Docker's container.diff() API which returns a list of changed paths
(Added/Modified/Deleted) since the container was created from its image.

Fingerprint workflow:
  1. baseline()  — snapshot container diff at job start (should be empty or minimal)
  2. capture()   — snapshot after execution
  3. delta()     — set-difference between the two snapshots

A container that downloads and stages a payload will show Added paths in
/tmp/ or mutated system directories. That triggers KILL in promote_or_kill().

The Docker diff API uses change type codes:
  0 = Modified
  1 = Added
  2 = Deleted
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("agentguard.sandbox.fingerprint")

# Docker diff change type constants
_MODIFIED = 0
_ADDED = 1
_DELETED = 2


@dataclass
class ContainerSnapshot:
    """Raw snapshot of Docker container.diff() output."""
    container_id: str
    added: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)


def take_snapshot(container) -> ContainerSnapshot:
    """Take a filesystem snapshot of a running container using Docker diff API.

    Args:
        container: docker.models.containers.Container instance

    Returns:
        ContainerSnapshot with current diff vs. image baseline.
    """
    added: list[str] = []
    modified: list[str] = []
    deleted: list[str] = []

    try:
        diffs = container.diff() or []
        for entry in diffs:
            kind = entry.get("Kind", -1)
            path = entry.get("Path", "")
            if kind == _ADDED:
                added.append(path)
            elif kind == _MODIFIED:
                modified.append(path)
            elif kind == _DELETED:
                deleted.append(path)
    except Exception as exc:
        logger.warning("container.diff() failed for %s: %s", container.id[:12], exc)

    return ContainerSnapshot(
        container_id=container.id,
        added=added,
        modified=modified,
        deleted=deleted,
    )


def compute_delta(
    before: ContainerSnapshot,
    after: ContainerSnapshot,
) -> "FingerprintDelta":
    """Compute the delta between two snapshots.

    Returns paths that changed BETWEEN before and after
    (i.e., new changes introduced by the sandboxed execution).
    """
    from .model import FingerprintDelta

    before_added = set(before.added)
    before_modified = set(before.modified)
    before_deleted = set(before.deleted)

    new_added = [p for p in after.added if p not in before_added]
    new_modified = [p for p in after.modified if p not in before_modified]
    new_deleted = [p for p in after.deleted if p not in before_deleted]

    return FingerprintDelta(
        added=new_added,
        modified=new_modified,
        deleted=new_deleted,
    )


def is_suspicious_delta(delta: "FingerprintDelta") -> tuple[bool, str]:
    """Assess whether a fingerprint delta indicates malicious activity.

    Returns (suspicious: bool, reason: str).
    """
    suspicious_paths = delta.suspicious_paths()
    if suspicious_paths:
        return True, f"Sandbox wrote to suspicious paths: {suspicious_paths[:5]}"

    # More than 50 new files in /tmp → likely staging area
    tmp_files = [p for p in delta.added if p.startswith("/tmp/")]
    if len(tmp_files) > 50:
        return True, f"Sandbox created {len(tmp_files)} files in /tmp"

    # Any modification to interpreter or shell binaries
    shell_paths = ["/bin/bash", "/bin/sh", "/usr/bin/python", "/usr/bin/python3"]
    for path in delta.modified:
        if path in shell_paths:
            return True, f"Sandbox modified shell/interpreter: {path}"

    return False, ""
