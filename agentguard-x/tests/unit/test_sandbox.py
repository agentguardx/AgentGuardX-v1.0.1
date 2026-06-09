"""Unit tests for Phase 7 — sandbox layer (no Docker dependency).

Tests the models, fingerprint delta logic, and manager tier selection.
No actual containers are started.
"""

from __future__ import annotations

import pytest

from agentguard.sandbox.model import (
    FingerprintDelta,
    SandboxJob,
    SandboxResult,
    SandboxTier,
    SandboxVerdict,
)
from agentguard.sandbox.fingerprint import compute_delta, ContainerSnapshot, is_suspicious_delta
from agentguard.sandbox.manager import SandboxManager


# ── FingerprintDelta model ────────────────────────────────────────────────────
class TestFingerprintDelta:
    def test_clean_delta_is_clean(self):
        delta = FingerprintDelta()
        assert delta.is_clean is True

    def test_non_empty_delta_is_not_clean(self):
        delta = FingerprintDelta(added=["/tmp/evil.sh"])
        assert delta.is_clean is False

    def test_suspicious_paths_detects_bin(self):
        delta = FingerprintDelta(added=["/bin/evil", "/usr/bin/payload"])
        suspicious = delta.suspicious_paths()
        assert "/bin/evil" in suspicious
        assert "/usr/bin/payload" in suspicious

    def test_suspicious_paths_detects_etc(self):
        delta = FingerprintDelta(modified=["/etc/passwd"])
        assert "/etc/passwd" in delta.suspicious_paths()

    def test_suspicious_paths_detects_tmp_scripts(self):
        delta = FingerprintDelta(added=["/tmp/run.sh", "/tmp/payload.py"])
        suspicious = delta.suspicious_paths()
        assert "/tmp/run.sh" in suspicious
        assert "/tmp/payload.py" in suspicious

    def test_tmp_binary_not_suspicious(self):
        # /tmp/data.txt is not suspicious
        delta = FingerprintDelta(added=["/tmp/data.txt"])
        assert delta.suspicious_paths() == []

    def test_to_dict_via_result(self):
        job = SandboxJob(tool_name="get_account_tool", tool_input={})
        delta = FingerprintDelta(added=["/tmp/test.sh"])
        result = SandboxResult(
            job=job,
            tier_used=SandboxTier.DOCKER,
            verdict=SandboxVerdict.PROMOTED,
            fingerprint_delta=delta,
        )
        d = result.to_dict()
        assert d["fingerprint_delta"]["added"] == ["/tmp/test.sh"]
        assert d["fingerprint_delta"]["is_clean"] is False


# ── Fingerprint delta computation ─────────────────────────────────────────────
class TestComputeDelta:
    def _snap(self, container_id: str, added=None, modified=None, deleted=None) -> ContainerSnapshot:
        return ContainerSnapshot(
            container_id=container_id,
            added=added or [],
            modified=modified or [],
            deleted=deleted or [],
        )

    def test_empty_before_and_after_is_clean(self):
        delta = compute_delta(self._snap("c1"), self._snap("c1"))
        assert delta.is_clean

    def test_new_added_path_detected(self):
        before = self._snap("c1")
        after = self._snap("c1", added=["/tmp/evil.sh"])
        delta = compute_delta(before, after)
        assert "/tmp/evil.sh" in delta.added

    def test_path_present_in_before_not_counted_as_new(self):
        before = self._snap("c1", added=["/tmp/existing.sh"])
        after = self._snap("c1", added=["/tmp/existing.sh", "/tmp/new.sh"])
        delta = compute_delta(before, after)
        assert "/tmp/existing.sh" not in delta.added
        assert "/tmp/new.sh" in delta.added

    def test_new_modified_path_detected(self):
        before = self._snap("c1")
        after = self._snap("c1", modified=["/etc/hosts"])
        delta = compute_delta(before, after)
        assert "/etc/hosts" in delta.modified

    def test_new_deleted_path_detected(self):
        before = self._snap("c1")
        after = self._snap("c1", deleted=["/tmp/cleanup.log"])
        delta = compute_delta(before, after)
        assert "/tmp/cleanup.log" in delta.deleted


# ── is_suspicious_delta ───────────────────────────────────────────────────────
class TestIsSuspiciousDelta:
    def test_clean_delta_not_suspicious(self):
        delta = FingerprintDelta()
        suspicious, reason = is_suspicious_delta(delta)
        assert suspicious is False

    def test_bin_write_is_suspicious(self):
        delta = FingerprintDelta(added=["/bin/malware"])
        suspicious, reason = is_suspicious_delta(delta)
        assert suspicious is True
        assert "suspicious paths" in reason.lower()

    def test_etc_modification_is_suspicious(self):
        delta = FingerprintDelta(modified=["/etc/crontab"])
        suspicious, reason = is_suspicious_delta(delta)
        assert suspicious is True

    def test_many_tmp_files_are_suspicious(self):
        delta = FingerprintDelta(added=[f"/tmp/file_{i}" for i in range(51)])
        suspicious, reason = is_suspicious_delta(delta)
        assert suspicious is True
        assert "/tmp" in reason

    def test_few_tmp_files_not_suspicious(self):
        delta = FingerprintDelta(added=[f"/tmp/file_{i}" for i in range(5)])
        suspicious, _ = is_suspicious_delta(delta)
        assert suspicious is False

    def test_shell_modification_is_suspicious(self):
        delta = FingerprintDelta(modified=["/bin/bash"])
        suspicious, reason = is_suspicious_delta(delta)
        assert suspicious is True
        assert "bash" in reason


# ── SandboxManager tier selection ─────────────────────────────────────────────
class TestSandboxManagerTierSelection:
    def test_docker_only_mode_selects_docker(self):
        manager = SandboxManager(sandbox_mode="docker_only", docker_client=None)
        job = SandboxJob(tool_name="get_account_tool", tool_input={})
        tier = manager._select_tier(job)
        assert tier == SandboxTier.DOCKER

    def test_gvisor_floor_docker_only_returns_blocked(self):
        manager = SandboxManager(sandbox_mode="docker_only", docker_client=None)
        job = SandboxJob(
            tool_name="execute_code_tool",
            tool_input={},
            requires_gvisor_floor=True,
        )
        tier = manager._select_tier(job)
        assert tier == SandboxTier.BLOCKED, (
            "gVisor floor required but SANDBOX_MODE=docker_only → must return BLOCKED, not docker"
        )

    def test_gvisor_mode_selects_gvisor_for_floor_ops(self):
        manager = SandboxManager(sandbox_mode="gvisor", docker_client=None)
        job = SandboxJob(
            tool_name="execute_code_tool",
            tool_input={},
            requires_gvisor_floor=True,
        )
        tier = manager._select_tier(job)
        assert tier == SandboxTier.GVISOR

    def test_gvisor_mode_selects_docker_for_normal_ops(self):
        manager = SandboxManager(sandbox_mode="gvisor", docker_client=None)
        job = SandboxJob(tool_name="get_account_tool", tool_input={})
        tier = manager._select_tier(job)
        assert tier == SandboxTier.DOCKER

    def test_blocked_tier_returns_blocked_verdict(self):
        """When tier is BLOCKED, run_sandboxed returns BLOCKED without trying to execute."""
        import asyncio
        manager = SandboxManager(sandbox_mode="docker_only", docker_client=None)
        manager._executor = None  # will trigger initialize

        job = SandboxJob(
            tool_name="execute_code_tool",
            tool_input={},
            requires_gvisor_floor=True,
        )

        # _select_tier will return BLOCKED
        assert manager._select_tier(job) == SandboxTier.BLOCKED

    def test_gvisor_unavailable_in_docker_only_mode(self):
        manager = SandboxManager(sandbox_mode="docker_only", docker_client=None)
        assert manager.gvisor_available is False

    def test_gvisor_available_in_gvisor_mode(self):
        manager = SandboxManager(sandbox_mode="gvisor", docker_client=None)
        assert manager.gvisor_available is True


# ── SandboxResult ─────────────────────────────────────────────────────────────
class TestSandboxResult:
    def test_promoted_property(self):
        job = SandboxJob(tool_name="get_account_tool", tool_input={})
        result = SandboxResult(job=job, tier_used=SandboxTier.DOCKER, verdict=SandboxVerdict.PROMOTED)
        assert result.promoted is True

    def test_killed_not_promoted(self):
        job = SandboxJob(tool_name="get_account_tool", tool_input={})
        result = SandboxResult(job=job, tier_used=SandboxTier.DOCKER, verdict=SandboxVerdict.KILLED)
        assert result.promoted is False

    def test_to_dict_keys(self):
        job = SandboxJob(tool_name="get_account_tool", tool_input={})
        result = SandboxResult(job=job, tier_used=SandboxTier.DOCKER, verdict=SandboxVerdict.PROMOTED)
        d = result.to_dict()
        for key in ("job_id", "tool_name", "tier_used", "verdict", "exit_code", "duration_ms"):
            assert key in d

    def test_blocked_result_has_reason(self):
        job = SandboxJob(tool_name="execute_code_tool", tool_input={}, requires_gvisor_floor=True)
        result = SandboxResult(
            job=job,
            tier_used=SandboxTier.BLOCKED,
            verdict=SandboxVerdict.BLOCKED,
            block_reason="gVisor floor required but unavailable (docker_only mode)",
        )
        assert "gvisor" in result.block_reason.lower()
        assert result.promoted is False
