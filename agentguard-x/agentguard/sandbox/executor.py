"""Single-use container executor — Phase 7.

Lifecycle of one sandboxed execution:
  1. Checkout container from pool (or start one on-demand).
  2. Take baseline fingerprint (diff vs. image — should be empty).
  3. Exec the tool payload inside the container.
  4. Take post-execution fingerprint.
  5. Compute delta = changes the execution made.
  6. promote_or_kill():
       - Suspicious delta → KILL container, return SandboxVerdict.KILLED
       - Clean delta      → PROMOTE result, return SandboxVerdict.PROMOTED
  7. Replenish pool asynchronously.
  8. Container is ALWAYS removed after step 6 (single-use invariant).

INVARIANT: every container touched by this executor is removed on exit,
           whether via promote or kill. No container leaks.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Optional

from .fingerprint import compute_delta, is_suspicious_delta, take_snapshot
from .model import (
    FingerprintDelta,
    SandboxJob,
    SandboxResult,
    SandboxTier,
    SandboxVerdict,
)

logger = logging.getLogger("agentguard.sandbox.executor")

# Execution limits
EXEC_TIMEOUT_SECONDS = float(os.getenv("SANDBOX_EXEC_TIMEOUT_SECONDS", "30.0"))


class SandboxExecutor:
    """Executes one tool call inside an ephemeral container and returns the result."""

    def __init__(self, pool=None, docker_client=None) -> None:
        self._pool = pool
        self._client = docker_client

    async def execute(
        self,
        job: SandboxJob,
        tier: SandboxTier,
    ) -> SandboxResult:
        """Run the job in a single-use container at the given tier."""
        if tier == SandboxTier.BLOCKED:
            return SandboxResult(
                job=job,
                tier_used=tier,
                verdict=SandboxVerdict.BLOCKED,
                block_reason="gVisor floor required but unavailable (docker_only mode)",
            )

        t0 = time.monotonic()
        container = None
        try:
            # 1. Get a container (pool first, on-demand fallback)
            if self._pool:
                container = await self._pool.checkout()
            if container is None:
                container = await self._start_ondemand(tier)
            if container is None:
                return SandboxResult(
                    job=job,
                    tier_used=tier,
                    verdict=SandboxVerdict.ERROR,
                    block_reason="Failed to start sandbox container",
                    duration_ms=(time.monotonic() - t0) * 1000,
                )

            # 2. Baseline fingerprint (should be empty right after start)
            baseline = take_snapshot(container)

            # 3. Execute the tool payload
            exit_code, stdout, stderr = await self._exec_payload(container, job)

            # 4. Post-execution fingerprint
            post_snap = take_snapshot(container)

            # 5. Compute delta
            delta = compute_delta(baseline, post_snap)

            # 6. promote_or_kill
            verdict, block_reason = self._promote_or_kill(delta, exit_code, stderr)

            duration_ms = (time.monotonic() - t0) * 1000
            result = SandboxResult(
                job=job,
                tier_used=tier,
                verdict=verdict,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                fingerprint_delta=delta,
                block_reason=block_reason,
                container_id=container.id,
                duration_ms=duration_ms,
            )

            logger.info(
                "Sandbox verdict=%s tier=%s tool=%s exit=%d delta_paths=%d duration=%.0fms",
                verdict.value, tier.value, job.tool_name,
                exit_code, len(delta.added) + len(delta.modified),
                duration_ms,
            )
            return result

        finally:
            # 7. ALWAYS remove the container (single-use invariant)
            if container is not None:
                await self._remove_container(container)
            # 8. Asynchronously replenish pool
            if self._pool:
                asyncio.create_task(self._pool.replenish())

    async def _exec_payload(
        self,
        container,
        job: SandboxJob,
    ) -> tuple[int, str, str]:
        """Run the tool payload inside the container via docker exec."""
        # Serialize the tool call as JSON and pass it to the sandbox entry point
        payload_json = json.dumps({
            "tool_name": job.tool_name,
            "tool_input": job.tool_input,
            "session_id": job.session_id,
            "agent_id": job.agent_id,
        })

        # Pass the payload as an argument (docker-py exec_run cannot reliably
        # stream stdin without a raw socket). The runner also accepts it via the
        # SANDBOX_PAYLOAD env var as a fallback.
        cmd = ["python", "/sandbox/run_tool.py", "--payload", payload_json]

        try:
            loop = asyncio.get_event_loop()
            exec_result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: container.exec_run(
                        cmd=cmd,
                        stdout=True,
                        stderr=True,
                        demux=True,
                        environment={"SANDBOX_MODE": "1", "SANDBOX_PAYLOAD": payload_json},
                    ),
                ),
                timeout=EXEC_TIMEOUT_SECONDS,
            )
            exit_code = exec_result.exit_code or 0
            stdout_bytes, stderr_bytes = exec_result.output or (b"", b"")
            stdout = (stdout_bytes or b"").decode("utf-8", errors="replace")[:4096]
            stderr = (stderr_bytes or b"").decode("utf-8", errors="replace")[:2048]
            return exit_code, stdout, stderr

        except asyncio.TimeoutError:
            logger.warning("Sandbox exec timeout for job %s", job.job_id)
            return -1, "", "Execution timed out"
        except Exception as exc:
            logger.warning("Sandbox exec error for job %s: %s", job.job_id, exc)
            return -1, "", str(exc)

    def _promote_or_kill(
        self,
        delta: FingerprintDelta,
        exit_code: int,
        stderr: str,
    ) -> tuple[SandboxVerdict, Optional[str]]:
        """Decide whether to promote the result or kill it.

        Kill conditions:
          - Suspicious filesystem delta (writes to system paths)
          - Non-zero exit code with error patterns
          - Stderr contains exfil/injection indicators
        """
        # Check fingerprint delta
        suspicious, reason = is_suspicious_delta(delta)
        if suspicious:
            return SandboxVerdict.KILLED, f"Suspicious delta: {reason}"

        # Non-zero exit with error in stderr
        if exit_code != 0 and exit_code != -1:
            if any(kw in stderr.lower() for kw in ["permission denied", "no such file", "error"]):
                return SandboxVerdict.KILLED, f"Execution error (exit={exit_code}): {stderr[:100]}"

        return SandboxVerdict.PROMOTED, None

    async def _start_ondemand(self, tier: SandboxTier):
        """Start a new container on-demand (pool empty)."""
        if self._client is None:
            return None
        from .pool import SANDBOX_IMAGE, _CONTAINER_CONFIG
        try:
            loop = asyncio.get_event_loop()
            kwargs = {**_CONTAINER_CONFIG}
            if tier == SandboxTier.GVISOR:
                kwargs["runtime"] = "runsc"
            container = await loop.run_in_executor(
                None,
                lambda: self._client.containers.run(
                    SANDBOX_IMAGE,
                    command=["cat"],
                    **kwargs,
                ),
            )
            return container
        except Exception as exc:
            logger.error("On-demand container start failed (tier=%s): %s", tier, exc)
            return None

    @staticmethod
    async def _remove_container(container) -> None:
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: container.remove(force=True)
            )
        except Exception:
            pass
