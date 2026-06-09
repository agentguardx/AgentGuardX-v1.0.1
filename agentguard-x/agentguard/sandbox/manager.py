"""Sandbox manager — Phase 7 top-level entry point.

Reads SANDBOX_MODE from the capability report (set by agentguard.sh preflight).
Applies host-capability degradation:
  - SANDBOX_MODE=gvisor   → Docker pool + gVisor pool both available
  - SANDBOX_MODE=docker_only → Docker pool only. gVisor-floor ops → BLOCKED.

Public API:
    manager = SandboxManager.from_env()
    await manager.initialize()
    result = await manager.run_sandboxed(job)
    await manager.shutdown()
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

from .executor import SandboxExecutor
from .model import SandboxJob, SandboxResult, SandboxTier, SandboxVerdict
from .pool import ContainerPool

logger = logging.getLogger("agentguard.sandbox.manager")


class SandboxManager:
    """Manages pre-warmed container pools and routes jobs to the correct tier."""

    def __init__(
        self,
        sandbox_mode: str = "docker_only",
        docker_client=None,
    ) -> None:
        self._sandbox_mode = sandbox_mode
        self._client = docker_client
        self._gvisor_available = (sandbox_mode == "gvisor")

        # Pools (None if tier unavailable)
        self._docker_pool: Optional[ContainerPool] = None
        self._gvisor_pool: Optional[ContainerPool] = None
        self._executor: Optional[SandboxExecutor] = None

    @classmethod
    def from_env(cls) -> "SandboxManager":
        """Construct from environment. docker_client is imported lazily."""
        sandbox_mode = os.getenv("AGENTGUARD_SANDBOX_MODE", "docker_only")
        try:
            import docker
            client = docker.from_env()
        except Exception:
            logger.warning("Docker SDK unavailable — sandbox will run in degraded mode")
            client = None
        return cls(sandbox_mode=sandbox_mode, docker_client=client)

    async def initialize(self) -> None:
        """Pre-warm container pools. Called once at startup."""
        if self._client is None:
            logger.warning("No Docker client — sandbox pools not initialized")
            self._executor = SandboxExecutor(pool=None, docker_client=None)
            return

        # Always create Docker pool
        self._docker_pool = ContainerPool(
            tier=SandboxTier.DOCKER,
            docker_client=self._client,
        )
        await self._docker_pool.initialize()

        # gVisor pool only when KVM is available
        if self._gvisor_available:
            self._gvisor_pool = ContainerPool(
                tier=SandboxTier.GVISOR,
                docker_client=self._client,
            )
            await self._gvisor_pool.initialize()
        else:
            logger.info(
                "SANDBOX_MODE=%s: gVisor pool not initialized. "
                "gVisor-floor operations will be BLOCKED (not downgraded).",
                self._sandbox_mode,
            )

        # Executor gets the pool for the default tier
        self._executor = SandboxExecutor(
            pool=self._docker_pool,
            docker_client=self._client,
        )
        logger.info("SandboxManager ready. mode=%s gvisor=%s", self._sandbox_mode, self._gvisor_available)

    async def run_sandboxed(self, job: SandboxJob) -> SandboxResult:
        """Execute job in the appropriate sandbox tier.

        Tier selection:
          - requires_gvisor_floor=True AND gVisor available → gVisor tier
          - requires_gvisor_floor=True AND gVisor unavailable → BLOCKED (not downgraded)
          - otherwise → Docker tier
        """
        if self._executor is None:
            await self.initialize()

        tier = self._select_tier(job)

        if tier == SandboxTier.BLOCKED:
            logger.warning(
                "SANDBOX_BLOCKED job=%s tool=%s reason=gvisor_floor_required",
                job.job_id, job.tool_name,
            )
            return SandboxResult(
                job=job,
                tier_used=SandboxTier.BLOCKED,
                verdict=SandboxVerdict.BLOCKED,
                block_reason=(
                    f"Tool '{job.tool_name}' requires gVisor isolation floor, "
                    "but SANDBOX_MODE=docker_only (WSL2 default). "
                    "Operation BLOCKED — never downgraded."
                ),
            )

        # Use gVisor executor if needed
        executor = self._executor
        if tier == SandboxTier.GVISOR and self._gvisor_pool:
            executor = SandboxExecutor(
                pool=self._gvisor_pool,
                docker_client=self._client,
            )

        return await executor.execute(job, tier)

    async def shutdown(self) -> None:
        """Drain all pools and release containers."""
        if self._docker_pool:
            await self._docker_pool.drain()
        if self._gvisor_pool:
            await self._gvisor_pool.drain()
        logger.info("SandboxManager shutdown complete.")

    def _select_tier(self, job: SandboxJob) -> SandboxTier:
        if job.requires_gvisor_floor:
            if self._gvisor_available:
                return SandboxTier.GVISOR
            # gVisor unavailable → BLOCK (not downgrade)
            return SandboxTier.BLOCKED
        return SandboxTier.DOCKER

    @property
    def gvisor_available(self) -> bool:
        return self._gvisor_available

    @property
    def sandbox_mode(self) -> str:
        return self._sandbox_mode
