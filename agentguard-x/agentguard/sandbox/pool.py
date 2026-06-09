"""Pre-warmed container pool — Phase 7.

Maintains a pool of idle containers ready to accept sandbox jobs.
Each container is single-use: checked out → used → destroyed.
A background replenisher adds a fresh container whenever one is consumed.

Pool design:
  - Tier-aware: separate pool per SandboxTier.
  - POOL_SIZE warm containers per tier (default 2).
  - Checkout is atomic (asyncio.Queue for no-wait allocation).
  - Containers that fail health checks are discarded silently.
  - Pool is optional: SandboxExecutor can start on-demand if pool is empty.

The Docker runtime handle is injected at construction so the pool itself
has no docker dependency in tests.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

from .model import SandboxTier

logger = logging.getLogger("agentguard.sandbox.pool")

POOL_SIZE = int(os.getenv("SANDBOX_POOL_SIZE", "2"))
SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "agentguard-sandbox:latest")

# Container resource limits (PoC)
_CONTAINER_CONFIG = {
    "mem_limit": "128m",
    "memswap_limit": "128m",
    "cpu_period": 100_000,
    "cpu_quota": 50_000,    # 50% of 1 core
    "network_mode": "none", # Sandboxed containers have NO network
    "read_only": False,     # Allow writes for fingerprint detection
    "auto_remove": False,   # We handle removal ourselves
    "detach": True,
    "tty": False,
    "stdin_open": True,     # Keep alive for exec
}


class ContainerPool:
    """Pre-warmed pool for a single sandbox tier (Docker or gVisor)."""

    def __init__(
        self,
        tier: SandboxTier,
        docker_client=None,
        pool_size: int = POOL_SIZE,
    ) -> None:
        self._tier = tier
        self._client = docker_client
        self._pool_size = pool_size
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=pool_size)
        self._initialized = False

    async def initialize(self) -> None:
        """Pre-warm pool_size containers."""
        if self._initialized:
            return
        if self._client is None:
            logger.warning("No Docker client — pool for %s will run on-demand only", self._tier)
            self._initialized = True
            return

        logger.info("Pre-warming %d container(s) for tier=%s", self._pool_size, self._tier)
        for _ in range(self._pool_size):
            container = await self._start_container()
            if container is not None:
                await self._queue.put(container)
        self._initialized = True
        logger.info("Pool ready: %d/%d containers warm (tier=%s)",
                    self._queue.qsize(), self._pool_size, self._tier)

    async def checkout(self, timeout_seconds: float = 2.0):
        """Return a warm container, or None if pool is empty."""
        try:
            return self._queue.get_nowait()
        except asyncio.QueueEmpty:
            # Start on-demand if pool is empty
            logger.debug("Pool empty for %s — starting on-demand container", self._tier)
            return await self._start_container()

    async def replenish(self) -> None:
        """Start a new container to replace one that was consumed."""
        if self._queue.qsize() < self._pool_size:
            container = await self._start_container()
            if container is not None:
                try:
                    self._queue.put_nowait(container)
                except asyncio.QueueFull:
                    await self._kill_container(container)

    async def drain(self) -> None:
        """Destroy all warm containers (called on shutdown)."""
        while not self._queue.empty():
            try:
                container = self._queue.get_nowait()
                await self._kill_container(container)
            except asyncio.QueueEmpty:
                break
        logger.info("Pool drained for tier=%s", self._tier)

    async def _start_container(self) -> Optional[object]:
        """Start a new idle container from the sandbox image."""
        if self._client is None:
            return None
        try:
            runtime = "runsc" if self._tier == SandboxTier.GVISOR else None
            kwargs = {**_CONTAINER_CONFIG}
            if runtime:
                kwargs["runtime"] = runtime
            # Container starts with `cat` (keeps it alive without doing anything)
            container = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._client.containers.run(
                    SANDBOX_IMAGE,
                    command=["cat"],
                    **kwargs,
                ),
            )
            logger.debug("Started warm container %s (tier=%s)", container.id[:12], self._tier)
            return container
        except Exception as exc:
            logger.warning("Failed to start warm container (tier=%s): %s", self._tier, exc)
            return None

    @staticmethod
    async def _kill_container(container) -> None:
        """Force-remove a container silently."""
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: container.remove(force=True)
            )
        except Exception:
            pass
