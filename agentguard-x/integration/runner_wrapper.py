#!/usr/bin/env python3
"""AgentGuard-X runner wrapper — zero-modification FinanceFlow integration.

Monkey-patches financeflow.runner._get_agent to inject AgentGuardGatewayCallback
before calling financeflow.runner.main(). sys.argv is forwarded as-is so every
CLI subcommand (benign, attack, seed, server) works unchanged.

FinanceFlow source is NOT modified by this file.

Environment variables (read at runtime):
    AGENTGUARD_ENABLED:     "true"|"false"  (default: "true")
    AGENTGUARD_ENFORCEMENT: "true"|"false"  (default: "true")
    GATEWAY_URL:            gateway base URL (default: "http://gateway:8080")
"""

from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger(__name__)


def _build_callback(role: str):
    from integration.gateway_callback import AgentGuardGatewayCallback

    enforcement = os.getenv("AGENTGUARD_ENFORCEMENT", "true").lower() in (
        "true", "on", "1", "yes",
    )
    gateway_url = os.getenv("GATEWAY_URL", "http://gateway:8080")

    return AgentGuardGatewayCallback(
        agent_id=f"financeflow-{role}",
        agent_role=role,
        gateway_url=gateway_url,
        enforcement=enforcement,
    )


def _patch_and_run() -> None:
    import financeflow.runner as ff_runner

    _original_get_agent = ff_runner._get_agent

    def _patched(role: str, extra_callbacks=None):
        handler = _build_callback(role)
        cbs = [handler] + (extra_callbacks or [])
        return _original_get_agent(role, extra_callbacks=cbs)

    ff_runner._get_agent = _patched
    logger.info(
        "AgentGuard-X: _get_agent patched — gateway callbacks injected for all roles"
    )
    ff_runner.main()


def main() -> None:
    enabled = os.getenv("AGENTGUARD_ENABLED", "true").lower() in (
        "true", "on", "1", "yes",
    )

    if enabled:
        _patch_and_run()
    else:
        import financeflow.runner as ff_runner
        ff_runner.main()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
