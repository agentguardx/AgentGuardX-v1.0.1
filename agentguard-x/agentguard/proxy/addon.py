"""AgentGuard-X mitmproxy addon — Phase 6 TLS inspection layer.

Loaded by mitmproxy via:  mitmdump -s /app/agentguard/proxy/addon.py

The addon:
  1. Checks outbound domain against the static allowlist (fail-closed).
  2. Parses the A2A envelope from headers/body/mTLS cert.
  3. POSTs the envelope to the AgentGuard-X gateway /v1/proxy/check endpoint.
  4. Blocks or passes the request based on the gateway verdict.
  5. Scans responses for credential leaks / injection markers (post-hook).

Observability is always active regardless of enforcement toggle.
When enforcement=False: logs threats but never blocks.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid

import httpx
from mitmproxy import http
from mitmproxy.script import concurrent

from agentguard.proxy.a2a_parser import parse_envelope
from agentguard.proxy.domain_allowlist import check_domain

logger = logging.getLogger("agentguard.proxy")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] agentguard-proxy %(message)s",
)

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://gateway:8080")
ENFORCEMENT_DEFAULT = os.getenv("AGENTGUARD_ENFORCEMENT", "true").lower() == "true"
PROXY_TIMEOUT_SECONDS = float(os.getenv("PROXY_TIMEOUT_SECONDS", "5.0"))

# Content types we introspect (avoid binary/media payloads)
_INSPECT_CONTENT_TYPES = frozenset({
    "application/json",
    "application/x-www-form-urlencoded",
    "text/plain",
})


class AgentGuardProxyAddon:
    """mitmproxy addon: intercept, triage, block/allow."""

    def __init__(self) -> None:
        self._client = httpx.Client(
            timeout=PROXY_TIMEOUT_SECONDS,
            follow_redirects=False,
        )
        logger.info(
            "AgentGuard-X proxy addon loaded. Gateway=%s enforcement_default=%s",
            GATEWAY_URL,
            ENFORCEMENT_DEFAULT,
        )

    # ── Outbound request interception ────────────────────────────────────────
    @concurrent
    def request(self, flow: http.HTTPFlow) -> None:
        """Called for every proxied request. May set flow.response to block."""
        t0 = time.monotonic()
        host = flow.request.pretty_host
        flow_id = str(uuid.uuid4())[:8]

        # ── 1. Domain allowlist ────────────────────────────────────────────
        domain_check = check_domain(host)
        if not domain_check.allowed:
            latency = (time.monotonic() - t0) * 1000
            logger.warning(
                "[%s] DOMAIN_BLOCK host=%s latency=%.1fms",
                flow_id, host, latency,
            )
            flow.response = _blocked_response(
                f"AgentGuard-X: domain '{host}' is not on the allowlist"
            )
            return

        # ── 2. A2A envelope extraction ────────────────────────────────────
        envelope = parse_envelope(flow.request)

        # Skip non-agent traffic (no X-Agent-Identity and no tool name)
        if envelope.agent_id == "unknown" and envelope.tool_name == "unknown":
            return

        # ── 3. Gateway proxy check ────────────────────────────────────────
        verdict = self._check_with_gateway(flow_id, envelope, host)
        if verdict is None:
            # Gateway unreachable — fail-closed when enforcement is on
            enforcement = ENFORCEMENT_DEFAULT
            if enforcement:
                logger.error(
                    "[%s] GATEWAY_UNREACHABLE host=%s → fail-closed BLOCK",
                    flow_id, host,
                )
                flow.response = _blocked_response(
                    "AgentGuard-X: gateway unreachable — fail-closed block"
                )
            else:
                logger.warning(
                    "[%s] GATEWAY_UNREACHABLE host=%s enforcement=OFF → pass-through",
                    flow_id, host,
                )
            return

        latency = (time.monotonic() - t0) * 1000
        action = verdict.get("action", "allow")
        enforcement = verdict.get("enforcement", ENFORCEMENT_DEFAULT)

        logger.info(
            "[%s] host=%s tool=%s agent=%s action=%s r=%s enforcement=%s latency=%.1fms",
            flow_id, host, envelope.tool_name, envelope.agent_id,
            action, verdict.get("r"), enforcement, latency,
        )

        if action == "block" and enforcement:
            flow.response = _blocked_response(
                f"AgentGuard-X: {verdict.get('reason', 'blocked by triage')}"
            )

    # ── Inbound response scan ────────────────────────────────────────────────
    @concurrent
    def response(self, flow: http.HTTPFlow) -> None:
        """Post-hook: scan response body for credential leaks and injection markers."""
        if flow.response is None:
            return

        content_type = flow.response.headers.get("content-type", "").lower()
        if not any(ct in content_type for ct in _INSPECT_CONTENT_TYPES):
            return

        body = _safe_decode(flow.response.content)
        if not body:
            return

        findings = self._post_hook_scan(body)
        if findings:
            host = flow.request.pretty_host
            logger.warning(
                "POST_HOOK_FINDINGS host=%s findings=%s",
                host, json.dumps(findings),
            )
            # When enforcement is on, replace response body with quarantine notice
            if ENFORCEMENT_DEFAULT:
                flow.response.content = json.dumps({
                    "error": "AgentGuard-X: response quarantined — post-hook findings",
                    "findings": findings,
                }).encode()
                flow.response.headers["content-type"] = "application/json"

    # ── Internal helpers ─────────────────────────────────────────────────────
    def _check_with_gateway(
        self, flow_id: str, envelope, host: str
    ) -> dict | None:
        """POST envelope to /v1/proxy/check. Returns None on error."""
        payload = {
            **envelope.to_gateway_dict(),
            "proxy_flow_id": flow_id,
            "destination_host": host,
            "tool_input": {},
        }
        try:
            resp = self._client.post(
                f"{GATEWAY_URL}/v1/proxy/check",
                json=payload,
            )
            return resp.json()
        except Exception as exc:
            logger.error("Gateway call failed: %s", exc)
            return None

    def _post_hook_scan(self, body: str) -> list[str]:
        """Lightweight post-hook credential / injection scan.

        Returns list of finding labels. Empty list = clean.
        """
        import re
        findings: list[str] = []

        # AWS-shaped synthetic key (AKIA... pattern) — obviously fake format per §0
        if re.search(r"\bAKIA[A-Z0-9]{16}\b", body):
            findings.append("credential:aws_key_shape")

        # Generic high-entropy token (≥20 chars with special chars)
        if re.search(r"[A-Za-z0-9+/]{20,}={0,2}", body):
            if _shannon_entropy(body) > 4.5:
                findings.append("credential:high_entropy")

        # Injection prompt markers
        _INJECTION_PATTERNS = [
            r"ignore\s+(?:your\s+)?(?:previous\s+)?instructions",
            r"you\s+are\s+now\s+",
            r"new\s+system\s+prompt",
            r"disregard\s+(?:all\s+)?previous",
            r"\[INST\]",
        ]
        for pat in _INJECTION_PATTERNS:
            if re.search(pat, body, re.IGNORECASE):
                findings.append("injection:prompt_override")
                break

        return findings

    def done(self) -> None:
        """Called by mitmproxy on shutdown."""
        self._client.close()


def _blocked_response(reason: str) -> http.Response:
    body = json.dumps({"error": reason, "blocked_by": "agentguard-x-proxy"}).encode()
    return http.Response.make(
        403,
        body,
        {"content-type": "application/json", "x-agentguard-blocked": "true"},
    )


def _safe_decode(content: bytes) -> str:
    if not content:
        return ""
    try:
        return content.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _shannon_entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


# mitmproxy addon entry point
addons = [AgentGuardProxyAddon()]
