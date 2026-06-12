"""Gateway FastAPI service — HTTP interface to the cognitive gateway."""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import os
from collections import deque
from contextlib import asynccontextmanager
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST, REGISTRY

from agentguard.observability.telemetry import setup_telemetry
from agentguard.toggle import enforcement_is_on, set_enforcement

# ── Prometheus metrics ────────────────────────────────────────────────────────
_prom_requests = Counter(
    "agentguard_requests_total",
    "Total triage requests processed",
    ["verdict", "route", "agent_role"],
)
_prom_blocks = Counter(
    "agentguard_blocks_total",
    "Total blocked requests",
    ["verdict", "agent_role"],
)
_prom_enforcement = Gauge(
    "agentguard_enforcement_active",
    "1 when enforcement is ON, 0 when observe-only",
)
# Phase 5 — break out detections by the detector that fired + sandbox verdicts.
_prom_detections = Counter(
    "agentguard_detections_total",
    "Detections by category (which detector fired)",
    ["category", "verdict", "agent_role"],
)
_prom_sandbox = Counter(
    "agentguard_sandbox_total",
    "Sandboxed executions by verdict",
    ["verdict", "tier"],
)

# Structured decision logger — exported to Loki via the OTLP log pipeline.
_decision_log = logging.getLogger("agentguard.decisions")

# In-memory ring buffer of recent triage decisions (last 200).
# Written by /check, /v1/proxy/check, and /v1/posthook/scan handlers.
# Read by GET /admin/status for the web UI live feed.
_decisions: deque = deque(maxlen=200)


def _record(entry: dict) -> None:
    entry.setdefault("ts", datetime.datetime.utcnow().isoformat() + "Z")
    _decisions.appendleft(entry)
    # Increment Prometheus counters for pre-hook decisions only
    if entry.get("type") == "pre_hook":
        verdict = entry.get("verdict", "allow")
        role = entry.get("agent_role", "unknown")
        route = entry.get("route", "unknown") or "unknown"
        _prom_requests.labels(verdict=verdict, route=route, agent_role=role).inc()
        if verdict in ("block", "block_short_circuit", "block_stage1"):
            _prom_blocks.labels(verdict=verdict, agent_role=role).inc()
        # Break out by which detector fired (only when one did).
        category = entry.get("detection_category")
        if category:
            _prom_detections.labels(category=category, verdict=verdict, agent_role=role).inc()
    elif entry.get("type") == "sandbox":
        _prom_sandbox.labels(
            verdict=entry.get("verdict", "unknown"),
            tier=entry.get("tier", "docker"),
        ).inc()
    _prom_enforcement.set(1 if enforcement_is_on() else 0)

    # Structured decision log → OTLP → Loki (Live Attack Logs panel).
    try:
        is_block = entry.get("verdict") in (
            "block", "block_short_circuit", "block_stage1", "killed", "quarantined")
        _decision_log.warning(
            "decision %s tool=%s verdict=%s category=%s reason=%s",
            "BLOCK" if is_block else entry.get("type", "decision"),
            entry.get("tool_name"), entry.get("verdict"),
            entry.get("detection_category"),
            (entry.get("detection_reason") or entry.get("block_reason") or "")[:200],
        )
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_telemetry("agentguard-gateway")
    print("[gateway] Ready.")
    yield
    print("[gateway] Shutting down.")


app = FastAPI(title="AgentGuard-X Cognitive Gateway", version="1.0.0", lifespan=lifespan)


class GatewayRequest(BaseModel):
    session_id: str
    agent_id: str
    agent_role: str
    tool_name: str
    tool_input: dict[str, Any] = {}
    raw_payload: str
    declared_tools: list[str] = []
    reversibility: Optional[str] = None


class ProxyCheckRequest(BaseModel):
    """Envelope from the TLS proxy addon (Phase 6)."""
    agent_id: str = "unknown"
    session_id: str = "unknown"
    agent_role: str = "research"
    tool_name: str = "unknown"
    declared_tools: list[str] = []
    raw_payload: str = ""
    request_id: str = ""
    mtls_subject: Optional[str] = None
    destination_host: str = ""
    proxy_flow_id: str = ""
    tool_input: dict[str, Any] = {}


@app.post("/check")
async def gateway_check(req: GatewayRequest) -> JSONResponse:
    """Pre-execution gateway check — intent gate + triage via triage service."""
    enforcement = enforcement_is_on()

    # Toggle OFF → AgentGuard is dormant. No intent gate, no triage, no scoring,
    # no decision recording. The client system runs completely unguarded so judges
    # can compare behaviour with vs. without AgentGuard-X.
    if not enforcement:
        return JSONResponse(content={
            "allowed": True,
            "verdict": "bypassed",
            "r": None,
            "route": "bypassed",
            "enforcement": False,
        })

    from agentguard.gateway.intent_gate import IntentGate

    gate = IntentGate()
    intent = gate.check(req.agent_role, req.tool_name, req.declared_tools)

    if not intent.allowed and enforcement:
        return JSONResponse(
            status_code=403,
            content={
                "allowed": False,
                "reason": intent.reason,
                "enforcement": enforcement,
            },
        )

    # Forward to triage service for full scoring
    triage_url = os.getenv("TRIAGE_URL", "http://triage:8081")
    import httpx
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(
                f"{triage_url}/triage",
                json={
                    "session_id": req.session_id,
                    "agent_id": req.agent_id,
                    "agent_role": req.agent_role,
                    "tool_name": req.tool_name,
                    "tool_input": req.tool_input,
                    "raw_payload": req.raw_payload,
                    "declared_tools": req.declared_tools,
                    "reversibility": req.reversibility,
                },
            )
            triage_result = resp.json()
        except Exception as e:
            if enforcement:
                return JSONResponse(
                    status_code=503,
                    content={"allowed": False, "reason": f"Triage error (fail-closed): {e}"},
                )
            triage_result = {"verdict": "allow", "r": 0.0, "enforcement_active": False}

    verdict = triage_result.get("verdict", "allow")
    blocked = verdict in ("block", "block_short_circuit", "block_stage1")
    category = triage_result.get("detection_category")
    # Prefer the specific detector reason over the generic short-circuit text.
    detail_reason = triage_result.get("detection_reason") or triage_result.get("block_reason")

    _record({
        "type": "pre_hook",
        "agent_id": req.agent_id,
        "agent_role": req.agent_role,
        "tool_name": req.tool_name,
        "verdict": verdict,
        "r": triage_result.get("r"),
        "route": triage_result.get("route"),
        "block_reason": triage_result.get("block_reason"),
        "detection_category": category,
        "detection_reason": detail_reason,
        "enforcement": enforcement,
    })

    if blocked and enforcement:
        return JSONResponse(
            status_code=403,
            content={
                "allowed": False,
                "verdict": verdict,
                "reason": detail_reason or triage_result.get("block_reason"),
                "category": category,
                "r": triage_result.get("r"),
                "enforcement": enforcement,
            },
        )

    return JSONResponse(
        content={
            "allowed": True,
            "verdict": verdict,
            "r": triage_result.get("r"),
            "route": triage_result.get("route"),
            "category": category,
            "enforcement": enforcement,
        }
    )


@app.post("/v1/proxy/check")
async def proxy_check(req: ProxyCheckRequest) -> JSONResponse:
    """Called by the TLS proxy addon for every intercepted agent request.

    Returns action: allow | block | observe.
    """
    enforcement = enforcement_is_on()

    # Toggle OFF → AgentGuard dormant: pass every flow through with no analysis.
    if not enforcement:
        return JSONResponse(content={
            "action": "allow",
            "verdict": "bypassed",
            "reason": None,
            "r": None,
            "enforcement": False,
            "proxy_flow_id": req.proxy_flow_id,
        })

    # Stage 1: intent gate (stateless, no external deps)
    from agentguard.gateway.intent_gate import IntentGate
    gate = IntentGate()
    intent = gate.check(req.agent_role, req.tool_name, req.declared_tools)

    if not intent.allowed and enforcement:
        return JSONResponse(content={
            "action": "block",
            "reason": f"intent_gate: {intent.reason}",
            "r": None,
            "enforcement": enforcement,
            "proxy_flow_id": req.proxy_flow_id,
        })

    # Full triage via triage service
    triage_url = os.getenv("TRIAGE_URL", "http://triage:8081")
    import httpx
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(
                f"{triage_url}/triage",
                json={
                    "session_id": req.session_id,
                    "agent_id": req.agent_id,
                    "agent_role": req.agent_role,
                    "tool_name": req.tool_name,
                    "tool_input": req.tool_input,
                    "raw_payload": req.raw_payload,
                    "declared_tools": req.declared_tools,
                    "reversibility": None,
                },
            )
            triage_result = resp.json()
        except Exception as exc:
            if enforcement:
                return JSONResponse(content={
                    "action": "block",
                    "reason": f"triage_error (fail-closed): {exc}",
                    "r": None,
                    "enforcement": enforcement,
                    "proxy_flow_id": req.proxy_flow_id,
                })
            triage_result = {"verdict": "allow", "r": 0.0}

    verdict = triage_result.get("verdict", "allow")
    blocked = verdict in ("block", "block_short_circuit", "block_stage1")

    action = "block" if (blocked and enforcement) else "allow"

    _record({
        "type": "proxy",
        "agent_id": req.agent_id,
        "agent_role": req.agent_role,
        "tool_name": req.tool_name,
        "verdict": verdict,
        "r": triage_result.get("r"),
        "block_reason": triage_result.get("block_reason") if blocked else None,
        "enforcement": enforcement,
    })

    return JSONResponse(content={
        "action": action,
        "verdict": verdict,
        "reason": triage_result.get("block_reason") if blocked else None,
        "r": triage_result.get("r"),
        "route": triage_result.get("route"),
        "enforcement": enforcement,
        "proxy_flow_id": req.proxy_flow_id,
    })


class PosthookScanRequest(BaseModel):
    """Request from the thin gateway callback (Phase 11 integration)."""
    output: str
    tool_name: str
    agent_id: str = "unknown"
    session_id: str = "unknown"


@app.post("/v1/posthook/scan")
async def posthook_scan(req: PosthookScanRequest) -> JSONResponse:
    """Post-execution output scan called by AgentGuardGatewayCallback.

    Runs PostHookProcessor (regex credential scan + injection detection)
    on the tool output inside the gateway process — no heavy deps in the
    FinanceFlow container.
    """
    # Toggle OFF → AgentGuard dormant: never scan or quarantine output.
    if not enforcement_is_on():
        return JSONResponse({
            "clean": True,
            "quarantined": False,
            "findings": [],
            "sanitized_output": req.output,
        })

    from agentguard.gateway.post_hook import PostHookProcessor

    proc = PostHookProcessor()
    scan = proc.scan(req.output, req.tool_name)

    _record({
        "type": "post_hook",
        "agent_id": req.agent_id,
        "tool_name": req.tool_name,
        "verdict": "quarantined" if scan.quarantined else "clean",
        "clean": scan.clean,
        "quarantined": scan.quarantined,
        "findings": scan.findings,
        "r": None,
        "enforcement": enforcement_is_on(),
    })

    return JSONResponse({
        "clean": scan.clean,
        "quarantined": scan.quarantined,
        "findings": scan.findings,
        "sanitized_output": scan.sanitized_output,
    })


# ── Phase 7 sandbox integration (defense-in-depth code execution) ─────────────
_sandbox_manager: Any = None
_sandbox_lock = asyncio.Lock()


async def _get_sandbox():
    """Lazily build + initialize the SandboxManager on first use.

    Lazy so the gateway stays healthy even if Docker/sandbox image is missing —
    the failure surfaces only on the first sandbox request, not at startup.
    """
    global _sandbox_manager
    if _sandbox_manager is None:
        async with _sandbox_lock:
            if _sandbox_manager is None:
                from agentguard.sandbox.manager import SandboxManager
                mgr = SandboxManager.from_env()
                await mgr.initialize()
                _sandbox_manager = mgr
    return _sandbox_manager


class SandboxExecRequest(BaseModel):
    tool_name: str
    tool_input: dict[str, Any] = {}
    session_id: str = ""
    agent_id: str = "unknown"
    agent_role: str = "admin"
    requires_gvisor_floor: bool = False


@app.post("/v1/sandbox/execute")
async def sandbox_execute(req: SandboxExecRequest) -> JSONResponse:
    """Run a tool call inside an ephemeral, network-isolated sandbox container.

    Fingerprint diff decides promote (clean) vs kill (suspicious side-effects).
    Toggle OFF → dormant: the caller runs the tool directly instead.
    """
    if not enforcement_is_on():
        return JSONResponse({"sandboxed": False, "verdict": "bypassed", "enforcement": False})

    try:
        from agentguard.sandbox.model import SandboxJob

        mgr = await _get_sandbox()
        job = SandboxJob(
            tool_name=req.tool_name,
            tool_input=req.tool_input,
            session_id=req.session_id,
            agent_id=req.agent_id,
            agent_role=req.agent_role,
            requires_gvisor_floor=req.requires_gvisor_floor,
        )
        result = await mgr.run_sandboxed(job)
        d = result.to_dict()

        # The sandbox runner prints {"result": ...} / {"error": ...} as JSON on stdout.
        tool_output = result.stdout
        try:
            parsed = json.loads(result.stdout) if result.stdout else {}
            if isinstance(parsed, dict):
                tool_output = parsed.get("result") or parsed.get("error") or result.stdout
        except (ValueError, TypeError):
            pass

        # Visible runtime line in `docker logs agentguard-gateway`.
        print(
            f"[SANDBOX] tool={req.tool_name} verdict={d['verdict']} "
            f"tier={d['tier_used']} duration={d.get('duration_ms', 0):.0f}ms"
            + (f" reason={d.get('block_reason')}" if d.get("block_reason") else ""),
            flush=True,
        )

        _record({
            "type": "sandbox",
            "agent_id": req.agent_id,
            "agent_role": req.agent_role,
            "tool_name": req.tool_name,
            "verdict": d["verdict"],
            "r": None,
            "tier": d["tier_used"],
            "block_reason": d.get("block_reason"),
            "enforcement": True,
        })

        return JSONResponse({
            "sandboxed": True,
            "verdict": d["verdict"],                 # promoted | killed | blocked | error
            "tier": d["tier_used"],                  # docker | gvisor | blocked
            "output": tool_output,
            "block_reason": d.get("block_reason"),
            "fingerprint": d.get("fingerprint_delta"),
            "duration_ms": d.get("duration_ms"),
            "enforcement": True,
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={
            "sandboxed": False, "verdict": "error", "error": str(exc)[:200],
        })


@app.get("/metrics")
async def metrics() -> Response:
    _prom_enforcement.set(1 if enforcement_is_on() else 0)
    return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
async def health() -> Response:
    return Response(content="ok", media_type="text/plain")


@app.get("/admin/status")
async def admin_status() -> JSONResponse:
    """Returns enforcement state and recent triage decisions for the web UI."""
    return JSONResponse({
        "enforcement": enforcement_is_on(),
        "recent_decisions": list(_decisions)[:100],
    })


@app.get("/admin/agents")
async def admin_agents() -> JSONResponse:
    """Expose the LIVE FinanceFlow agent registry + RBAC/ABAC policy for the web UI.

    - agents: declared tool envelopes (RBAC) + isolation floor (ABAC) from the
      in-memory registry that Stage 1 / the intent gate actually enforce.
    - policy: per-role rate limits + per-tool risk scores pulled live from OPA's
      data API (the same policy Stage 3 evaluates). Falls back to {} if OPA is
      unreachable so the endpoint never hard-fails.
    """
    from agentguard.registry.agent_registry import get_agent_registry

    registry = get_agent_registry()
    agents = [
        {
            "agent_id": a.agent_id,
            "role": a.role,
            "allowed_tools": list(a.allowed_tools),
            "isolation_floor": a.isolation_floor,
            "description": a.description,
        }
        for a in registry.all()
    ]

    # Mirrors policies/rbac/rbac.rego — used as a fallback when OPA's data API
    # has no bundle loaded (kept in sync with the rego, single source of truth).
    _RBAC_RATE_LIMITS = {"research": 50, "data": 30, "admin": 20}
    _RBAC_TOOL_RISK_SCORES = {
        "transfer_funds_tool": 0.75,
        "execute_code_tool": 0.75,
        "post_external_tool": 0.80,
        "read_customer_pii_tool": 0.40,
        "send_email_tool": 0.50,
        "compress_data_tool": 0.20,
    }

    rate_limits: dict = {}
    risk_scores: dict = {}
    opa_url = os.getenv("OPA_URL", "http://opa:8181").rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=2.0) as c:
            rl = await c.get(f"{opa_url}/v1/data/agentguard/rbac/role_rate_limits")
            if rl.status_code == 200:
                rate_limits = rl.json().get("result", {}) or {}
            rs = await c.get(f"{opa_url}/v1/data/agentguard/rbac/tool_risk_scores")
            if rs.status_code == 200:
                risk_scores = rs.json().get("result", {}) or {}
    except Exception:
        pass

    # Fall back to the policy values if OPA returned nothing.
    rate_limits = rate_limits or _RBAC_RATE_LIMITS
    risk_scores = risk_scores or _RBAC_TOOL_RISK_SCORES

    return JSONResponse({
        "agents": agents,
        "policy": {"rate_limits": rate_limits, "tool_risk_scores": risk_scores},
    })


@app.post("/admin/toggle")
async def toggle(request: Request) -> JSONResponse:
    body = await request.json()
    enforcement = bool(body.get("enforcement", True))
    set_enforcement("on" if enforcement else "off")
    return JSONResponse({"enforcement": enforcement})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=os.getenv("GATEWAY_HOST", "0.0.0.0"),
        port=int(os.getenv("GATEWAY_PORT", "8080")),
        log_level="info",
    )
