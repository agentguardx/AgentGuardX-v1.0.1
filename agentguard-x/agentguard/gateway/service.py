"""Gateway FastAPI service — HTTP interface to the cognitive gateway."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agentguard.observability.telemetry import setup_telemetry
from agentguard.toggle import enforcement_is_on, set_enforcement


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
    from agentguard.gateway.intent_gate import IntentGate

    gate = IntentGate()
    intent = gate.check(req.agent_role, req.tool_name, req.declared_tools)

    enforcement = enforcement_is_on()

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

    if blocked and enforcement:
        return JSONResponse(
            status_code=403,
            content={
                "allowed": False,
                "verdict": verdict,
                "reason": triage_result.get("block_reason"),
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
            "enforcement": enforcement,
        }
    )


@app.post("/v1/proxy/check")
async def proxy_check(req: ProxyCheckRequest) -> JSONResponse:
    """Called by the TLS proxy addon for every intercepted agent request.

    Returns action: allow | block | observe.
    Observability always fires regardless of enforcement state.
    """
    enforcement = enforcement_is_on()

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
    return JSONResponse(content={
        "action": action,
        "verdict": verdict,
        "reason": triage_result.get("block_reason") if blocked else None,
        "r": triage_result.get("r"),
        "route": triage_result.get("route"),
        "enforcement": enforcement,
        "proxy_flow_id": req.proxy_flow_id,
    })


@app.get("/health")
async def health() -> Response:
    return Response(content="ok", media_type="text/plain")


@app.post("/admin/toggle")
async def toggle(request: Request) -> JSONResponse:
    body = await request.json()
    enforcement = bool(body.get("enforcement", True))
    set_enforcement("on" if enforcement else "off")
    return JSONResponse({"enforcement": enforcement})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "agentguard.gateway.service:app",
        host=os.getenv("GATEWAY_HOST", "0.0.0.0"),
        port=int(os.getenv("GATEWAY_PORT", "8080")),
        log_level="info",
    )
