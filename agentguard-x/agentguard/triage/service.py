"""Triage FastAPI service — HTTP interface to the triage pipeline."""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from prometheus_client import Histogram, generate_latest, CONTENT_TYPE_LATEST, REGISTRY

from agentguard.observability.telemetry import setup_telemetry
from agentguard.scoring.model import TriageResult
from agentguard.stages.base import StageInput
from agentguard.triage.pipeline import TriagePipeline
from agentguard.toggle import enforcement_is_on

# ── Prometheus metrics ────────────────────────────────────────────────────────
_prom_latency = Histogram(
    "agentguard_triage_latency_ms",
    "End-to-end triage pipeline latency in milliseconds",
    buckets=[5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000],
)
_prom_risk_score = Histogram(
    "agentguard_risk_score",
    "Distribution of composite R scores",
    buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
)

_pipeline: Optional[TriagePipeline] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pipeline
    setup_telemetry("agentguard-triage")

    from agentguard.registry.agent_registry import get_agent_registry
    from agentguard.stages.stage1_identity import Stage1IdentityGate
    from agentguard.stages.stage2_signatures import Stage2Signatures
    from agentguard.stages.stage3_opa import Stage3OPA
    from agentguard.stages.stage4_rag import Stage4RAG
    from agentguard.stages.stage5_behavioral import Stage5Behavioral

    opa_url = os.getenv("OPA_URL", "http://opa:8181")
    chroma_host = os.getenv("CHROMA_HOST", "chromadb")
    chroma_port = int(os.getenv("CHROMA_PORT", "8888"))
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")

    redis_client = None
    try:
        import redis
        redis_client = redis.from_url(redis_url, decode_responses=True)
        redis_client.ping()
    except Exception as e:
        print(f"[triage] Redis unavailable: {e} — S5 will be suspended")

    _pipeline = TriagePipeline(
        stage1=Stage1IdentityGate(registry=get_agent_registry()),
        stage2=Stage2Signatures(),
        stage3=Stage3OPA(opa_url=opa_url),
        stage4=Stage4RAG(chroma_host=chroma_host, chroma_port=chroma_port,
                         redis_client=redis_client),
        stage5=Stage5Behavioral(redis_client=redis_client),
    )
    print("[triage] Pipeline ready.")
    yield
    print("[triage] Shutting down.")


app = FastAPI(title="AgentGuard-X Triage Engine", version="1.0.0", lifespan=lifespan)


class TriageRequest(BaseModel):
    request_id: Optional[str] = None
    session_id: str
    agent_id: str
    agent_role: str
    tool_name: str
    tool_input: dict[str, Any] = {}
    raw_payload: str
    tool_output: Optional[str] = None
    declared_tools: list[str] = []
    reversibility: Optional[str] = None


class TriageResponse(BaseModel):
    request_id: str
    verdict: str
    route: str
    r: float
    k: int
    base: float
    corroboration_bonus: float
    a_bar: float
    triggered_stages: list[str]
    block_reason: Optional[str]
    short_circuited: bool
    latency_ms: float
    enforcement_active: bool
    detection_category: Optional[str] = None
    detection_reason: Optional[str] = None


@app.post("/triage", response_model=TriageResponse)
async def triage_endpoint(req: TriageRequest) -> TriageResponse:
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="Triage pipeline not ready")

    request_id = req.request_id or str(uuid.uuid4())
    inp = StageInput(
        request_id=request_id,
        session_id=req.session_id,
        agent_id=req.agent_id,
        agent_role=req.agent_role,
        tool_name=req.tool_name,
        tool_input=req.tool_input,
        raw_payload=req.raw_payload,
        tool_output=req.tool_output,
        declared_tools=req.declared_tools,
    )

    result: TriageResult = await _pipeline.evaluate(
        inp, reversibility=req.reversibility
    )

    _prom_latency.observe(result.latency_ms)
    _prom_risk_score.observe(result.r)

    return TriageResponse(
        request_id=request_id,
        verdict=result.verdict.value,
        route=result.route.value,
        r=result.r,
        k=result.k,
        base=result.base,
        corroboration_bonus=result.corroboration_bonus,
        a_bar=result.a_bar,
        triggered_stages=result.triggered_stages,
        block_reason=result.block_reason,
        short_circuited=result.short_circuited,
        latency_ms=result.latency_ms,
        enforcement_active=enforcement_is_on(),
        detection_category=result.detection_category,
        detection_reason=result.detection_reason,
    )


@app.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
async def health() -> Response:
    return Response(content="ok", media_type="text/plain")


@app.post("/admin/toggle")
async def set_toggle(request: Request) -> JSONResponse:
    body = await request.json()
    enforcement = bool(body.get("enforcement", True))
    from agentguard.toggle import set_enforcement
    set_enforcement("on" if enforcement else "off")
    return JSONResponse({"enforcement": enforcement})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=os.getenv("TRIAGE_HOST", "0.0.0.0"),
        port=int(os.getenv("TRIAGE_PORT", "8081")),
        log_level="info",
    )
