"""Analyst Queue FastAPI service — port 8083.

UI for reviewing and resolving analyst holds placed by the gateway hooks.

Endpoints:
  GET  /           — HTML dashboard (hold queue view)
  GET  /holds      — JSON list of all holds
  GET  /holds/pending — JSON list of pending holds only
  POST /holds      — Submit a new hold (called by gateway hooks)
  POST /holds/{id}/approve — Analyst approves operation
  POST /holds/{id}/reject  — Analyst rejects (blocks) operation
  GET  /metrics    — Hold queue counters for Prometheus scrape
  GET  /health     — Liveness probe
"""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from agentguard.analyst.queue import HoldStatus, get_hold_queue
from agentguard.observability.telemetry import setup_telemetry


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_telemetry("agentguard-analyst")
    # Background reaper: auto-expire stale holds every 5 seconds
    async def _reaper():
        queue = get_hold_queue()
        while True:
            await asyncio.sleep(5)
            expired = await queue.expire_stale()
            if expired:
                print(f"[analyst] Auto-expired {expired} hold(s) → BLOCK (fail-closed)")

    task = asyncio.create_task(_reaper())
    print("[analyst] Hold queue ready.")
    yield
    task.cancel()
    print("[analyst] Shutting down.")


app = FastAPI(title="AgentGuard-X Analyst Queue", version="1.0.0", lifespan=lifespan)


class SubmitHoldRequest(BaseModel):
    agent_id: str
    agent_role: str = "unknown"
    tool_name: str
    r_score: float
    session_id: str = ""
    raw_payload: str = ""
    operation_value_usd: float = 0.0
    timeout_seconds: int = 300


class ResolveRequest(BaseModel):
    analyst_note: str = ""


@app.get("/health")
async def health() -> Response:
    return Response(content="ok", media_type="text/plain")


@app.post("/holds")
async def submit_hold(req: SubmitHoldRequest) -> JSONResponse:
    """Called by the gateway hooks to register a hold for analyst review."""
    queue = get_hold_queue()
    hold = await queue.submit(
        agent_id=req.agent_id,
        agent_role=req.agent_role,
        tool_name=req.tool_name,
        r_score=req.r_score,
        session_id=req.session_id,
        raw_payload=req.raw_payload,
        operation_value_usd=req.operation_value_usd,
        timeout_seconds=req.timeout_seconds,
    )
    return JSONResponse(status_code=201, content=hold.to_dict())


@app.get("/holds/pending")
async def list_pending() -> JSONResponse:
    queue = get_hold_queue()
    holds = await queue.list_pending()
    return JSONResponse([h.to_dict() for h in holds])


@app.get("/holds")
async def list_holds() -> JSONResponse:
    queue = get_hold_queue()
    holds = await queue.list_all()
    return JSONResponse([h.to_dict() for h in holds])


@app.post("/holds/{hold_id}/approve")
async def approve_hold(hold_id: str, req: ResolveRequest) -> JSONResponse:
    queue = get_hold_queue()
    hold = await queue.resolve(hold_id, HoldStatus.APPROVED, req.analyst_note)
    if hold is None:
        raise HTTPException(status_code=404, detail="Hold not found or already resolved")
    return JSONResponse(hold.to_dict())


@app.post("/holds/{hold_id}/reject")
async def reject_hold(hold_id: str, req: ResolveRequest) -> JSONResponse:
    queue = get_hold_queue()
    hold = await queue.resolve(hold_id, HoldStatus.REJECTED, req.analyst_note)
    if hold is None:
        raise HTTPException(status_code=404, detail="Hold not found or already resolved")
    return JSONResponse(hold.to_dict())


@app.get("/metrics")
async def metrics_endpoint() -> Response:
    """Prometheus-format metrics for the hold queue."""
    queue = get_hold_queue()
    all_holds = await queue.list_all()
    pending = sum(1 for h in all_holds if h.status == HoldStatus.PENDING)
    approved = sum(1 for h in all_holds if h.status == HoldStatus.APPROVED)
    rejected = sum(1 for h in all_holds if h.status == HoldStatus.REJECTED)
    expired = sum(1 for h in all_holds if h.status == HoldStatus.EXPIRED)

    body = (
        "# HELP agentguard_hold_queue_pending Current pending holds awaiting analyst review\n"
        "# TYPE agentguard_hold_queue_pending gauge\n"
        f"agentguard_hold_queue_pending {pending}\n"
        "# HELP agentguard_hold_total Total holds by resolution status\n"
        "# TYPE agentguard_hold_total counter\n"
        f'agentguard_hold_total{{status="approved"}} {approved}\n'
        f'agentguard_hold_total{{status="rejected"}} {rejected}\n'
        f'agentguard_hold_total{{status="expired"}} {expired}\n'
    )
    return Response(content=body, media_type="text/plain; version=0.0.4")


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    """Minimal analyst hold queue UI."""
    queue = get_hold_queue()
    holds = await queue.list_all()
    pending_count = sum(1 for h in holds if h.status == HoldStatus.PENDING)

    rows = ""
    for h in holds:
        status_color = {
            "pending": "#f59e0b",
            "approved": "#10b981",
            "rejected": "#ef4444",
            "expired": "#6b7280",
        }.get(h.status.value, "#6b7280")

        action_btns = ""
        if h.status.value == "pending":
            action_btns = (
                f'<button onclick="resolve(\'{h.hold_id}\',\'approve\')" '
                f'style="background:#10b981;color:white;border:none;padding:4px 10px;cursor:pointer;margin-right:4px;border-radius:3px">Approve</button>'
                f'<button onclick="resolve(\'{h.hold_id}\',\'reject\')" '
                f'style="background:#ef4444;color:white;border:none;padding:4px 10px;cursor:pointer;border-radius:3px">Reject</button>'
            )
        else:
            action_btns = f'<span style="color:{status_color}">{h.status.value.upper()}</span>'

        rows += (
            f"<tr>"
            f"<td style='padding:8px;border-bottom:1px solid #333'>{h.tool_name}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #333'>{h.agent_id}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #333'>{h.r_score:.3f}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #333'>${h.operation_value_usd:,.0f}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #333'>"
            f"<span style='color:{status_color}'>{h.status.value}</span>"
            f"{'&nbsp;('+str(int(h.remaining_seconds))+'s)' if h.status.value == 'pending' else ''}"
            f"</td>"
            f"<td style='padding:8px;border-bottom:1px solid #333'>{action_btns}</td>"
            f"</tr>\n"
        )

    if not rows:
        rows = "<tr><td colspan='6' style='padding:20px;text-align:center;color:#6b7280'>No holds yet</td></tr>"

    html = f"""<!DOCTYPE html>
<html>
<head>
  <title>AgentGuard-X — Analyst Hold Queue</title>
  <meta http-equiv="refresh" content="5">
  <style>
    body {{ background:#111;color:#e5e7eb;font-family:monospace;padding:20px }}
    h1 {{ color:#f59e0b;margin-bottom:4px }}
    .badge {{ background:#ef4444;color:white;padding:2px 8px;border-radius:10px;font-size:12px }}
    table {{ width:100%;border-collapse:collapse;margin-top:20px }}
    th {{ text-align:left;padding:8px;border-bottom:2px solid #444;color:#9ca3af }}
  </style>
</head>
<body>
  <h1>AgentGuard-X Analyst Hold Queue</h1>
  <p>Pending holds: <span class="badge">{pending_count}</span>
     &nbsp;&bull;&nbsp; Auto-refreshes every 5s
     &nbsp;&bull;&nbsp; Expired holds → BLOCK (fail-closed)</p>
  <table>
    <thead>
      <tr>
        <th>Tool</th><th>Agent</th><th>R Score</th>
        <th>Value</th><th>Status</th><th>Action</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
  <script>
    async function resolve(id, action) {{
      const note = prompt('Analyst note (optional):') || '';
      const r = await fetch(`/holds/${{id}}/${{action}}`, {{
        method:'POST', headers:{{'Content-Type':'application/json'}},
        body: JSON.stringify({{analyst_note: note}})
      }});
      if (r.ok) location.reload();
      else alert('Error: ' + await r.text());
    }}
  </script>
</body>
</html>"""
    return HTMLResponse(html)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "agentguard.analyst.service:app",
        host=os.getenv("ANALYST_HOST", "0.0.0.0"),
        port=int(os.getenv("ANALYST_PORT", "8083")),
        log_level="info",
    )
