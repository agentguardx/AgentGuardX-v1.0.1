"""Exfil capture server — localhost HTTP listener for demo exfiltration.

Simulates an attacker-controlled external endpoint.
All posts from post_external tool land here; nothing leaves localhost.
Provides a REST API to inspect captured payloads.
"""

from __future__ import annotations

import datetime
import json
import sys
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from financeflow.config import DATA_DIR, EXFIL_CAPTURE_PORT

CAPTURE_LOG = DATA_DIR / "exfil_captures.jsonl"
_captures: list[dict[str, Any]] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(
        f"\n{'='*60}\n"
        f"  EXFIL CAPTURE SERVER running on :{EXFIL_CAPTURE_PORT}\n"
        f"  All POST /capture requests are LOGGED here.\n"
        f"  Nothing leaves localhost. This is a demo containment server.\n"
        f"{'='*60}\n",
        file=sys.stderr,
    )
    yield
    print("[exfil-server] Shutting down.", file=sys.stderr)


app = FastAPI(
    title="FinanceFlow Exfil Capture Server",
    description="Demo-only local capture endpoint. Simulates attacker-controlled server.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.post("/capture")
async def capture(request: Request) -> JSONResponse:
    """Capture an inbound POST — simulates attacker receiving exfiltrated data."""
    body = await request.body()
    headers = dict(request.headers)

    record = {
        "id": len(_captures) + 1,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "original_target": headers.get("x-original-target", "unknown"),
        "source_tool": headers.get("x-financeflow-tool", "unknown"),
        "content_type": headers.get("content-type", "unknown"),
        "payload_size_bytes": len(body),
        "payload_preview": body.decode("utf-8", errors="replace")[:500],
    }
    _captures.append(record)

    # Append to persistent log
    with CAPTURE_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    print(
        f"\n{'!'*60}\n"
        f"  EXFIL CAPTURE #{record['id']}\n"
        f"  Source:  {record['source_tool']}\n"
        f"  Target:  {record['original_target']}\n"
        f"  Size:    {record['payload_size_bytes']} bytes\n"
        f"  Preview: {record['payload_preview'][:200]}\n"
        f"{'!'*60}\n",
        file=sys.stderr,
    )

    return JSONResponse(
        status_code=200,
        content={"status": "captured", "capture_id": record["id"]},
    )


@app.get("/captures")
async def list_captures() -> JSONResponse:
    """List all captured payloads (for demo inspection)."""
    return JSONResponse(content={"count": len(_captures), "captures": _captures})


@app.delete("/captures")
async def clear_captures() -> JSONResponse:
    """Clear all captured payloads (reset between demo runs)."""
    n = len(_captures)
    _captures.clear()
    if CAPTURE_LOG.exists():
        CAPTURE_LOG.unlink()
    return JSONResponse(content={"cleared": n})


@app.get("/health")
async def health() -> Response:
    return Response(content="ok", media_type="text/plain")


if __name__ == "__main__":
    uvicorn.run(
        "financeflow.exfil_server.server:app",
        host="0.0.0.0",
        port=EXFIL_CAPTURE_PORT,
        log_level="warning",
    )
