"""FinanceFlow Web UI — minimalist fintech browser dashboard.

Accessible at http://localhost:8100 after `docker compose up`.

Features:
  - Dashboard with account balances and transaction summary
  - Accounts and transactions tables
  - Demo runner: run attack/benign scenarios without Ollama
  - Live security feed: real-time AgentGuard-X decisions
  - Observability panel: Prometheus metrics, service health, Docker logs
  - Top-right enforcement toggle: calls gateway /admin/toggle
"""

from __future__ import annotations

import asyncio
import datetime
import json
import os
import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

# ── Service URLs (resolved within Docker network) ────────────────────────────
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://gateway:8080")
ANALYST_URL = os.getenv("ANALYST_URL", "http://analyst:8083")
PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
WEB_PORT = int(os.getenv("WEB_PORT", "8100"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Seed database on startup so the UI always has data
    try:
        from financeflow.database.seed import seed
        seed()
    except Exception as e:
        print(f"[web] DB seed skipped: {e}", file=sys.stderr)
    print(f"[financeflow-web] Listening on :{WEB_PORT}", file=sys.stderr)
    yield


app = FastAPI(title="FinanceFlow", lifespan=lifespan)


# ── Database helpers ──────────────────────────────────────────────────────────

def _db_accounts() -> list[dict]:
    from financeflow.database.models import Account, get_session
    s = get_session()
    try:
        return [a.to_dict() for a in s.query(Account).order_by(Account.account_number).all()]
    finally:
        s.close()


def _db_transactions(limit: int = 100) -> list[dict]:
    from financeflow.database.models import Transaction, get_session
    s = get_session()
    try:
        rows = s.query(Transaction).order_by(Transaction.timestamp.desc()).limit(limit).all()
        return [t.to_dict() for t in rows]
    finally:
        s.close()


# ── JSON API routes ───────────────────────────────────────────────────────────

@app.get("/api/accounts")
async def api_accounts():
    try:
        return JSONResponse(_db_accounts())
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/transactions")
async def api_transactions(limit: int = 100):
    try:
        return JSONResponse(_db_transactions(limit))
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/status")
async def api_status():
    """Aggregate health + enforcement + recent decisions from all services."""
    result: dict = {
        "enforcement": True,
        "services": {},
        "recent_decisions": [],
        "holds": [],
    }
    async with httpx.AsyncClient(timeout=3.0) as c:
        for svc, url, path in [
            ("gateway",    GATEWAY_URL,    "/health"),
            ("triage",     os.getenv("TRIAGE_URL", "http://triage:8081"),    "/health"),
            ("analyst",    ANALYST_URL,    "/health"),
            ("prometheus", PROMETHEUS_URL, "/-/healthy"),
        ]:
            try:
                r = await c.get(url + path)
                result["services"][svc] = r.status_code == 200
            except Exception:
                result["services"][svc] = False

        # Enforcement state + recent decisions from gateway
        try:
            r = await c.get(f"{GATEWAY_URL}/admin/status")
            if r.status_code == 200:
                d = r.json()
                result["enforcement"] = d.get("enforcement", True)
                result["recent_decisions"] = d.get("recent_decisions", [])
        except Exception:
            pass

        # Analyst holds
        try:
            r = await c.get(f"{ANALYST_URL}/holds")
            if r.status_code == 200:
                result["holds"] = r.json()
        except Exception:
            pass

    return JSONResponse(result)


@app.post("/api/toggle")
async def api_toggle(request: Request):
    body = await request.json()
    async with httpx.AsyncClient(timeout=3.0) as c:
        try:
            r = await c.post(f"{GATEWAY_URL}/admin/toggle", json=body)
            return JSONResponse(r.json())
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=503)


@app.get("/api/prometheus")
async def api_prometheus():
    """Return a curated set of Prometheus metric values."""
    queries = {
        "total_checks":      'sum(increase(agentguard_checks_total[1h])) or vector(0)',
        "blocked":           'sum(increase(agentguard_blocked_total[1h])) or vector(0)',
        "allowed":           'sum(increase(agentguard_allowed_total[1h])) or vector(0)',
        "grey_band":         'sum(increase(agentguard_greyband_total[1h])) or vector(0)',
        "hold_pending":      'agentguard_hold_queue_pending or vector(0)',
        "hold_approved":     'agentguard_hold_total{status="approved"} or vector(0)',
        "hold_expired":      'agentguard_hold_total{status="expired"} or vector(0)',
        "s2_short_circuits": 'sum(increase(agentguard_short_circuit_total[1h])) or vector(0)',
    }
    out: dict = {}
    async with httpx.AsyncClient(timeout=5.0) as c:
        for key, q in queries.items():
            try:
                r = await c.get(f"{PROMETHEUS_URL}/api/v1/query", params={"query": q})
                d = r.json()
                res = d.get("data", {}).get("result", [])
                out[key] = round(float(res[0]["value"][1]), 1) if res else 0
            except Exception:
                out[key] = None
    return JSONResponse(out)


# ── Demo runner ───────────────────────────────────────────────────────────────

@app.get("/api/demo/scenarios")
async def demo_scenarios():
    from financeflow.workflows.attacks import ATTACK_WORKFLOWS
    from financeflow.workflows.benign import BENIGN_WORKFLOWS
    return JSONResponse({
        "attacks": [
            {"name": s.name, "description": s.description,
             "owasp": s.owasp_category, "role": s.agent_role,
             "steps": len(s.scripted_tool_calls)}
            for s in ATTACK_WORKFLOWS
        ],
        "benign": [
            {"name": w.name, "description": w.description, "role": w.agent_role}
            for w in BENIGN_WORKFLOWS
        ],
    })


@app.get("/api/demo/run/{scenario_name}")
async def demo_run(scenario_name: str, enforcement: bool = True):
    """Stream attack scenario execution results via SSE."""

    async def _gen() -> AsyncGenerator[str, None]:
        from financeflow.workflows.attacks import ATTACK_BY_NAME
        from financeflow.tools import ROLE_TOOLS

        scenario = ATTACK_BY_NAME.get(scenario_name)
        if scenario is None:
            yield _sse({"error": f"Unknown scenario: {scenario_name}"})
            return

        yield _sse({"type": "start", "scenario": scenario_name,
                    "owasp": scenario.owasp_category, "role": scenario.agent_role,
                    "enforcement": enforcement})

        gateway_url = GATEWAY_URL
        session_id = f"web-demo-{scenario_name}-{datetime.datetime.utcnow().strftime('%H%M%S')}"

        # Build callback inline (thin HTTP version — no heavy deps)
        import httpx as _httpx
        tool_list = ROLE_TOOLS.get(scenario.agent_role, [])
        tool_map = {t.name: t for t in tool_list}
        call_seq: list[str] = []
        _REVERSIBLE = {"get_account_tool", "query_transactions_tool",
                       "read_customer_pii_tool", "run_report_tool",
                       "fetch_market_data_tool", "compress_data_tool"}
        _ROLE_TOOLS_MAP = {
            "research": ["get_account_tool", "run_report_tool", "fetch_market_data_tool"],
            "data": ["get_account_tool", "query_transactions_tool", "run_report_tool",
                     "fetch_market_data_tool", "read_customer_pii_tool"],
            "admin": ["get_account_tool", "query_transactions_tool", "read_customer_pii_tool",
                      "transfer_funds_tool", "run_report_tool", "fetch_market_data_tool",
                      "send_email_tool", "compress_data_tool", "post_external_tool",
                      "execute_code_tool"],
        }
        declared = _ROLE_TOOLS_MAP.get(scenario.agent_role, [])
        prev_outputs: dict[str, str] = {}

        for step_idx, step in enumerate(scenario.scripted_tool_calls):
            tool_name = step["tool"]
            raw_input = step["input"]

            # Resolve __PLACEHOLDER__ references
            resolved: dict = {}
            for k, v in raw_input.items():
                if isinstance(v, str) and v.startswith("__") and v.endswith("__"):
                    key = v.strip("_").lower()
                    resolved[k] = next(
                        (out for name, out in prev_outputs.items() if key in name.lower()),
                        f"[placeholder:{v}]",
                    )
                else:
                    resolved[k] = v

            call_seq.append(tool_name)
            payload = {
                "session_id": session_id,
                "agent_id": f"financeflow-{scenario.agent_role}",
                "agent_role": scenario.agent_role,
                "tool_name": tool_name,
                "tool_input": {"input": json.dumps(resolved)},
                "raw_payload": (
                    f"agent=financeflow-{scenario.agent_role} "
                    f"role={scenario.agent_role} tool={tool_name} "
                    f"input={json.dumps(resolved)} "
                    f"history={' '.join(call_seq[-10:])}"
                ),
                "declared_tools": declared,
                "reversibility": "reversible" if tool_name in _REVERSIBLE else "irreversible",
            }

            yield _sse({"type": "step_start", "step": step_idx + 1,
                        "tool": tool_name, "input": resolved})

            # Pre-execution check
            blocked = False
            block_reason = ""
            verdict = "allow"
            r_score = 0.0
            try:
                async with _httpx.AsyncClient(timeout=8.0) as c:
                    resp = await c.post(f"{gateway_url}/check", json=payload)
                if resp.status_code == 403:
                    body = resp.json()
                    blocked = True
                    block_reason = body.get("reason", "blocked")
                    verdict = body.get("verdict", "block")
                    r_score = body.get("r") or 0.0
                elif resp.status_code == 200:
                    body = resp.json()
                    verdict = body.get("verdict", "allow")
                    r_score = body.get("r") or 0.0
            except Exception as e:
                if enforcement:
                    blocked = True
                    block_reason = f"Gateway unreachable (fail-closed): {e}"

            if blocked and enforcement:
                yield _sse({"type": "step_blocked", "step": step_idx + 1,
                            "tool": tool_name, "verdict": verdict,
                            "r": r_score, "reason": block_reason})
                yield _sse({"type": "kill_chain_stopped", "step": step_idx + 1})
                break

            # Execute tool
            tool_fn = tool_map.get(tool_name)
            output = ""
            if tool_fn is None:
                output = f"TOOL UNAVAILABLE FOR ROLE '{scenario.agent_role}': {tool_name}"
            else:
                try:
                    output = str(tool_fn.invoke(resolved))
                except Exception as e:
                    output = f"TOOL ERROR: {e}"

            prev_outputs[tool_name] = output
            yield _sse({"type": "step_executed", "step": step_idx + 1,
                        "tool": tool_name, "output_preview": output[:300]})

            # Post-execution scan
            quarantined = False
            findings: list = []
            try:
                async with _httpx.AsyncClient(timeout=5.0) as c:
                    pr = await c.post(
                        f"{gateway_url}/v1/posthook/scan",
                        json={"output": output, "tool_name": tool_name,
                              "agent_id": f"financeflow-{scenario.agent_role}",
                              "session_id": session_id},
                    )
                if pr.status_code == 200:
                    pb = pr.json()
                    quarantined = pb.get("quarantined", False)
                    findings = pb.get("findings", [])
            except Exception:
                pass

            if quarantined and enforcement:
                yield _sse({"type": "step_quarantined", "step": step_idx + 1,
                            "tool": tool_name, "findings": findings})
                yield _sse({"type": "kill_chain_stopped", "step": step_idx + 1})
                break

            yield _sse({"type": "step_allowed", "step": step_idx + 1,
                        "tool": tool_name, "verdict": verdict, "r": r_score,
                        "quarantined": quarantined, "findings": findings})

        else:
            yield _sse({"type": "scenario_complete",
                        "outcome": "SUCCEEDED" if not enforcement else "PASSED_THROUGH"})
            return

        # If we broke out of the loop
        yield _sse({"type": "scenario_complete", "outcome": "BLOCKED"})

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


# ── Docker log streaming (optional — needs docker socket) ────────────────────

@app.get("/api/logs/stream")
async def logs_stream():
    """Stream recent logs from AgentGuard-X containers via Docker SDK.
    Falls back gracefully if docker socket is unavailable."""

    async def _gen() -> AsyncGenerator[str, None]:
        containers = [
            "agentguard-gateway",
            "agentguard-triage",
            "agentguard-proxy",
            "agentguard-analyst",
        ]
        try:
            import docker as _docker
            client = _docker.from_env()
        except Exception as e:
            yield _sse_log("system", f"Docker SDK unavailable: {e}", "warn")
            yield _sse_log("system", "Falling back to gateway decision log — see Security Feed tab.", "info")
            return

        # Initial tail from each container
        for name in containers:
            try:
                c = client.containers.get(name)
                raw = c.logs(tail=25, timestamps=True).decode("utf-8", errors="replace")
                for line in raw.splitlines():
                    if line.strip():
                        yield _sse_log(name.replace("agentguard-", ""), line.strip(),
                                       _log_level(line))
            except Exception as e:
                yield _sse_log(name, f"Container not found: {e}", "warn")

        # Poll for new logs every 2 s using tail=5 (simple, stateless)
        for _ in range(300):  # max ~10 min stream
            await asyncio.sleep(2)
            for name in containers:
                try:
                    c = client.containers.get(name)
                    raw = c.logs(tail=4, timestamps=True).decode("utf-8", errors="replace")
                    for line in raw.splitlines():
                        if line.strip():
                            yield _sse_log(name.replace("agentguard-", ""), line.strip(),
                                           _log_level(line))
                except Exception:
                    pass
            yield f"data: {json.dumps({'heartbeat': True})}\n\n"

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _sse_log(service: str, line: str, level: str) -> str:
    return f"data: {json.dumps({'service': service, 'line': line, 'level': level, 'ts': datetime.datetime.utcnow().strftime('%H:%M:%S')})}\n\n"


def _log_level(line: str) -> str:
    low = line.lower()
    if any(w in low for w in ["error", "exception", "blocked", "quarantined", "block_short"]):
        return "error"
    if any(w in low for w in ["warn", "hold", "grey_band", "greyband"]):
        return "warn"
    if any(w in low for w in ["allow", "healthy", "ready", "promoted", "start"]):
        return "success"
    return "info"


# ── Main HTML ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(_HTML)


_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FinanceFlow</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
  --bg:       #0c1220;
  --surface:  #111827;
  --card:     #1a2235;
  --border:   #1f2f47;
  --border2:  #2d3f5c;
  --text:     #e2e8f0;
  --muted:    #8899aa;
  --accent:   #3b82f6;
  --accent2:  #60a5fa;
  --green:    #22c55e;
  --red:      #ef4444;
  --amber:    #f59e0b;
  --purple:   #a78bfa;
  --cyan:     #22d3ee;
  --mono:     'JetBrains Mono', monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;font-size:14px;line-height:1.5;min-height:100vh}
a{color:var(--accent2);text-decoration:none}

/* ── Header ── */
#header{position:fixed;top:0;left:0;right:0;z-index:100;background:rgba(12,18,32,.95);backdrop-filter:blur(8px);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 24px;height:56px}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;letter-spacing:-.3px}
.logo-icon{width:28px;height:28px;background:var(--accent);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:800;color:#fff}
.logo-sub{font-size:11px;color:var(--muted);font-weight:400;letter-spacing:.5px;text-transform:uppercase}

/* ── Nav ── */
#nav{display:flex;gap:2px;align-items:center}
.tab{padding:6px 14px;border-radius:6px;color:var(--muted);cursor:pointer;font-size:13px;font-weight:500;transition:all .15s;border:none;background:none;white-space:nowrap}
.tab:hover{color:var(--text);background:rgba(255,255,255,.05)}
.tab.active{color:var(--accent2);background:rgba(59,130,246,.12)}

/* ── Toggle ── */
#guard-bar{display:flex;align-items:center;gap:10px;font-size:13px}
.guard-label{color:var(--muted);font-size:12px;font-weight:500;letter-spacing:.3px;text-transform:uppercase}
.guard-state{font-size:12px;font-weight:600;min-width:28px}
.guard-state.on{color:var(--green)}
.guard-state.off{color:var(--red)}
.toggle-wrap{position:relative;width:44px;height:24px;cursor:pointer}
.toggle-wrap input{opacity:0;width:0;height:0;position:absolute}
.toggle-slider{position:absolute;inset:0;background:#2d3f5c;border-radius:24px;transition:.2s}
.toggle-slider:before{content:'';position:absolute;height:18px;width:18px;left:3px;top:3px;background:#8899aa;border-radius:50%;transition:.2s}
.toggle-wrap input:checked + .toggle-slider{background:rgba(34,197,94,.25);border:1px solid var(--green)}
.toggle-wrap input:checked + .toggle-slider:before{transform:translateX(20px);background:var(--green)}

/* ── Layout ── */
#main{margin-top:56px;padding:24px;max-width:1400px;margin-left:auto;margin-right:auto;margin-top:56px}

/* ── Cards ── */
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.card-header{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.card-title{font-size:13px;font-weight:600;color:var(--text);letter-spacing:.2px}
.card-body{padding:18px}
.card-sm{padding:12px 16px}

/* ── Stat cards ── */
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
@media(max-width:900px){.stats-row{grid-template-columns:repeat(2,1fr)}}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:18px 20px}
.stat-label{font-size:11px;color:var(--muted);font-weight:500;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
.stat-val{font-size:26px;font-weight:700;letter-spacing:-1px}
.stat-sub{font-size:12px;color:var(--muted);margin-top:4px}
.stat-val.green{color:var(--green)}
.stat-val.red{color:var(--red)}
.stat-val.amber{color:var(--amber)}
.stat-val.blue{color:var(--accent2)}

/* ── Two-col grid ── */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:900px){.grid2{grid-template-columns:1fr}}
.grid3{display:grid;grid-template-columns:2fr 1fr 1fr;gap:14px}
@media(max-width:1100px){.grid3{grid-template-columns:1fr}}

/* ── Tables ── */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{padding:10px 14px;text-align:left;font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border)}
tbody tr{border-bottom:1px solid rgba(255,255,255,.04);transition:background .1s}
tbody tr:hover{background:rgba(255,255,255,.025)}
tbody td{padding:10px 14px;color:var(--text)}
tbody tr:last-child{border-bottom:none}

/* ── Badges ── */
.badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;letter-spacing:.3px;text-transform:uppercase}
.badge.green{background:rgba(34,197,94,.12);color:var(--green);border:1px solid rgba(34,197,94,.2)}
.badge.red{background:rgba(239,68,68,.12);color:var(--red);border:1px solid rgba(239,68,68,.2)}
.badge.amber{background:rgba(245,158,11,.12);color:var(--amber);border:1px solid rgba(245,158,11,.2)}
.badge.blue{background:rgba(59,130,246,.12);color:var(--accent2);border:1px solid rgba(59,130,246,.2)}
.badge.purple{background:rgba(167,139,250,.12);color:var(--purple);border:1px solid rgba(167,139,250,.2)}
.badge.muted{background:rgba(136,153,170,.08);color:var(--muted);border:1px solid rgba(136,153,170,.15)}
.dot{width:6px;height:6px;border-radius:50%;background:currentColor;display:inline-block}

/* ── Buttons ── */
.btn{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer;transition:all .15s;border:none;white-space:nowrap}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#2563eb}
.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--border2)}
.btn-ghost:hover{color:var(--text);border-color:var(--border2);background:rgba(255,255,255,.05)}
.btn-danger{background:rgba(239,68,68,.12);color:var(--red);border:1px solid rgba(239,68,68,.2)}
.btn-danger:hover{background:rgba(239,68,68,.2)}
.btn-green{background:rgba(34,197,94,.12);color:var(--green);border:1px solid rgba(34,197,94,.2)}
.btn-green:hover{background:rgba(34,197,94,.2)}
.btn:disabled{opacity:.4;cursor:not-allowed}

/* ── Log pane ── */
.log-pane{background:#080e18;border:1px solid var(--border);border-radius:8px;padding:14px;font-family:var(--mono);font-size:12px;line-height:1.7;height:380px;overflow-y:auto}
.log-line{display:flex;gap:10px;align-items:baseline}
.log-ts{color:#4a6080;min-width:58px;flex-shrink:0}
.log-svc{min-width:64px;flex-shrink:0;font-weight:500}
.log-msg{word-break:break-all}
.log-info .log-svc{color:var(--accent2)}
.log-success .log-svc{color:var(--green)}
.log-warn .log-svc{color:var(--amber)}
.log-error .log-svc{color:var(--red)}
.log-info .log-msg{color:#8faac4}
.log-success .log-msg{color:#a7e3c0}
.log-warn .log-msg{color:#e3c07a}
.log-error .log-msg{color:#e3a0a0}

/* ── Decision feed ── */
.decision-row{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:12px}
.decision-row:last-child{border-bottom:none}
.dec-ts{color:var(--muted);min-width:60px;font-family:var(--mono)}
.dec-agent{color:var(--muted);min-width:90px}
.dec-tool{color:var(--text);font-family:var(--mono);min-width:160px}
.dec-r{font-family:var(--mono);min-width:46px;color:var(--muted)}

/* ── Service health grid ── */
.svc-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
@media(max-width:800px){.svc-grid{grid-template-columns:repeat(2,1fr)}}
.svc-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center}
.svc-name{font-size:12px;font-weight:600;margin-top:6px}
.svc-dot{width:10px;height:10px;border-radius:50%;display:inline-block;margin-bottom:4px}
.svc-dot.up{background:var(--green);box-shadow:0 0 8px rgba(34,197,94,.5)}
.svc-dot.down{background:var(--red);box-shadow:0 0 8px rgba(239,68,68,.5)}
.svc-dot.unknown{background:var(--muted)}

/* ── Scenario cards ── */
.scenario-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px}
.scenario-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px}
.scenario-card h4{font-size:13px;font-weight:600;margin-bottom:4px}
.scenario-card p{font-size:12px;color:var(--muted);margin-bottom:12px;line-height:1.5}
.scenario-meta{display:flex;gap:6px;align-items:center;margin-bottom:10px;flex-wrap:wrap}

/* ── Demo output ── */
#demo-output{display:none}
.demo-step{display:flex;align-items:flex-start;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:12px}
.demo-step:last-child{border-bottom:none}
.step-num{width:22px;height:22px;border-radius:50%;background:var(--border);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0}
.step-num.blocked{background:rgba(239,68,68,.2);color:var(--red);border:1px solid rgba(239,68,68,.3)}
.step-num.allowed{background:rgba(34,197,94,.15);color:var(--green);border:1px solid rgba(34,197,94,.3)}
.step-num.quarantined{background:rgba(245,158,11,.15);color:var(--amber);border:1px solid rgba(245,158,11,.3)}
.step-tool{font-family:var(--mono);color:var(--text);font-weight:500}
.step-detail{color:var(--muted);margin-top:2px}

/* ── Prometheus table ── */
.prom-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
@media(max-width:800px){.prom-grid{grid-template-columns:repeat(2,1fr)}}
.prom-cell{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px 14px}
.prom-metric{font-size:11px;color:var(--muted);font-weight:500;text-transform:uppercase;letter-spacing:.4px}
.prom-val{font-size:22px;font-weight:700;font-family:var(--mono);margin-top:4px}

/* ── Misc ── */
.section-title{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:12px}
.row-sep{display:flex;align-items:center;gap:14px;margin-bottom:16px;flex-wrap:wrap}
.empty{padding:32px;text-align:center;color:var(--muted);font-size:13px}
.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600}
.pill.green{background:rgba(34,197,94,.1);color:var(--green)}
.pill.red{background:rgba(239,68,68,.1);color:var(--red)}
.ext-link-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}
.spin{animation:spin .8s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}
.hidden{display:none}
.tab-page{display:none}
.tab-page.active{display:block}
</style>
</head>
<body>

<!-- ── Header ── -->
<header id="header">
  <div style="display:flex;align-items:center;gap:32px">
    <div class="logo">
      <div class="logo-icon">FF</div>
      <div>
        <div>FinanceFlow</div>
        <div class="logo-sub">Enterprise Banking Platform</div>
      </div>
    </div>
    <nav id="nav">
      <button class="tab active" onclick="showTab('dashboard')">Dashboard</button>
      <button class="tab" onclick="showTab('accounts')">Accounts</button>
      <button class="tab" onclick="showTab('transactions')">Transactions</button>
      <button class="tab" onclick="showTab('demo')">Run Demo</button>
      <button class="tab" onclick="showTab('security')">Security Feed</button>
      <button class="tab" onclick="showTab('observability')">Observability</button>
    </nav>
  </div>
  <div id="guard-bar">
    <span class="guard-label">AgentGuard&#8209;X</span>
    <span class="guard-state on" id="guard-state-label">ON</span>
    <label class="toggle-wrap" title="Toggle AgentGuard-X enforcement">
      <input type="checkbox" id="guard-toggle" checked onchange="toggleEnforcement()">
      <span class="toggle-slider"></span>
    </label>
  </div>
</header>

<!-- ── Main content ── -->
<div id="main">

  <!-- ── Dashboard ── -->
  <div id="page-dashboard" class="tab-page active">
    <div class="stats-row" id="stat-row">
      <div class="stat-card">
        <div class="stat-label">Total Accounts</div>
        <div class="stat-val blue" id="s-accounts">—</div>
        <div class="stat-sub">Active accounts</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Portfolio Value</div>
        <div class="stat-val green" id="s-balance">—</div>
        <div class="stat-sub">Sum of all balances</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Transactions</div>
        <div class="stat-val" id="s-txns">—</div>
        <div class="stat-sub">On record</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Security Events</div>
        <div class="stat-val amber" id="s-events">—</div>
        <div class="stat-sub">Last 1h (AgentGuard-X)</div>
      </div>
    </div>

    <div class="grid2">
      <div class="card">
        <div class="card-header">
          <span class="card-title">Account Balances</span>
          <span class="badge blue">Live</span>
        </div>
        <div class="card-body" style="padding:0">
          <div class="tbl-wrap">
            <table>
              <thead><tr><th>Account</th><th>Owner</th><th>Type</th><th style="text-align:right">Balance</th></tr></thead>
              <tbody id="tbl-accounts-mini"></tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="card-title">Latest Security Decisions</span>
          <span id="decisions-badge" class="badge muted">Loading…</span>
        </div>
        <div class="card-body" style="padding:0 18px">
          <div id="decisions-mini" style="max-height:260px;overflow-y:auto"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Accounts ── -->
  <div id="page-accounts" class="tab-page">
    <div class="card">
      <div class="card-header"><span class="card-title">All Accounts</span></div>
      <div class="card-body" style="padding:0">
        <div class="tbl-wrap">
          <table>
            <thead><tr><th>Account Number</th><th>Owner</th><th>Type</th><th>Status</th><th style="text-align:right">Balance</th></tr></thead>
            <tbody id="tbl-accounts-full"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Transactions ── -->
  <div id="page-transactions" class="tab-page">
    <div class="card">
      <div class="card-header"><span class="card-title">Transaction History</span></div>
      <div class="card-body" style="padding:0">
        <div class="tbl-wrap">
          <table>
            <thead><tr><th>Time</th><th>Type</th><th>Merchant</th><th>Description</th><th style="text-align:right">Amount</th></tr></thead>
            <tbody id="tbl-txns"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Demo ── -->
  <div id="page-demo" class="tab-page">
    <div class="card" style="margin-bottom:16px">
      <div class="card-header">
        <span class="card-title">Demo Controls</span>
        <div style="display:flex;align-items:center;gap:12px;font-size:13px">
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;color:var(--muted)">
            <input type="checkbox" id="demo-enforcement" checked style="accent-color:var(--accent)">
            Enforcement ON
          </label>
          <span id="demo-running-badge" class="badge amber hidden"><span class="dot"></span> Running</span>
        </div>
      </div>
      <div class="card-body" style="padding:12px 18px">
        <p style="color:var(--muted);font-size:12px;line-height:1.6">
          Click <strong style="color:var(--text)">Run</strong> on any attack scenario below to execute it through the AgentGuard-X gateway callback.
          With <strong style="color:var(--green)">Enforcement ON</strong>, the kill chain stops on the first blocked step.
          With <strong style="color:var(--red)">Enforcement OFF</strong>, all steps execute and data exfiltrates (demo containment only — nothing leaves localhost).
          No Ollama required — these run the scripted tool-call path.
        </p>
      </div>
    </div>

    <div id="demo-output" class="card" style="margin-bottom:16px">
      <div class="card-header">
        <span class="card-title" id="demo-out-title">Scenario Output</span>
        <span id="demo-out-verdict" class="badge muted"></span>
      </div>
      <div class="card-body" style="padding:0 18px">
        <div id="demo-steps"></div>
      </div>
    </div>

    <div class="section-title">Attack Scenarios</div>
    <div class="scenario-grid" id="attack-cards"></div>
  </div>

  <!-- ── Security Feed ── -->
  <div id="page-security" class="tab-page">
    <div class="grid2">
      <div class="card">
        <div class="card-header">
          <span class="card-title">Live Decision Log</span>
          <div style="display:flex;gap:8px;align-items:center">
            <span id="feed-count" class="badge muted">0 events</span>
            <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" onclick="clearFeed()">Clear</button>
          </div>
        </div>
        <div class="card-body" style="padding:0 18px">
          <div id="security-feed" style="max-height:460px;overflow-y:auto"></div>
        </div>
      </div>

      <div>
        <div class="card" style="margin-bottom:14px">
          <div class="card-header">
            <span class="card-title">Analyst Hold Queue</span>
            <span id="holds-count" class="badge amber">0 pending</span>
          </div>
          <div class="card-body" style="padding:0 18px">
            <div id="holds-list" style="max-height:200px;overflow-y:auto">
              <div class="empty">No holds</div>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Verdict Distribution</span></div>
          <div class="card-body">
            <div id="verdict-dist" style="display:grid;grid-template-columns:1fr 1fr;gap:8px"></div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Observability ── -->
  <div id="page-observability" class="tab-page">
    <div class="card" style="margin-bottom:14px">
      <div class="card-header"><span class="card-title">Service Health</span></div>
      <div class="card-body">
        <div class="svc-grid" id="svc-health-grid"></div>
      </div>
    </div>

    <div class="card" style="margin-bottom:14px">
      <div class="card-header">
        <span class="card-title">Prometheus Metrics (last 1h)</span>
        <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" onclick="loadPrometheus()">Refresh</button>
      </div>
      <div class="card-body">
        <div class="prom-grid" id="prom-grid"></div>
      </div>
    </div>

    <div class="grid2" style="margin-bottom:14px">
      <div class="card">
        <div class="card-header"><span class="card-title">External Dashboards</span></div>
        <div class="card-body">
          <p style="color:var(--muted);font-size:12px;margin-bottom:14px">Open in a new browser tab for full dashboard experience.</p>
          <div class="ext-link-row">
            <a href="http://localhost:3000" target="_blank" class="btn btn-ghost">
              ⬡ Grafana Dashboard <span style="color:var(--muted);font-size:11px">:3000</span>
            </a>
            <a href="http://localhost:9090" target="_blank" class="btn btn-ghost">
              ◉ Prometheus <span style="color:var(--muted);font-size:11px">:9090</span>
            </a>
            <a href="http://localhost:8083" target="_blank" class="btn btn-ghost">
              ⏱ Analyst Queue <span style="color:var(--muted);font-size:11px">:8083</span>
            </a>
          </div>
          <p style="color:var(--muted);font-size:11px;margin-top:12px">
            Grafana credentials: <code style="color:var(--text)">admin / agentguard</code>
          </p>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Grafana Preview</span></div>
        <div class="card-body" style="padding:0">
          <iframe src="http://localhost:3000/d/agentguard-threats/agentguard-threats?orgId=1&theme=dark&kiosk"
            style="width:100%;height:260px;border:none;border-radius:0 0 10px 10px"
            onerror="this.style.display='none'" title="Grafana"></iframe>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">Container Log Stream</span>
        <div style="display:flex;gap:8px;align-items:center">
          <select id="log-filter" style="background:var(--surface);color:var(--text);border:1px solid var(--border2);border-radius:4px;padding:3px 8px;font-size:12px" onchange="filterLogs()">
            <option value="all">All services</option>
            <option value="gateway">gateway</option>
            <option value="triage">triage</option>
            <option value="proxy">proxy</option>
            <option value="analyst">analyst</option>
          </select>
          <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" onclick="startLogStream()">↺ Reconnect</button>
          <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" onclick="clearLogs()">Clear</button>
        </div>
      </div>
      <div class="log-pane" id="log-pane"></div>
    </div>
  </div>

</div><!-- /main -->

<script>
// ── State ──
let enforcement = true;
let statusInterval = null;
let logSource = null;
let feedEvents = [];
let verdictCounts = {allow:0, grey_band:0, block:0, block_short_circuit:0, block_stage1:0, quarantined:0};
let allLogLines = [];

// ── Tab switching ──
function showTab(name) {
  document.querySelectorAll('.tab-page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  document.querySelectorAll('.tab').forEach(t => {
    if (t.textContent.toLowerCase().includes(name) ||
        (name==='dashboard' && t.textContent==='Dashboard') ||
        (name==='accounts' && t.textContent==='Accounts') ||
        (name==='transactions' && t.textContent==='Transactions') ||
        (name==='demo' && t.textContent==='Run Demo') ||
        (name==='security' && t.textContent==='Security Feed') ||
        (name==='observability' && t.textContent==='Observability')) {
      t.classList.add('active');
    }
  });
  if (name === 'observability') { loadPrometheus(); startLogStream(); }
  if (name === 'demo') { loadScenarios(); }
}

// ── Toggle ──
async function toggleEnforcement() {
  const cb = document.getElementById('guard-toggle');
  try {
    const r = await fetch('/api/toggle', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({enforcement: cb.checked}),
    });
    const d = await r.json();
    enforcement = d.enforcement ?? cb.checked;
    updateToggleUI();
  } catch(e) {
    alert('Could not reach gateway: ' + e);
    cb.checked = !cb.checked;
  }
}

function updateToggleUI() {
  const lbl = document.getElementById('guard-state-label');
  lbl.textContent = enforcement ? 'ON' : 'OFF';
  lbl.className = 'guard-state ' + (enforcement ? 'on' : 'off');
  document.getElementById('guard-toggle').checked = enforcement;
}

// ── Status polling ──
async function loadStatus() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    enforcement = d.enforcement ?? enforcement;
    updateToggleUI();
    renderDecisionsMini(d.recent_decisions || []);
    renderHolds(d.holds || []);
    renderServiceHealth(d.services || {});
    document.getElementById('decisions-badge').textContent =
      (d.recent_decisions || []).length + ' recent';
    // Update security feed
    if (d.recent_decisions) {
      d.recent_decisions.forEach(dec => addFeedEvent(dec));
    }
  } catch(e) {}
}

async function loadAccounts() {
  try {
    const r = await fetch('/api/accounts');
    const accounts = await r.json();
    if (accounts.error) return;
    document.getElementById('s-accounts').textContent = accounts.length;
    const total = accounts.reduce((s,a) => s + a.balance, 0);
    document.getElementById('s-balance').textContent = '$' + total.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2});
    renderAccountsMini(accounts);
    renderAccountsFull(accounts);
  } catch(e) {}
}

async function loadTransactions() {
  try {
    const r = await fetch('/api/transactions');
    const txns = await r.json();
    if (txns.error) return;
    document.getElementById('s-txns').textContent = txns.length;
    renderTransactions(txns);
  } catch(e) {}
}

// ── Render helpers ──
function typeColor(t) {
  const m = {checking:'blue', savings:'green', investment:'purple'};
  return m[t] || 'muted';
}

function renderAccountsMini(accounts) {
  const tbody = document.getElementById('tbl-accounts-mini');
  tbody.innerHTML = accounts.map(a => `
    <tr>
      <td style="font-family:var(--mono);font-size:12px">${a.account_number}</td>
      <td>${a.owner_name}</td>
      <td><span class="badge ${typeColor(a.account_type)}">${a.account_type}</span></td>
      <td style="text-align:right;font-family:var(--mono);color:var(--green)">$${a.balance.toLocaleString('en-US',{minimumFractionDigits:2})}</td>
    </tr>`).join('');
}

function renderAccountsFull(accounts) {
  const tbody = document.getElementById('tbl-accounts-full');
  tbody.innerHTML = accounts.map(a => `
    <tr>
      <td style="font-family:var(--mono);font-size:12px">${a.account_number}</td>
      <td>${a.owner_name}</td>
      <td><span class="badge ${typeColor(a.account_type)}">${a.account_type}</span></td>
      <td><span class="badge ${a.is_active?'green':'red'}">${a.is_active?'Active':'Inactive'}</span></td>
      <td style="text-align:right;font-family:var(--mono);font-weight:600;color:var(--green)">$${a.balance.toLocaleString('en-US',{minimumFractionDigits:2})}</td>
    </tr>`).join('');
}

function renderTransactions(txns) {
  const tbody = document.getElementById('tbl-txns');
  tbody.innerHTML = txns.map(t => {
    const ts = t.timestamp ? new Date(t.timestamp).toLocaleString() : '—';
    const amtColor = t.tx_type === 'credit' ? 'var(--green)' : 'var(--red)';
    const sign = t.tx_type === 'credit' ? '+' : '-';
    return `<tr>
      <td style="font-size:12px;color:var(--muted)">${ts}</td>
      <td><span class="badge ${t.tx_type==='credit'?'green':'red'}">${t.tx_type}</span></td>
      <td>${t.merchant || '—'}</td>
      <td>${t.description}</td>
      <td style="text-align:right;font-family:var(--mono);color:${amtColor};font-weight:600">${sign}$${Math.abs(t.amount).toLocaleString('en-US',{minimumFractionDigits:2})}</td>
    </tr>`;
  }).join('');
}

function verdictBadge(v, r) {
  if (!v) return '';
  const m = {
    'allow': '<span class="badge green"><span class="dot"></span> ALLOW</span>',
    'grey_band': '<span class="badge amber"><span class="dot"></span> GREY</span>',
    'block': '<span class="badge red"><span class="dot"></span> BLOCK</span>',
    'block_short_circuit': '<span class="badge red"><span class="dot"></span> SHORT-CIRCUIT</span>',
    'block_stage1': '<span class="badge red"><span class="dot"></span> STAGE1</span>',
    'quarantined': '<span class="badge amber"><span class="dot"></span> QUARANTINE</span>',
  };
  const b = m[v] || `<span class="badge muted">${v}</span>`;
  const rStr = r != null ? `<span style="font-family:var(--mono);font-size:11px;color:var(--muted)">R=${parseFloat(r).toFixed(3)}</span>` : '';
  return b + ' ' + rStr;
}

function renderDecisionsMini(decisions) {
  const el = document.getElementById('decisions-mini');
  if (!decisions.length) { el.innerHTML = '<div class="empty">No decisions yet — run a demo scenario</div>'; return; }
  el.innerHTML = decisions.slice(0,12).map(d => `
    <div class="decision-row">
      <span class="dec-ts">${(d.ts||'').split('T')[1]?.slice(0,8)||'—'}</span>
      <span class="dec-agent" style="font-size:11px">${(d.agent_role||'?').padEnd(8)}</span>
      <span class="dec-tool">${d.tool_name||'—'}</span>
      <span class="dec-r">${d.r != null ? parseFloat(d.r).toFixed(3) : '—'}</span>
      ${verdictBadge(d.verdict)}
    </div>`).join('');
}

function renderHolds(holds) {
  const el = document.getElementById('holds-list');
  const pending = holds.filter(h => h.status === 'pending');
  document.getElementById('holds-count').textContent = pending.length + ' pending';
  if (!holds.length) { el.innerHTML = '<div class="empty">No holds</div>'; return; }
  el.innerHTML = holds.slice(0,8).map(h => {
    const sc = {pending:'amber', approved:'green', rejected:'red', expired:'muted'}[h.status] || 'muted';
    return `<div style="padding:8px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:12px;display:flex;align-items:center;gap:8px">
      <span class="badge ${sc}">${h.status}</span>
      <span style="font-family:var(--mono);color:var(--text)">${h.tool_name}</span>
      <span style="color:var(--muted)">${h.agent_id||''}</span>
      ${h.r_score != null ? `<span style="color:var(--muted);font-family:var(--mono);font-size:11px">R=${parseFloat(h.r_score).toFixed(3)}</span>` : ''}
    </div>`;
  }).join('');
}

// ── Security feed ──
function addFeedEvent(dec) {
  const key = (dec.ts||'') + (dec.tool_name||'') + (dec.verdict||'');
  if (feedEvents.includes(key)) return;
  feedEvents.push(key);
  if (feedEvents.length > 500) feedEvents = feedEvents.slice(-400);

  const v = dec.verdict || '';
  if (verdictCounts[v] !== undefined) verdictCounts[v]++;

  const el = document.getElementById('security-feed');
  const row = document.createElement('div');
  row.className = 'decision-row';
  row.innerHTML = `
    <span class="dec-ts">${(dec.ts||'').split('T')[1]?.slice(0,8)||'—'}</span>
    <span class="dec-agent" style="font-size:11px">${dec.type||'pre_hook'}</span>
    <span class="dec-tool">${dec.tool_name||'—'}</span>
    <span class="dec-r">${dec.r != null ? parseFloat(dec.r).toFixed(3) : '—'}</span>
    ${verdictBadge(dec.verdict)}
    ${dec.findings?.length ? `<span style="font-size:11px;color:var(--amber)" title="${dec.findings.join('; ')}">⚠ ${dec.findings.length} finding(s)</span>` : ''}
  `;
  el.insertBefore(row, el.firstChild);

  const total = Object.values(verdictCounts).reduce((a,b)=>a+b,0);
  document.getElementById('feed-count').textContent = total + ' events';
  renderVerdictDist();
}

function renderVerdictDist() {
  const el = document.getElementById('verdict-dist');
  const items = [
    {k:'allow', label:'Allow', cls:'green'},
    {k:'block', label:'Block', cls:'red'},
    {k:'block_short_circuit', label:'Short-Circuit', cls:'red'},
    {k:'grey_band', label:'Grey Band', cls:'amber'},
    {k:'quarantined', label:'Quarantined', cls:'amber'},
    {k:'block_stage1', label:'Stage-1 Gate', cls:'red'},
  ];
  el.innerHTML = items.map(i => `
    <div style="text-align:center;padding:10px;background:var(--surface);border:1px solid var(--border);border-radius:6px">
      <div style="font-size:20px;font-weight:700;font-family:var(--mono);color:var(--${i.cls})">${verdictCounts[i.k]||0}</div>
      <div style="font-size:11px;color:var(--muted);margin-top:2px">${i.label}</div>
    </div>`).join('');
}

function clearFeed() {
  feedEvents = [];
  verdictCounts = {allow:0, grey_band:0, block:0, block_short_circuit:0, block_stage1:0, quarantined:0};
  document.getElementById('security-feed').innerHTML = '';
  document.getElementById('feed-count').textContent = '0 events';
  renderVerdictDist();
}

// ── Service health ──
function renderServiceHealth(services) {
  const el = document.getElementById('svc-health-grid');
  const icons = {gateway:'⬡', triage:'◈', analyst:'⏱', proxy:'⛨', prometheus:'◉', grafana:'⬡', redis:'⬡'};
  const order = ['gateway','triage','analyst','proxy','prometheus'];
  el.innerHTML = order.map(svc => {
    const up = services[svc];
    const cls = up === true ? 'up' : up === false ? 'down' : 'unknown';
    return `<div class="svc-card">
      <span class="svc-dot ${cls}"></span>
      <div class="svc-name">${svc}</div>
      <div style="font-size:11px;color:var(--muted);margin-top:2px">${up === true ? 'Healthy' : up === false ? 'Unreachable' : 'Unknown'}</div>
    </div>`;
  }).join('');
}

// ── Prometheus ──
async function loadPrometheus() {
  try {
    const r = await fetch('/api/prometheus');
    const d = await r.json();
    const items = [
      {k:'total_checks', label:'Total Checks', color:'blue'},
      {k:'allowed', label:'Allowed', color:'green'},
      {k:'blocked', label:'Blocked', color:'red'},
      {k:'grey_band', label:'Grey Band', color:'amber'},
      {k:'hold_pending', label:'Holds Pending', color:'amber'},
      {k:'hold_approved', label:'Holds Approved', color:'green'},
      {k:'hold_expired', label:'Holds Expired', color:'red'},
      {k:'s2_short_circuits', label:'Short Circuits', color:'red'},
    ];
    document.getElementById('prom-grid').innerHTML = items.map(i => `
      <div class="prom-cell">
        <div class="prom-metric">${i.label}</div>
        <div class="prom-val" style="color:var(--${i.color})">${d[i.k] != null ? d[i.k] : '—'}</div>
      </div>`).join('');
  } catch(e) {
    document.getElementById('prom-grid').innerHTML = '<div style="color:var(--muted);font-size:12px;padding:8px">Prometheus unreachable. Start the stack with <code>docker compose up</code>.</div>';
  }
}

// ── Demo scenarios ──
async function loadScenarios() {
  try {
    const r = await fetch('/api/demo/scenarios');
    const d = await r.json();
    const container = document.getElementById('attack-cards');
    const owaspColor = {LLM01:'red', LLM02:'amber', LLM06:'purple', LLM07:'blue', LLM10:'red'};
    container.innerHTML = d.attacks.map(s => `
      <div class="scenario-card">
        <div class="scenario-meta">
          <span class="badge ${owaspColor[s.owasp]||'muted'}">${s.owasp}</span>
          <span class="badge muted">${s.role}</span>
          <span style="font-size:11px;color:var(--muted)">${s.steps} step${s.steps!==1?'s':''}</span>
        </div>
        <h4>${s.name.replace(/_/g,' ')}</h4>
        <p>${s.description}</p>
        <button class="btn btn-danger" onclick="runScenario('${s.name}')">▶ Run Attack</button>
      </div>`).join('');
  } catch(e) {}
}

function runScenario(name) {
  const enforcement = document.getElementById('demo-enforcement').checked;
  const outDiv = document.getElementById('demo-output');
  const stepsDiv = document.getElementById('demo-steps');
  const titleEl = document.getElementById('demo-out-title');
  const verdictEl = document.getElementById('demo-out-verdict');
  const badge = document.getElementById('demo-running-badge');

  outDiv.style.display = 'block';
  outDiv.scrollIntoView({behavior:'smooth', block:'start'});
  stepsDiv.innerHTML = '';
  titleEl.textContent = name.replace(/_/g,' ');
  verdictEl.className = 'badge amber';
  verdictEl.textContent = 'Running…';
  badge.classList.remove('hidden');

  const es = new EventSource(`/api/demo/run/${name}?enforcement=${enforcement}`);
  const stepEls = {};

  es.onmessage = (evt) => {
    const d = JSON.parse(evt.data);

    if (d.type === 'start') {
      stepsDiv.innerHTML = `<div style="padding:10px 0;color:var(--muted);font-size:12px">
        Session: <code style="color:var(--text)">${d.scenario}</code> &nbsp;|&nbsp;
        Role: <span class="badge muted">${d.role}</span> &nbsp;|&nbsp;
        OWASP: <span class="badge amber">${d.owasp}</span> &nbsp;|&nbsp;
        Enforcement: <span class="badge ${d.enforcement?'green':'red'}">${d.enforcement?'ON':'OFF'}</span>
      </div>`;
      return;
    }

    if (d.type === 'step_start') {
      const el = document.createElement('div');
      el.className = 'demo-step';
      el.id = 'step-' + d.step;
      el.innerHTML = `
        <div class="step-num">${d.step}</div>
        <div>
          <div class="step-tool">${d.tool} <span class="spin" style="color:var(--muted)">↻</span></div>
          <div class="step-detail">Input: <code style="color:var(--muted);font-size:11px">${JSON.stringify(d.input).slice(0,100)}</code></div>
        </div>`;
      stepsDiv.appendChild(el);
      stepEls[d.step] = el;
      return;
    }

    const el = stepEls[d.step];
    if (!el) return;

    if (d.type === 'step_blocked') {
      el.querySelector('.step-num').className = 'step-num blocked';
      el.querySelector('.step-tool').innerHTML = `${d.tool} ${verdictBadge(d.verdict, d.r)}`;
      el.querySelector('.step-detail').innerHTML = `<span style="color:var(--red)">⊘ ${d.reason || 'Blocked by AgentGuard-X'}</span>`;
    } else if (d.type === 'step_quarantined') {
      el.querySelector('.step-num').className = 'step-num quarantined';
      el.querySelector('.step-tool').innerHTML = `${d.tool} <span class="badge amber">QUARANTINED</span>`;
      el.querySelector('.step-detail').innerHTML = `<span style="color:var(--amber)">⚠ Output quarantined: ${(d.findings||[]).join('; ') || 'findings detected'}</span>`;
    } else if (d.type === 'step_allowed') {
      el.querySelector('.step-num').className = 'step-num allowed';
      el.querySelector('.step-tool').innerHTML = `${d.tool} ${verdictBadge(d.verdict, d.r)}`;
    } else if (d.type === 'step_executed') {
      el.querySelector('.step-detail').innerHTML += `<br><span style="color:var(--muted);font-size:11px">↳ ${d.output_preview?.slice(0,200)||''}</span>`;
    } else if (d.type === 'kill_chain_stopped') {
      const kc = document.createElement('div');
      kc.style.cssText = 'padding:10px 0;border-top:1px solid rgba(239,68,68,.2);margin-top:4px;font-size:12px;color:var(--red);font-weight:600';
      kc.textContent = '⊘ Kill chain stopped at step ' + d.step + ' — remaining steps not executed.';
      stepsDiv.appendChild(kc);
    } else if (d.type === 'scenario_complete') {
      badge.classList.add('hidden');
      const isBlocked = d.outcome === 'BLOCKED';
      verdictEl.className = 'badge ' + (isBlocked ? 'green' : 'red');
      verdictEl.textContent = isBlocked ? '✓ Attack Blocked' : '✗ Attack Succeeded';
      es.close();
    }
  };

  es.onerror = () => {
    badge.classList.add('hidden');
    es.close();
  };
}

// ── Docker log stream ──
function startLogStream() {
  if (logSource) { logSource.close(); logSource = null; }
  const pane = document.getElementById('log-pane');
  pane.innerHTML = '';

  logSource = new EventSource('/api/logs/stream');
  logSource.onmessage = (evt) => {
    const d = JSON.parse(evt.data);
    if (d.heartbeat) return;
    allLogLines.push(d);
    if (allLogLines.length > 2000) allLogLines = allLogLines.slice(-1500);
    appendLogLine(pane, d);
  };
  logSource.onerror = () => {};
}

function appendLogLine(pane, d) {
  const filter = document.getElementById('log-filter')?.value || 'all';
  if (filter !== 'all' && d.service !== filter) return;
  const div = document.createElement('div');
  div.className = `log-line log-${d.level||'info'}`;
  div.dataset.svc = d.service || '';
  div.innerHTML = `<span class="log-ts">${d.ts||''}</span><span class="log-svc">[${(d.service||'sys').slice(0,7)}]</span><span class="log-msg">${escHtml(d.line||'')}</span>`;
  pane.appendChild(div);
  // Auto-scroll if near bottom
  if (pane.scrollHeight - pane.scrollTop < pane.clientHeight + 120) {
    pane.scrollTop = pane.scrollHeight;
  }
  // Trim
  while (pane.children.length > 600) pane.removeChild(pane.firstChild);
}

function filterLogs() {
  const pane = document.getElementById('log-pane');
  const filter = document.getElementById('log-filter').value;
  pane.innerHTML = '';
  allLogLines.forEach(d => {
    if (filter === 'all' || d.service === filter) appendLogLine(pane, d);
  });
}

function clearLogs() {
  allLogLines = [];
  document.getElementById('log-pane').innerHTML = '';
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Dashboard security events count (from prometheus) ──
async function updateSecurityCount() {
  try {
    const r = await fetch('/api/prometheus');
    const d = await r.json();
    const total = (d.blocked||0) + (d.grey_band||0);
    document.getElementById('s-events').textContent = total != null ? total : '—';
  } catch(e) {}
}

// ── Startup ──
(async function init() {
  await loadAccounts();
  await loadTransactions();
  await loadStatus();
  await updateSecurityCount();
  renderVerdictDist();

  // Refresh every 5s
  setInterval(async () => {
    await loadStatus();
    await updateSecurityCount();
  }, 5000);

  // Refresh data less often
  setInterval(async () => {
    await loadAccounts();
    await loadTransactions();
  }, 30000);
})();
</script>
</body>
</html>
"""

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "financeflow.web.app:app",
        host="0.0.0.0",
        port=WEB_PORT,
        log_level="info",
        access_log=False,
    )
