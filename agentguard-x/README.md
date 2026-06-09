# AgentGuard-X

**AI Agent Security Middleware Mesh** — authorized man-in-the-middle in the agent's data path that reasons over sequence and scope, not individual packets.

## The Core Idea

Network/app-layer tools read packets. Agentic attacks live at the intent+behavior layer.
`GET /users` is fine, `POST /external` is fine — but **read-credentials → compress → post-external** is a kill chain where no single request looks wrong.

AgentGuard-X intercepts the agent's tool calls and evaluates the full request in context via a 5-stage triage engine. Every component exists to enable that.

## Quick Start (WSL2 Ubuntu + Docker)

```bash
git clone <repo>
cd agentguard-x

# Phase 0: Check host capabilities
./agentguard.sh preflight

# Start the full stack + seed KB
./agentguard.sh up

# Run the full before/after demo
./agentguard.sh demo
```

> **WSL2 note:** gVisor (runsc) requires KVM, which is typically unavailable under WSL2.
> Docker-only sandbox mode is the expected, fully-supported default. The `preflight` command
> detects this and prints a LOUD warning. gVisor-floor operations are BLOCKED, not downgraded.

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │         AgentGuard-X Middleware          │
                    │                                          │
Agent Tool Call ───>│  Gateway pre-hook → TLS proxy → Triage ─┤──> Tool (if allowed)
                    │      ↑ intent gate      ↑ 5 stages       │
                    │      ↑ RBAC             ↑ scoring R       │
                    │      ↑ rate limit       ↑ grey-band route │
                    │                                          │
Tool Response  ────>│  Gateway post-hook (Presidio + entropy)  │──> Agent (if clean)
                    └─────────────────────────────────────────┘
                              │                │
                         Prometheus          Loki
                         Grafana            (always on)
```

### 5-Stage Triage Engine

| Stage | What | Weight |
|-------|------|--------|
| S1 | Identity + Context (binary hard gate) | — |
| S2 | Signature matching (pyahocorasick) | 0.35 |
| S3 | OPA policy / RBAC | 0.30 |
| S4 | Semantic RAG (all-MiniLM-L6-v2 + ChromaDB) | 0.20 |
| S5 | Behavioral context (Redis sliding window) | 0.15 |

**Scoring formula:**
```
base  = 0.35·S2 + 0.30·S3 + 0.20·S4 + 0.15·S5
k     = count of voting stages (score ≥ 0.5)
a_bar = mean of voting stage scores
bonus = 0.4 · max(0, k-1) · a_bar · (1 - base)
R     = min(1.0, base + bonus)

R < 0.25        → ALLOW
0.25 ≤ R ≤ 0.85 → GREY BAND (sandbox or hold)
R > 0.85        → BLOCK
S2 ≥ 0.95       → SHORT-CIRCUIT BLOCK (<2ms)
```

**Headline invariant:** A composite block is mathematically impossible with <2 voting stages.
Single-signal block only via Stage-2 short-circuit at 0.95 certainty.

### Grey-Band Routing (§11)

Reversibility determines the physical route, not the score:
- **Reversible ops** → sandbox + async analyst review
- **Irreversible ops** → cheap-gate pre-filter → synchronous hold-with-timeout → **BLOCK on expiry** (never allow-on-timeout)

### PoC Toggle

```bash
./agentguard.sh toggle off   # Observe-only: attacks succeed, dashboards show them
./agentguard.sh toggle on    # Full enforcement: attacks blocked/held
```

**Observability is always on** regardless of toggle state.

## OWASP Coverage

| Category | Detection |
|----------|-----------|
| LLM01 | Aho-Corasick + indirect injection scan in post-hook |
| LLM02 | Presidio PII scan on tool outputs |
| LLM03 | Tool RBAC via OPA (untrusted by default) |
| LLM04 | Behavioral drift S5 + no online learning |
| LLM05 | Post-hook: Presidio + entropy + indirect injection |
| LLM06 | OPA RBAC: tools/resources/rate per role |
| LLM07 | Aho-Corasick extraction probe signatures |
| LLM10 | Sliding-window rate limit + kill-chain detection in S5 |

## Services

| Service | Port | Description |
|---------|------|-------------|
| Gateway | 8080 | Cognitive gateway HTTP API |
| Triage | 8081 | 5-stage triage engine |
| OPA | 8181 | Policy engine (Rego) |
| Redis | 6379 | Session store + rate limits + embed cache |
| ChromaDB | 8888 | Vector KB (threat patterns) |
| Prometheus | 9090 | Metrics |
| Grafana | 3000 | Dashboards (admin / agentguard) |
| Loki | 3100 | Log aggregation |
| FinanceFlow exfil | 8099 | Demo exfil capture server |
| Ollama | 11434 | Local LLM (llama3.2) |

## Testing

```bash
# All unit tests (no external dependencies required)
cd agentguard-x
python -m pytest tests/unit/ -v

# The 4 golden scoring cases + headline invariant must always pass
python -m pytest tests/unit/test_scoring.py -v

# Fail-closed edge cases
python -m pytest tests/unit/test_fail_closed.py -v
```

## Security

See [SECURITY.md](SECURITY.md). Report issues to agentguardx@gmail.com — do NOT open public GitHub issues for security vulnerabilities.

## License

Apache-2.0. See [LICENSE](LICENSE).
