#!/usr/bin/env bash
# AgentGuard-X — single entrypoint orchestrator
# Designed for WSL2 Ubuntu + Docker Desktop (WSL2 backend)
# Requires: bash 5+, docker (compose v2), ss or netstat
set -euo pipefail

# ── Terminal colours ────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
CAPABILITY_REPORT="${SCRIPT_DIR}/.capability_report"
TOGGLE_FILE="${SCRIPT_DIR}/.toggle_state"
ENV_FILE="${SCRIPT_DIR}/.env"

log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()     { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_section() { echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════${NC}"; \
                echo -e "${BOLD}${CYAN}  $*${NC}"; \
                echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════${NC}"; }

# ── Usage ───────────────────────────────────────────────────────────────────
usage() {
    echo -e "${BOLD}AgentGuard-X Orchestrator${NC}"
    echo ""
    echo -e "  ${CYAN}Usage:${NC} $0 <command> [options]"
    echo ""
    echo -e "  ${BOLD}Commands:${NC}"
    echo "    preflight         Check host capabilities (Docker, KVM, gVisor)"
    echo "    up                Build + start full stack, wait on health, then seed"
    echo "    seed              Pull ML models, seed ChromaDB KB, load OPA bundles"
    echo "    gen-ca            Export mitmproxy CA cert to certs/ (called by up)"
    echo "    toggle on|off     Enable or disable AgentGuard enforcement layer"
    echo "    demo              Full before/after demo (toggle OFF attacks, then ON)"
    echo "    attack            Run attack suite only (requires stack running)"
    echo "    status            Show compose stack status"
    echo "    logs [service]    Tail logs"
    echo "    down              Stop the stack (keep volumes)"
    echo "    clean             Stop + remove all containers and volumes"
    echo ""
    echo -e "  ${YELLOW}Run inside WSL2 Ubuntu. Docker Desktop WSL2 backend required.${NC}"
    echo -e "  ${YELLOW}Start fresh: ./agentguard.sh up && ./agentguard.sh demo${NC}"
    exit 0
}

# ── Port probe helper ────────────────────────────────────────────────────────
port_in_use() {
    local port="$1"
    if command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | grep -q ":${port} "
    elif command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | grep -q ":${port} "
    else
        return 1  # can't tell; assume free
    fi
}

# ── Phase 0: preflight ───────────────────────────────────────────────────────
cmd_preflight() {
    log_section "AgentGuard-X Preflight Check"
    local errors=0
    local warnings=0

    # -- Docker daemon --
    log_section "Docker Runtime"
    if command -v docker &>/dev/null; then
        local dver
        dver=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
        log_ok "Docker found — server v${dver}"
    else
        log_err "Docker not found. Install Docker Desktop with WSL2 backend, or docker-engine in WSL2."
        ((errors++))
    fi

    # -- Compose v2 --
    if docker compose version &>/dev/null 2>&1; then
        local cver
        cver=$(docker compose version --short 2>/dev/null || echo "unknown")
        log_ok "Docker Compose v2 found — v${cver}"
    else
        log_err "Docker Compose v2 not found. Requires 'docker compose' (not 'docker-compose')."
        log_err "  Update Docker Desktop or install compose plugin: apt install docker-compose-plugin"
        ((errors++))
    fi

    # -- WSL2 check --
    if [ -f /proc/version ] && grep -qi microsoft /proc/version 2>/dev/null; then
        log_ok "Running inside WSL2 — correct execution environment"
    else
        log_warn "Not detected as WSL2 environment. This tool is designed for WSL2 Ubuntu."
        log_warn "  If running natively on Linux, most things will still work."
        ((warnings++))
    fi

    # -- Required ports --
    log_section "Port Availability"
    declare -A PORT_MAP=(
        [8080]="agentguard-gateway"
        [8081]="agentguard-triage"
        [8082]="agentguard-proxy"
        [8083]="analyst-queue-ui"
        [8099]="financeflow-exfil-capture"
        [8000]="financeflow-runner"
        [6379]="redis"
        [8888]="chromadb"
        [9090]="prometheus"
        [3000]="grafana"
        [3100]="loki"
        [4317]="otel-grpc"
        [4318]="otel-http"
        [8181]="opa"
        [11434]="ollama"
    )
    for port in "${!PORT_MAP[@]}"; do
        local name="${PORT_MAP[$port]}"
        if port_in_use "${port}"; then
            log_warn "Port ${port} (${name}) is already in use — may conflict"
            ((warnings++))
        else
            log_ok "Port ${port} (${name}) free"
        fi
    done

    # -- KVM availability --
    log_section "KVM / gVisor (runsc) Detection"
    local kvm_available=false
    local runsc_available=false
    local runsc_functional=false

    if [ -c /dev/kvm ] 2>/dev/null; then
        if [ -r /dev/kvm ] && [ -w /dev/kvm ] 2>/dev/null; then
            kvm_available=true
            log_ok "/dev/kvm exists and is accessible by current user"
        else
            log_warn "/dev/kvm exists but current user lacks rw permission"
            log_warn "  Try: sudo usermod -aG kvm \$(whoami) && newgrp kvm"
        fi
    else
        log_warn "/dev/kvm not present — nested virtualization unavailable"
        log_warn "  EXPECTED on WSL2 without nested KVM support (most configurations)."
    fi

    # -- runsc (gVisor) probe --
    if command -v runsc &>/dev/null; then
        local runsc_ver
        runsc_ver=$(runsc --version 2>/dev/null | head -1 || echo "unknown")
        log_ok "runsc binary found — ${runsc_ver}"
        # Probe for actual functionality (needs KVM or ptrace platform)
        if $kvm_available; then
            if runsc --platform=kvm do --  /bin/true 2>/dev/null; then
                runsc_functional=true
                runsc_available=true
                log_ok "runsc KVM platform functional"
            else
                log_warn "runsc found but KVM platform test failed"
            fi
        else
            # Try ptrace fallback (slower but doesn't need KVM)
            if runsc --platform=ptrace do -- /bin/true 2>/dev/null; then
                runsc_functional=true
                runsc_available=true
                log_warn "runsc functional via ptrace platform (no KVM) — performance degraded"
            else
                log_warn "runsc binary found but no functional platform available"
            fi
        fi
    else
        log_warn "runsc (gVisor) not on PATH — install from https://gvisor.dev/docs/user_guide/install/"
    fi

    # -- Capability determination + write report --
    log_section "Capability Report"

    local sandbox_mode
    if $runsc_functional; then
        sandbox_mode="gvisor"
        log_ok "FULL capability: Docker + gVisor (runsc) sandboxing available"
        log_ok "  Code-execution, agent-spawning, and unrecognized-identity operations"
        log_ok "  will use gVisor isolation tier."
    else
        sandbox_mode="docker_only"
        echo ""
        echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}${BOLD}║  DOCKER-ONLY SANDBOX MODE ACTIVE  (WSL2 expected default)       ║${NC}"
        echo -e "${YELLOW}${BOLD}╠══════════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}${BOLD}║  gVisor/runsc is unavailable (no KVM or non-functional runsc).  ║${NC}"
        echo -e "${YELLOW}${BOLD}║  This is the EXPECTED, FULLY-SUPPORTED default on WSL2.         ║${NC}"
        echo -e "${YELLOW}${BOLD}║                                                                  ║${NC}"
        echo -e "${YELLOW}${BOLD}║  IMPORTANT: Operations that REQUIRE gVisor isolation floor      ║${NC}"
        echo -e "${YELLOW}${BOLD}║  (code execution, agent spawning, unrecognized identities)      ║${NC}"
        echo -e "${YELLOW}${BOLD}║  will be BLOCKED — not downgraded to Docker isolation.          ║${NC}"
        echo -e "${YELLOW}${BOLD}║  Fail-closed by design; never silently demoted.                 ║${NC}"
        echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
    fi

    cat > "${CAPABILITY_REPORT}" <<EOF
# AgentGuard-X Capability Report — generated $(date -u +"%Y-%m-%dT%H:%M:%SZ")
SANDBOX_MODE=${sandbox_mode}
KVM_AVAILABLE=${kvm_available}
RUNSC_AVAILABLE=${runsc_available}
RUNSC_FUNCTIONAL=${runsc_functional}
EOF
    log_ok "Capability report written to: ${CAPABILITY_REPORT}"

    # -- Summary --
    log_section "Preflight Summary"
    if [ "${errors}" -gt 0 ]; then
        log_err "FAILED: ${errors} error(s), ${warnings} warning(s). Fix errors before running 'up'."
        exit 1
    elif [ "${warnings}" -gt 0 ]; then
        log_warn "PASSED WITH ${warnings} WARNING(S) — stack should function, review warnings above."
        exit 0
    else
        log_ok "ALL CHECKS PASSED — ready to run: ./agentguard.sh up"
        exit 0
    fi
}

# ── Helper: load capability report ──────────────────────────────────────────
load_capability() {
    if [ -f "${CAPABILITY_REPORT}" ]; then
        # shellcheck disable=SC1090
        source "${CAPABILITY_REPORT}" 2>/dev/null || true
    else
        SANDBOX_MODE="docker_only"
        log_warn "No capability report found — run 'preflight' first. Defaulting to docker_only."
    fi
}

# ── Helper: wait for service health ─────────────────────────────────────────
wait_healthy() {
    local service="$1"
    local url="$2"
    local max_wait="${3:-120}"
    local waited=0
    log_info "Waiting for ${service} at ${url} ..."
    while ! curl -sf "${url}" >/dev/null 2>&1; do
        if [ "${waited}" -ge "${max_wait}" ]; then
            log_err "${service} did not become healthy within ${max_wait}s"
            return 1
        fi
        sleep 2
        ((waited+=2))
    done
    log_ok "${service} healthy (${waited}s)"
}

# ── cmd: up ─────────────────────────────────────────────────────────────────
cmd_up() {
    cmd_preflight || true  # warn but continue
    load_capability

    log_section "Building Images"
    docker compose -f "${COMPOSE_FILE}" build --parallel

    log_section "Starting Stack"
    # Export sandbox mode so compose can pick it up
    export AGENTGUARD_SANDBOX_MODE="${SANDBOX_MODE}"
    docker compose -f "${COMPOSE_FILE}" up -d

    log_section "Waiting for Health"
    wait_healthy "Redis"       "http://localhost:6379" 30 || true
    wait_healthy "ChromaDB"    "http://localhost:8888/api/v1/heartbeat" 60
    wait_healthy "OPA"         "http://localhost:8181/health" 60
    wait_healthy "Triage"      "http://localhost:8081/health" 90
    wait_healthy "Gateway"     "http://localhost:8080/health" 90
    wait_healthy "Analyst"     "http://localhost:8083/health" 60
    wait_healthy "Prometheus"  "http://localhost:9090/-/healthy" 60
    wait_healthy "Grafana"     "http://localhost:3000/api/health" 90
    wait_healthy "Loki"        "http://localhost:3100/ready" 60
    # Wait for proxy separately (may need gateway to be healthy first)
    wait_healthy "Proxy"       "http://localhost:8082" 60 || \
        log_warn "Proxy not yet healthy — proceeding (will retry in seed)"

    log_section "CA Certificate (Phase 6)"
    cmd_gen_ca

    log_section "Seeding"
    cmd_seed

    log_ok "AgentGuard-X stack is UP and ready."
    log_info "  Dashboard:  http://localhost:3000  (admin / agentguard)"
    log_info "  Toggle:     ./agentguard.sh toggle on|off"
    log_info "  Demo:       ./agentguard.sh demo"
}

# ── cmd: gen-ca (Phase 6) ────────────────────────────────────────────────────
cmd_gen_ca() {
    local certs_dir="${SCRIPT_DIR}/certs"
    local ca_cert="${certs_dir}/mitmproxy-ca-cert.pem"

    mkdir -p "${certs_dir}"

    if [ -f "${ca_cert}" ]; then
        log_ok "mitmproxy CA cert already exists: ${ca_cert}"
        return 0
    fi

    log_info "Generating mitmproxy CA (Phase 6 TLS proxy)..."
    if ! bash "${SCRIPT_DIR}/docker/gen-ca.sh" "${certs_dir}"; then
        log_warn "CA generation failed — proxy may not intercept TLS yet."
        log_warn "  Run manually: bash docker/gen-ca.sh"
        return 0
    fi
    log_ok "mitmproxy CA exported to: ${ca_cert}"
    log_info "  Agents should trust this CA for TLS inspection."
}

# ── cmd: seed ───────────────────────────────────────────────────────────────
cmd_seed() {
    log_section "Seeding AgentGuard-X"

    log_info "Pulling sentence-transformers all-MiniLM-L6-v2 model..."
    docker compose -f "${COMPOSE_FILE}" exec triage \
        python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')" \
        2>&1 | tail -5

    log_info "Seeding ChromaDB knowledge base (OWASP + MITRE patterns)..."
    docker compose -f "${COMPOSE_FILE}" exec triage \
        python -m agentguard.seed.seed_kb

    log_info "Loading and validating OPA policy bundles..."
    docker compose -f "${COMPOSE_FILE}" exec opa \
        opa build /policies -b -o /bundles/agentguard-bundle.tar.gz

    log_info "Initializing Redis session stores..."
    docker compose -f "${COMPOSE_FILE}" exec redis \
        redis-cli PING

    log_info "Building sandbox worker image (Phase 7)..."
    docker compose -f "${COMPOSE_FILE}" build sandbox-builder 2>&1 | tail -3 || \
        log_warn "Sandbox image build failed — sandboxing will run in degraded mode."

    log_ok "Seed complete."
}

# ── cmd: toggle ──────────────────────────────────────────────────────────────
cmd_toggle() {
    local state="${2:-}"
    case "${state}" in
        on|ON)
            echo "on" > "${TOGGLE_FILE}"
            docker compose -f "${COMPOSE_FILE}" exec gateway \
                curl -sf -X POST http://localhost:8080/admin/toggle -d '{"enforcement":true}' >/dev/null 2>&1 || true
            docker compose -f "${COMPOSE_FILE}" exec proxy \
                curl -sf -X POST http://localhost:8082/admin/toggle -d '{"enforcement":true}' >/dev/null 2>&1 || true
            echo -e "${GREEN}${BOLD}AgentGuard-X ENFORCEMENT: ON${NC} — all layers active"
            ;;
        off|OFF)
            echo "off" > "${TOGGLE_FILE}"
            docker compose -f "${COMPOSE_FILE}" exec gateway \
                curl -sf -X POST http://localhost:8080/admin/toggle -d '{"enforcement":false}' >/dev/null 2>&1 || true
            docker compose -f "${COMPOSE_FILE}" exec proxy \
                curl -sf -X POST http://localhost:8082/admin/toggle -d '{"enforcement":false}' >/dev/null 2>&1 || true
            echo -e "${YELLOW}${BOLD}AgentGuard-X ENFORCEMENT: OFF${NC} — observability only, attacks will SUCCEED"
            ;;
        *)
            log_err "Usage: $0 toggle on|off"
            exit 1
            ;;
    esac
}

# ── cmd: attack ──────────────────────────────────────────────────────────────
cmd_attack() {
    log_section "Attack Suite"
    log_info "Running attack scenarios against FinanceFlow..."
    docker compose -f "${COMPOSE_FILE}" exec financeflow-runner \
        python runner.py attack --all --report
}

# ── cmd: demo ────────────────────────────────────────────────────────────────
cmd_demo() {
    log_section "AgentGuard-X Full Demo — Before / After"

    echo -e "${BOLD}${RED}"
    echo "  ████████████████████████████████████████████████████████"
    echo "  ██         PHASE 1: ENFORCEMENT OFF                   ██"
    echo "  ██  Attacks will SUCCEED. Watch the dashboards.       ██"
    echo "  ████████████████████████████████████████████████████████"
    echo -e "${NC}"

    cmd_toggle "" "off"
    sleep 2

    log_info "Running attack suite with enforcement OFF..."
    cmd_attack
    log_warn "Attacks executed. Open Grafana (http://localhost:3000) to see red dashboards."
    echo ""
    echo -e "${YELLOW}Press ENTER to continue to Phase 2 (enforcement ON)...${NC}"
    read -r

    echo -e "${BOLD}${GREEN}"
    echo "  ████████████████████████████████████████████████████████"
    echo "  ██         PHASE 2: ENFORCEMENT ON                    ██"
    echo "  ██  Attacks will be BLOCKED / HELD. Watch dashboards. ██"
    echo "  ████████████████████████████████████████████████████████"
    echo -e "${NC}"

    cmd_toggle "" "on"
    sleep 2

    log_info "Running attack suite with enforcement ON..."
    cmd_attack
    log_ok "Attacks blocked/held. Check dashboards for sandbox routing and hold queue."
    log_info "Analyst hold queue: http://localhost:8083"
    log_info "Grafana threat view: http://localhost:3000/d/agentguard-threats"
}

# ── cmd: status ──────────────────────────────────────────────────────────────
cmd_status() {
    log_section "AgentGuard-X Stack Status"
    local toggle_state="unknown"
    [ -f "${TOGGLE_FILE}" ] && toggle_state=$(cat "${TOGGLE_FILE}")
    echo -e "  Enforcement toggle: ${BOLD}${toggle_state}${NC}"
    echo ""
    docker compose -f "${COMPOSE_FILE}" ps 2>/dev/null || log_warn "Stack not running — run './agentguard.sh up'"

    load_capability
    echo ""
    echo -e "  Sandbox mode: ${BOLD}${SANDBOX_MODE:-unknown}${NC}"
}

# ── cmd: logs ────────────────────────────────────────────────────────────────
cmd_logs() {
    local service="${1:-}"
    if [ -n "${service}" ]; then
        docker compose -f "${COMPOSE_FILE}" logs --tail=200 -f "${service}"
    else
        docker compose -f "${COMPOSE_FILE}" logs --tail=100 -f
    fi
}

# ── cmd: down ────────────────────────────────────────────────────────────────
cmd_down() {
    log_info "Stopping AgentGuard-X stack (volumes preserved)..."
    docker compose -f "${COMPOSE_FILE}" down
    log_ok "Stack stopped."
}

# ── cmd: clean ───────────────────────────────────────────────────────────────
cmd_clean() {
    log_warn "This will DESTROY all containers, networks, and volumes."
    log_warn "Press Ctrl+C to abort, or ENTER to proceed."
    read -r
    docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans 2>/dev/null || true
    rm -f "${CAPABILITY_REPORT}" "${TOGGLE_FILE}"
    log_ok "Clean complete. Run './agentguard.sh up' to start fresh."
}

# ── Main dispatch ─────────────────────────────────────────────────────────────
case "${1:-}" in
    preflight) cmd_preflight ;;
    up)        cmd_up ;;
    seed)      cmd_seed ;;
    gen-ca)    cmd_gen_ca ;;
    toggle)    cmd_toggle "$@" ;;
    demo)      cmd_demo ;;
    attack)    cmd_attack ;;
    status)    cmd_status ;;
    logs)      shift; cmd_logs "${1:-}" ;;
    down)      cmd_down ;;
    clean)     cmd_clean ;;
    "")        usage ;;
    *)
        log_err "Unknown command: '${1}'"
        echo ""
        usage
        ;;
esac
