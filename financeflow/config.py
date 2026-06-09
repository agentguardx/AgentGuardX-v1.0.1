"""FinanceFlow configuration — read from environment, no hardcoded secrets."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# ── LLM (Ollama) ──────────────────────────────────────────────────────────────
OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "120"))

# ── Database ──────────────────────────────────────────────────────────────────
DATABASE_URL: str = os.getenv(
    "DATABASE_URL", f"sqlite:///{DATA_DIR / 'financeflow.db'}"
)

# ── Exfil capture server (the one controlled "real" external element) ─────────
EXFIL_CAPTURE_HOST: str = os.getenv("EXFIL_CAPTURE_HOST", "localhost")
EXFIL_CAPTURE_PORT: int = int(os.getenv("EXFIL_CAPTURE_PORT", "8099"))
EXFIL_CAPTURE_URL: str = os.getenv(
    "EXFIL_CAPTURE_URL",
    f"http://{EXFIL_CAPTURE_HOST}:{EXFIL_CAPTURE_PORT}/capture",
)

# ── Agent settings ────────────────────────────────────────────────────────────
AGENT_MAX_ITERATIONS: int = int(os.getenv("AGENT_MAX_ITERATIONS", "10"))
AGENT_VERBOSE: bool = os.getenv("AGENT_VERBOSE", "true").lower() == "true"

# ── Runner ────────────────────────────────────────────────────────────────────
RUNNER_HOST: str = os.getenv("RUNNER_HOST", "0.0.0.0")
RUNNER_PORT: int = int(os.getenv("RUNNER_PORT", "8000"))
