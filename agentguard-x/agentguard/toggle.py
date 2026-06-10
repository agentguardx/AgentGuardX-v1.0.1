"""PoC toggle — controls enforcement vs. observe-only mode (§2).

Toggle ON:  every layer enforces — gateway pre/post hooks, TLS proxy, triage, sandbox, holds.
Toggle OFF: proxy passes through; hooks register but pass through without enforcing.
            OBSERVABILITY STAYS FULLY ON regardless of toggle state.

The toggle is a first-class concept: surface in agentguard.sh, dashboard, and this module.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

_TOGGLE_FILE = Path(os.getenv("TOGGLE_FILE", ".toggle_state"))
_ENV_KEY = "AGENTGUARD_ENFORCEMENT"

EnforcementState = Literal["on", "off"]


def get_enforcement() -> bool:
    """Return True if enforcement is ON, False if observe-only.

    Priority: toggle file > env var > default True.
    The file allows the web UI toggle to override the env-var default at runtime.
    Observability is ALWAYS active regardless of this flag.
    """
    # 1. Toggle file (highest priority — allows runtime web UI override)
    if _TOGGLE_FILE.exists():
        try:
            state = _TOGGLE_FILE.read_text().strip().lower()
            if state in ("on", "off"):
                return state == "on"
        except OSError:
            pass

    # 2. Env var (sets the default when no file exists yet)
    env_val = os.getenv(_ENV_KEY, "").lower()
    if env_val in ("true", "on", "1", "yes"):
        return True
    if env_val in ("false", "off", "0", "no"):
        return False

    return True  # default: enforcement ON


def set_enforcement(state: EnforcementState) -> None:
    """Set the toggle state. Called by agentguard.sh toggle and API endpoint."""
    _TOGGLE_FILE.write_text(state)


def enforcement_is_on() -> bool:
    return get_enforcement()
