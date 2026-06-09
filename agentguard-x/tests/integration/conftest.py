"""Integration test conftest — stubs heavy runtime dependencies.

gateway_callback.py requires `httpx` and `langchain-core`. In a developer
environment running tests against the system Python (without the full venv),
these may not be installed. This conftest stubs only what the integration
tests need so they can run anywhere pytest runs.

All httpx.post calls are overridden per-test via unittest.mock.patch anyway,
so the stub default implementation is never reached in normal test execution.
"""

import sys
import types
from unittest.mock import MagicMock


def _install_stub(name: str, stub: types.ModuleType) -> None:
    """Register stub only if the real package is absent."""
    if name not in sys.modules:
        sys.modules[name] = stub


# ── httpx stub ────────────────────────────────────────────────────────────────
if "httpx" not in sys.modules:
    class _ConnectError(OSError):
        """Minimal httpx.ConnectError stub — real exception subclass."""

    class _TimeoutException(Exception):
        """Minimal httpx.TimeoutException stub."""

    class _MockResponse:
        def __init__(self, status_code: int = 200, body: dict | None = None):
            self.status_code = status_code
            self._body = body or {}

        def json(self) -> dict:
            return self._body

    def _stub_post(url: str, *, json=None, timeout=None, **kwargs) -> _MockResponse:
        # Default stub returns 200 allow; per-test mocks override this.
        return _MockResponse(200, {"allowed": True, "verdict": "allow", "r": 0.0,
                                   "clean": True, "quarantined": False, "findings": []})

    _httpx = types.ModuleType("httpx")
    _httpx.post = _stub_post                    # type: ignore[attr-defined]
    _httpx.ConnectError = _ConnectError         # type: ignore[attr-defined]
    _httpx.TimeoutException = _TimeoutException # type: ignore[attr-defined]
    sys.modules["httpx"] = _httpx


# ── langchain_core stub ───────────────────────────────────────────────────────
if "langchain_core" not in sys.modules:
    class _BaseCallbackHandler:
        raise_error: bool = False

        def __init__(self, *args, **kwargs):
            pass

    _lc_core = types.ModuleType("langchain_core")
    _lc_callbacks = types.ModuleType("langchain_core.callbacks")
    _lc_callbacks.BaseCallbackHandler = _BaseCallbackHandler  # type: ignore[attr-defined]

    _lc_core.callbacks = _lc_callbacks  # type: ignore[attr-defined]
    sys.modules["langchain_core"] = _lc_core
    sys.modules["langchain_core.callbacks"] = _lc_callbacks
