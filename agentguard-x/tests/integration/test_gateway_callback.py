"""Integration tests for AgentGuardGatewayCallback.

All tests are unit-style (no running gateway, no Docker). httpx.post is
mocked via unittest.mock.patch so the callback logic is exercised in isolation.

Coverage:
  - Allow path (gateway 200)
  - Block path enforcement=on  → PermissionError
  - Block path enforcement=off → no exception (observe-only)
  - Gateway unreachable enforcement=on  → PermissionError (fail-closed)
  - Gateway unreachable enforcement=off → no exception
  - Posthook clean scan → no exception
  - Posthook quarantined enforcement=on  → ValueError
  - Posthook quarantined enforcement=off → no exception
  - Posthook unreachable → never raises (non-fatal)
  - Helper: declared_tools_for_role
  - Helper: reversibility
  - call_seq accumulates tool names
"""

from __future__ import annotations

import sys
import os

# Ensure the agentguard-x root is on sys.path so `integration` package is found.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from unittest.mock import MagicMock, patch

import pytest

from integration.gateway_callback import (
    AgentGuardGatewayCallback,
    declared_tools_for_role,
    reversibility,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_callback(enforcement: bool = True) -> AgentGuardGatewayCallback:
    return AgentGuardGatewayCallback(
        agent_id="financeflow-admin",
        agent_role="admin",
        gateway_url="http://gateway-test:8080",
        enforcement=enforcement,
        session_id="test-session-001",
    )


def _mock_response(status_code: int, body: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    return resp


# ── Pre-execution (on_tool_start) ─────────────────────────────────────────────

class TestOnToolStart:
    def test_allow_response_does_not_raise(self):
        cb = _make_callback(enforcement=True)
        ok_resp = _mock_response(200, {"allowed": True, "verdict": "allow", "r": 0.1})
        with patch("httpx.post", return_value=ok_resp):
            cb.on_tool_start({"name": "get_account_tool"}, '{"account_id": "FF-001"}')
        # no exception

    def test_block_403_enforcement_on_raises_permission_error(self):
        cb = _make_callback(enforcement=True)
        block_resp = _mock_response(403, {
            "allowed": False,
            "verdict": "block_short_circuit",
            "reason": "exfil kill chain",
            "r": 0.97,
        })
        with patch("httpx.post", return_value=block_resp):
            with pytest.raises(PermissionError) as exc_info:
                cb.on_tool_start({"name": "post_external_tool"}, '{"url": "http://attacker-c2.example"}')
        assert "[AgentGuard-X] BLOCKED" in str(exc_info.value)
        assert "exfil kill chain" in str(exc_info.value)

    def test_block_403_enforcement_off_does_not_raise(self):
        cb = _make_callback(enforcement=False)
        block_resp = _mock_response(403, {"allowed": False, "verdict": "block", "reason": "test"})
        with patch("httpx.post", return_value=block_resp):
            cb.on_tool_start({"name": "transfer_funds_tool"}, '{"amount": 50000}')
        # observe-only — no exception

    def test_gateway_unreachable_enforcement_on_raises_fail_closed(self):
        import httpx as _httpx
        cb = _make_callback(enforcement=True)
        with patch("httpx.post", side_effect=_httpx.ConnectError("connection refused")):
            with pytest.raises(PermissionError) as exc_info:
                cb.on_tool_start({"name": "transfer_funds_tool"}, '{}')
        assert "fail-closed" in str(exc_info.value)

    def test_gateway_unreachable_enforcement_off_does_not_raise(self):
        import httpx as _httpx
        cb = _make_callback(enforcement=False)
        with patch("httpx.post", side_effect=_httpx.ConnectError("connection refused")):
            cb.on_tool_start({"name": "get_account_tool"}, '{}')
        # observe-only — no exception

    def test_call_seq_accumulates_tool_names(self):
        cb = _make_callback(enforcement=False)
        ok_resp = _mock_response(200, {"allowed": True, "verdict": "allow", "r": 0.05})
        with patch("httpx.post", return_value=ok_resp):
            cb.on_tool_start({"name": "get_account_tool"}, '{}')
            cb.on_tool_start({"name": "read_customer_pii_tool"}, '{}')
        assert cb._call_seq == ["get_account_tool", "read_customer_pii_tool"]

    def test_unknown_tool_name_defaults_to_unknown(self):
        cb = _make_callback(enforcement=False)
        ok_resp = _mock_response(200, {"allowed": True, "verdict": "allow", "r": 0.05})
        posted_payload = {}
        def capture_post(url, json, timeout):
            posted_payload.update(json)
            return ok_resp
        with patch("httpx.post", side_effect=capture_post):
            cb.on_tool_start({}, '{}')  # no "name" key in serialized
        assert posted_payload.get("tool_name") == "unknown"


# ── Post-execution (on_tool_end) ──────────────────────────────────────────────

class TestOnToolEnd:
    def test_clean_scan_does_not_raise(self):
        cb = _make_callback(enforcement=True)
        cb._call_seq = ["get_account_tool"]
        clean_resp = _mock_response(200, {
            "clean": True, "quarantined": False, "findings": [], "sanitized_output": None,
        })
        with patch("httpx.post", return_value=clean_resp):
            cb.on_tool_end("Account balance: $1,234.56")
        # no exception

    def test_quarantined_enforcement_on_raises_value_error(self):
        cb = _make_callback(enforcement=True)
        cb._call_seq = ["read_customer_pii_tool"]
        quarantine_resp = _mock_response(200, {
            "clean": False,
            "quarantined": True,
            "findings": ["Credential pattern matched (LLM05)"],
            "sanitized_output": "[QUARANTINED] output blocked",
        })
        with patch("httpx.post", return_value=quarantine_resp):
            with pytest.raises(ValueError) as exc_info:
                cb.on_tool_end("AKIAIOSFODNN7EXAMPLE secret data here")
        assert "QUARANTINED" in str(exc_info.value)

    def test_quarantined_enforcement_off_does_not_raise(self):
        cb = _make_callback(enforcement=False)
        cb._call_seq = ["read_customer_pii_tool"]
        quarantine_resp = _mock_response(200, {
            "clean": False,
            "quarantined": True,
            "findings": ["High-entropy token (LLM05)"],
            "sanitized_output": "[QUARANTINED]",
        })
        with patch("httpx.post", return_value=quarantine_resp):
            cb.on_tool_end("some high entropy output")
        # observe-only — no exception

    def test_posthook_unreachable_never_raises(self):
        import httpx as _httpx
        cb = _make_callback(enforcement=True)
        cb._call_seq = ["get_account_tool"]
        with patch("httpx.post", side_effect=_httpx.ConnectError("offline")):
            cb.on_tool_end("some output")
        # posthook is best-effort — never raises on connection failure

    def test_posthook_non_200_response_skipped_silently(self):
        cb = _make_callback(enforcement=True)
        cb._call_seq = ["get_account_tool"]
        error_resp = _mock_response(503, {})
        with patch("httpx.post", return_value=error_resp):
            cb.on_tool_end("output")
        # no exception on non-200

    def test_tool_name_falls_back_to_unknown_when_seq_empty(self):
        cb = _make_callback(enforcement=True)
        # _call_seq is empty — tool_name should be "unknown"
        posted = {}
        def capture_post(url, json, timeout):
            posted.update(json)
            return _mock_response(200, {"clean": True, "quarantined": False, "findings": []})
        with patch("httpx.post", side_effect=capture_post):
            cb.on_tool_end("output")
        assert posted.get("tool_name") == "unknown"


# ── Helper functions ──────────────────────────────────────────────────────────

class TestHelpers:
    def test_declared_tools_research(self):
        tools = declared_tools_for_role("research")
        assert "get_account_tool" in tools
        assert "transfer_funds_tool" not in tools
        assert "execute_code_tool" not in tools

    def test_declared_tools_admin_has_all(self):
        tools = declared_tools_for_role("admin")
        for expected in [
            "get_account_tool", "transfer_funds_tool", "execute_code_tool",
            "post_external_tool", "read_customer_pii_tool",
        ]:
            assert expected in tools, f"{expected} missing from admin tools"

    def test_declared_tools_unknown_role_returns_empty(self):
        assert declared_tools_for_role("superuser") == []

    def test_reversibility_read_tool_is_reversible(self):
        assert reversibility("get_account_tool") == "reversible"

    def test_reversibility_transfer_is_irreversible(self):
        assert reversibility("transfer_funds_tool") == "irreversible"

    def test_reversibility_post_external_is_irreversible(self):
        assert reversibility("post_external_tool") == "irreversible"

    def test_reversibility_unknown_tool_is_irreversible(self):
        # Unknown tools default to irreversible (conservative)
        assert reversibility("some_unknown_tool") == "irreversible"


# ── Enforcement property ──────────────────────────────────────────────────────

class TestEnforcementProperty:
    def test_enforcement_on_by_default(self):
        cb = _make_callback(enforcement=True)
        assert cb.enforcement is True

    def test_enforcement_off(self):
        cb = _make_callback(enforcement=False)
        assert cb.enforcement is False
