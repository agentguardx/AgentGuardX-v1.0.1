"""Unit tests for Phase 6 — TLS proxy domain allowlist and A2A envelope parser.

No mitmproxy or network dependencies required.
"""

from __future__ import annotations

import pytest

from agentguard.proxy.domain_allowlist import check_domain
from agentguard.proxy.a2a_parser import (
    A2AEnvelope,
    parse_envelope,
    LEAST_PRIVILEGE_ROLE,
    VALID_ROLES,
)


# ── Domain allowlist ──────────────────────────────────────────────────────────
class TestDomainAllowlist:
    def test_localhost_allowed(self):
        assert check_domain("localhost").allowed is True

    def test_loopback_ipv4_allowed(self):
        assert check_domain("127.0.0.1").allowed is True

    def test_loopback_ipv6_allowed(self):
        assert check_domain("::1").allowed is True

    def test_docker_bridge_172_allowed(self):
        assert check_domain("172.17.0.2").allowed is True
        assert check_domain("172.31.0.1").allowed is True

    def test_docker_bridge_10_allowed(self):
        assert check_domain("10.0.0.1").allowed is True
        assert check_domain("10.255.255.255").allowed is True

    def test_financeflow_container_allowed(self):
        assert check_domain("financeflow-exfil").allowed is True
        assert check_domain("financeflow-runner").allowed is True

    def test_agentguard_container_allowed(self):
        assert check_domain("agentguard-gateway").allowed is True
        assert check_domain("agentguard-triage").allowed is True

    def test_ollama_allowed(self):
        assert check_domain("ollama").allowed is True

    def test_redis_allowed(self):
        assert check_domain("redis").allowed is True

    def test_rfc_example_tld_allowed(self):
        assert check_domain("api.example").allowed is True
        assert check_domain("exfil.target.example").allowed is True

    def test_rfc_example_com_allowed(self):
        assert check_domain("somehost.example.com").allowed is True

    def test_rfc_test_tld_allowed(self):
        assert check_domain("myserver.test").allowed is True

    def test_rfc_localhost_tld_allowed(self):
        assert check_domain("myapp.localhost").allowed is True

    def test_unknown_domain_blocked(self):
        result = check_domain("evil.attacker.com")
        assert result.allowed is False
        assert result.matched_pattern is None

    def test_google_blocked(self):
        assert check_domain("google.com").allowed is False

    def test_aws_blocked(self):
        assert check_domain("s3.amazonaws.com").allowed is False

    def test_port_stripped_before_check(self):
        assert check_domain("localhost:8080").allowed is True
        assert check_domain("172.17.0.2:9000").allowed is True

    def test_fails_closed_for_empty_domain(self):
        result = check_domain("")
        assert result.allowed is False

    def test_non_docker_private_ip_blocked(self):
        # 192.168.x.x is NOT in the allowlist
        result = check_domain("192.168.1.1")
        assert result.allowed is False


# ── A2A envelope parser ───────────────────────────────────────────────────────
class FakeRequest:
    """Minimal mock of a mitmproxy request for testing."""
    def __init__(
        self,
        headers: dict | None = None,
        body: bytes = b"",
    ) -> None:
        self.headers = headers or {}
        self.content = body


class TestA2AParser:
    def test_parse_headers_all_present(self):
        req = FakeRequest(headers={
            "x-agent-identity": "agent-alice",
            "x-session-id": "sess-001",
            "x-agent-role": "data",
            "x-tool-name": "read_customer_pii_tool",
            "x-declared-tools": "read_customer_pii_tool,get_account_tool",
            "x-request-id": "req-abc",
        })
        env = parse_envelope(req)
        assert env.agent_id == "agent-alice"
        assert env.session_id == "sess-001"
        assert env.agent_role == "data"
        assert env.tool_name == "read_customer_pii_tool"
        assert "read_customer_pii_tool" in env.declared_tools
        assert "get_account_tool" in env.declared_tools
        assert env.request_id == "req-abc"

    def test_unknown_role_defaults_to_least_privilege(self):
        req = FakeRequest(headers={"x-agent-role": "superadmin"})
        env = parse_envelope(req)
        assert env.agent_role == LEAST_PRIVILEGE_ROLE

    def test_missing_role_defaults_to_least_privilege(self):
        req = FakeRequest()
        env = parse_envelope(req)
        assert env.agent_role == LEAST_PRIVILEGE_ROLE

    def test_all_valid_roles_accepted(self):
        for role in VALID_ROLES:
            req = FakeRequest(headers={"x-agent-role": role})
            env = parse_envelope(req)
            assert env.agent_role == role

    def test_json_body_fallback_tool_name(self):
        import json
        body = json.dumps({"tool_name": "transfer_funds_tool", "amount": 1000}).encode()
        req = FakeRequest(body=body)
        env = parse_envelope(req)
        assert env.tool_name == "transfer_funds_tool"

    def test_json_body_tool_field_fallback(self):
        import json
        body = json.dumps({"tool": "send_email_tool"}).encode()
        req = FakeRequest(body=body)
        env = parse_envelope(req)
        assert env.tool_name == "send_email_tool"

    def test_header_takes_priority_over_body(self):
        import json
        body = json.dumps({"tool_name": "body_tool"}).encode()
        req = FakeRequest(
            headers={"x-tool-name": "header_tool"},
            body=body,
        )
        env = parse_envelope(req)
        assert env.tool_name == "header_tool"

    def test_no_headers_no_body_safe_defaults(self):
        req = FakeRequest()
        env = parse_envelope(req)
        assert env.agent_id == "unknown"
        assert env.session_id == "unknown"
        assert env.tool_name == "unknown"
        assert env.agent_role == LEAST_PRIVILEGE_ROLE
        assert env.declared_tools == []

    def test_declared_tools_parsed_from_csv(self):
        req = FakeRequest(headers={
            "x-declared-tools": "get_account_tool, run_report_tool,  fetch_market_data_tool",
        })
        env = parse_envelope(req)
        assert env.declared_tools == [
            "get_account_tool", "run_report_tool", "fetch_market_data_tool"
        ]

    def test_empty_declared_tools_header(self):
        req = FakeRequest(headers={"x-declared-tools": ""})
        env = parse_envelope(req)
        assert env.declared_tools == []

    def test_to_gateway_dict_includes_required_fields(self):
        req = FakeRequest(headers={
            "x-agent-identity": "agent-bob",
            "x-tool-name": "get_account_tool",
        })
        env = parse_envelope(req)
        d = env.to_gateway_dict()
        required = {"agent_id", "session_id", "agent_role", "tool_name", "declared_tools", "raw_payload"}
        assert required.issubset(d.keys())

    def test_garbage_json_body_handled_gracefully(self):
        req = FakeRequest(body=b"{not valid json!!")
        env = parse_envelope(req)
        assert env.tool_name == "unknown"  # graceful fallback, no exception

    def test_has_identity_false_for_unknown(self):
        env = A2AEnvelope()
        assert env.has_identity() is False

    def test_has_identity_true_when_set(self):
        env = A2AEnvelope(agent_id="real-agent")
        assert env.has_identity() is True
