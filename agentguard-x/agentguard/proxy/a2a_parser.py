"""A2A (Agent-to-Agent) envelope parser for the TLS proxy.

Extracts agent identity and tool-call context from intercepted HTTP requests.
Sources (in priority order):
  1. Custom A2A headers set by the gateway pre-hook
  2. JSON request body introspection
  3. mTLS client certificate CN (if TLS client auth was negotiated)
  4. Safe defaults (least-privilege role, empty declared_tools)

A2A header schema:
  X-Agent-Identity   : <agent_id>
  X-Session-ID       : <session_id>
  X-Agent-Role       : research | data | admin
  X-Tool-Name        : <tool_name>
  X-Declared-Tools   : comma-separated list of declared tool names
  X-Request-ID       : correlation UUID

mTLS subject:
  When mutual TLS is negotiated, the client cert CN is treated as the authoritative
  agent identity. It overrides X-Agent-Identity if present.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Optional


VALID_ROLES = frozenset({"research", "data", "admin"})
LEAST_PRIVILEGE_ROLE = "research"


@dataclass
class A2AEnvelope:
    agent_id: str = "unknown"
    session_id: str = "unknown"
    tool_name: str = "unknown"
    agent_role: str = LEAST_PRIVILEGE_ROLE
    declared_tools: list[str] = field(default_factory=list)
    raw_payload: str = ""
    mtls_subject: Optional[str] = None
    request_id: str = ""

    def has_identity(self) -> bool:
        return self.agent_id != "unknown"

    def has_session(self) -> bool:
        return self.session_id != "unknown"

    def to_gateway_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "agent_role": self.agent_role,
            "tool_name": self.tool_name,
            "declared_tools": self.declared_tools,
            "raw_payload": self.raw_payload,
            "request_id": self.request_id,
            "mtls_subject": self.mtls_subject,
        }


def parse_envelope(request) -> A2AEnvelope:
    """Parse A2A envelope from a mitmproxy HTTPFlow.request object.

    Applies least-privilege defaults: unknown role → research, empty
    declared_tools stays empty (intent gate will deny if tool not declared).
    """
    headers = request.headers

    # 1. Extract custom A2A headers
    agent_id = headers.get("x-agent-identity", "unknown")
    session_id = headers.get("x-session-id", "unknown")
    tool_name = headers.get("x-tool-name", "unknown")
    request_id = headers.get("x-request-id", str(uuid.uuid4()))

    # Role validation: unknown or invalid role → least-privilege
    raw_role = headers.get("x-agent-role", LEAST_PRIVILEGE_ROLE).lower().strip()
    agent_role = raw_role if raw_role in VALID_ROLES else LEAST_PRIVILEGE_ROLE

    # Declared tools from header
    declared_hdr = headers.get("x-declared-tools", "")
    declared_tools = [t.strip() for t in declared_hdr.split(",") if t.strip()]

    # 2. JSON body introspection (fallback for tool_name)
    raw_payload = ""
    if request.content:
        try:
            raw_payload = request.content.decode("utf-8", errors="replace")
            if tool_name == "unknown":
                body = json.loads(raw_payload)
                tool_name = (
                    body.get("tool_name")
                    or body.get("tool")
                    or body.get("action")
                    or "unknown"
                )
                # Also check for declared tools in body
                if not declared_tools and "declared_tools" in body:
                    declared_tools = list(body["declared_tools"])
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            pass

    # 3. mTLS client cert CN override (highest-trust identity source)
    mtls_subject: Optional[str] = None
    if hasattr(request, "client_certs") and request.client_certs:
        cert = request.client_certs[0]
        if hasattr(cert, "subject"):
            mtls_subject = _extract_cn(cert.subject)
            if mtls_subject:
                agent_id = mtls_subject  # mTLS identity is authoritative

    return A2AEnvelope(
        agent_id=agent_id,
        session_id=session_id,
        tool_name=tool_name,
        agent_role=agent_role,
        declared_tools=declared_tools,
        raw_payload=raw_payload,
        mtls_subject=mtls_subject,
        request_id=request_id,
    )


def _extract_cn(subject) -> Optional[str]:
    """Extract CN value from a certificate subject (string or list of tuples)."""
    if isinstance(subject, str):
        for part in subject.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                return part[3:]
    elif isinstance(subject, (list, tuple)):
        for attr in subject:
            if hasattr(attr, "oid") and attr.oid.dotted_string == "2.5.4.3":
                return str(attr.value)
            if isinstance(attr, (list, tuple)) and len(attr) == 2:
                name, value = attr
                if str(name).upper() in ("CN", "COMMONNAME", "2.5.4.3"):
                    return str(value)
    return None
