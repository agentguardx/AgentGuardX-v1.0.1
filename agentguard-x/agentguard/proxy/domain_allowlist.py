"""Outbound domain allowlist for the TLS proxy.

Fail-closed: domain not on allowlist → BLOCK.
The allowlist is static for the PoC. Production would load from OPA.

Policy:
- Localhost / loopback: always allowed (local services).
- Docker internal bridge ranges (172.16-31.x.x, 10.x.x.x): allowed.
- Container short-hostnames: allowed (Docker Compose DNS).
- RFC-reserved test domains (.example, .test, .localhost): allowed.
- Everything else: BLOCK.

The exfil capture server (localhost:8099) is intentionally on the allowlist.
When enforcement is OFF, attacks reach it (demo phase 1).
When enforcement is ON, triage blocks the tool call before it reaches the proxy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# Patterns applied in order; first match wins.
# Compiled once at module load.
_ALLOWLIST: list[tuple[str, re.Pattern[str]]] = [
    # Loopback / localhost
    ("loopback-localhost",   re.compile(r"^localhost$")),
    ("loopback-ipv4",        re.compile(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$")),
    ("loopback-ipv6",        re.compile(r"^::1$")),
    # Docker bridge networks
    ("docker-bridge-172",    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}$")),
    ("docker-bridge-10",     re.compile(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$")),
    # Container short-hostnames (Docker Compose service names)
    ("container-financeflow", re.compile(r"^financeflow[\w-]*$")),
    ("container-agentguard",  re.compile(r"^agentguard[\w-]*$")),
    ("container-ollama",      re.compile(r"^ollama$")),
    ("container-redis",       re.compile(r"^redis$")),
    ("container-chromadb",    re.compile(r"^chromadb$")),
    ("container-opa",         re.compile(r"^opa$")),
    ("container-prometheus",  re.compile(r"^prometheus$")),
    ("container-grafana",     re.compile(r"^grafana$")),
    ("container-loki",        re.compile(r"^loki$")),
    # RFC-reserved test / example TLDs (safe for demo payloads)
    ("rfc-example-tld",       re.compile(r"^[a-z0-9][\w.-]*\.example$", re.IGNORECASE)),
    ("rfc-example-com",       re.compile(r"^[a-z0-9][\w.-]*\.example\.com$", re.IGNORECASE)),
    ("rfc-test-tld",          re.compile(r"^[a-z0-9][\w.-]*\.test$", re.IGNORECASE)),
    ("rfc-localhost-tld",     re.compile(r"^[a-z0-9][\w.-]*\.localhost$", re.IGNORECASE)),
    ("rfc-invalid-tld",       re.compile(r"^[a-z0-9][\w.-]*\.invalid$", re.IGNORECASE)),
]


@dataclass(frozen=True)
class DomainCheckResult:
    allowed: bool
    domain: str
    matched_pattern: str | None = None


def check_domain(host: str) -> DomainCheckResult:
    """Return a DomainCheckResult for the given host.

    Strips port suffix if present before matching.
    Handles IPv6 (::1, [::1]:port) and IPv4/hostname:port forms.
    Unknown host → allowed=False (fail-closed).
    """
    host = host.strip()
    if host.startswith("["):
        # Bracketed IPv6: [::1] or [::1]:8080 → extract ::1
        domain = host[1:host.find("]")] if "]" in host else host[1:]
    elif host.count(":") > 1:
        # Bare IPv6 address without port (multiple colons, no bracket)
        domain = host
    else:
        # IPv4 or hostname, possibly with :port
        domain = host.split(":")[0]
    domain = domain.strip().lower()

    for label, pattern in _ALLOWLIST:
        if pattern.match(domain):
            return DomainCheckResult(allowed=True, domain=domain, matched_pattern=label)

    return DomainCheckResult(allowed=False, domain=domain)
