"""TLS inspection proxy — mitmproxy addon + domain allowlist + A2A envelope parsing.

The proxy operates as an explicit HTTP/HTTPS proxy (HTTP_PROXY env var).
mitmproxy auto-generates its CA on first start (never committed to git).
The addon calls the gateway /v1/proxy/check endpoint for every intercepted request.
"""

from .domain_allowlist import DomainCheckResult, check_domain
from .a2a_parser import A2AEnvelope, parse_envelope

__all__ = [
    "DomainCheckResult",
    "check_domain",
    "A2AEnvelope",
    "parse_envelope",
]
