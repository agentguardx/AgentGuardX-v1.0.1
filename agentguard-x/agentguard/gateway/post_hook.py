"""Post-execution hook — LLM05 surface. Treats tool outputs as ATTACK SURFACE.

Scans tool responses for:
  1. PII (Presidio) — LLM02
  2. Credentials/secrets (regex + Shannon entropy) — LLM05
  3. Indirect injection (embedded instructions in data) — LLM05

NOTE (§12): detection != neutralization.
A detected injection QUARANTINES the response — it is NOT passed silently to the agent.
The quarantine decision is logged. The agent receives a sanitized "data unavailable" notice.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PostHookResult:
    clean: bool
    pii_detected: bool = False
    credential_detected: bool = False
    injection_detected: bool = False
    findings: list[str] = field(default_factory=list)
    quarantined: bool = False
    sanitized_output: Optional[str] = None


# ── Credential/entropy patterns ────────────────────────────────────────────────
# All regex patterns here use SYNTHETIC examples — never real credential formats.
# The patterns match the SHAPE of credentials, not specific values.
CREDENTIAL_PATTERNS = [
    # AWS-style key (synthetic — matches shape, AKIA_EXAMPLE_NOT_A_REAL_KEY would match)
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    # Generic API key shape: "key_<32+ alphanumeric chars>"
    re.compile(r"\b(?:api_key|apikey|api-key)\s*[:=]\s*[A-Za-z0-9_\-]{16,}", re.IGNORECASE),
    # Bearer token shape
    re.compile(r"\bBearer\s+[A-Za-z0-9\-_\.]{20,}", re.IGNORECASE),
    # Generic secret
    re.compile(r"\b(?:secret|password|passwd|token)\s*[:=]\s*[^\s\"']{8,}", re.IGNORECASE),
]

# Indirect injection markers (things that should NOT appear in data responses)
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(your\s+)?(?:previous\s+|all\s+)?instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now", re.IGNORECASE),
    re.compile(r"new\s+(?:system\s+)?prompt\s*:", re.IGNORECASE),
    re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior)\s+", re.IGNORECASE),
    re.compile(r"system\s+override", re.IGNORECASE),
    re.compile(r"your\s+new\s+task", re.IGNORECASE),
]

# Shannon entropy threshold for credential detection
ENTROPY_THRESHOLD = 4.5  # bits per character; high entropy → likely encoded secret
MIN_HIGH_ENTROPY_LENGTH = 20  # only flag strings long enough to be meaningful


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {c: text.count(c) / len(text) for c in set(text)}
    return -sum(p * math.log2(p) for p in freq.values() if p > 0)


def _detect_high_entropy_strings(text: str) -> list[str]:
    """Find tokens that look like encoded secrets (high entropy, sufficient length)."""
    found = []
    for token in re.findall(r"[A-Za-z0-9+/=_\-]{" + str(MIN_HIGH_ENTROPY_LENGTH) + r",}", text):
        if _shannon_entropy(token) >= ENTROPY_THRESHOLD:
            found.append(token[:50] + "...")
    return found


class PostHookProcessor:
    """Scans tool outputs before they reach the agent.

    Called from the LangChain callback's on_tool_end hook.
    """

    def __init__(self, presidio_engine=None) -> None:
        self._presidio = presidio_engine  # None = Presidio unavailable (graceful degradation)

    def scan(self, tool_output: str, tool_name: str) -> PostHookResult:
        result = PostHookResult(clean=True)
        findings = []

        # ── 1. PII scan (Presidio) ────────────────────────────────────────────
        if self._presidio is not None:
            try:
                pii_results = self._presidio.analyze(
                    text=tool_output, language="en"
                )
                if pii_results:
                    result.pii_detected = True
                    types = {r.entity_type for r in pii_results}
                    findings.append(f"PII detected (LLM02): {', '.join(sorted(types))}")
            except Exception as e:
                findings.append(f"Presidio error (skipped): {e}")

        # ── 2. Credential/secret scan ─────────────────────────────────────────
        for pat in CREDENTIAL_PATTERNS:
            if pat.search(tool_output):
                result.credential_detected = True
                findings.append(f"Credential pattern matched (LLM05): {pat.pattern[:60]}")
                break

        # High-entropy tokens
        entropy_hits = _detect_high_entropy_strings(tool_output)
        if entropy_hits:
            result.credential_detected = True
            findings.append(f"High-entropy token (LLM05): possible secret in output")

        # ── 3. Indirect injection detection ──────────────────────────────────
        for pat in INJECTION_PATTERNS:
            if pat.search(tool_output):
                result.injection_detected = True
                findings.append(
                    f"Indirect injection marker (LLM05): '{pat.pattern[:60]}' in tool output. "
                    f"NOTE: detection != neutralization — response QUARANTINED."
                )
                break

        # ── 4. Quarantine decision ─────────────────────────────────────────────
        if result.pii_detected or result.credential_detected or result.injection_detected:
            result.clean = False
            result.quarantined = True
            result.sanitized_output = (
                f"[QUARANTINED by AgentGuard-X] Tool '{tool_name}' output contained "
                f"security findings and has been blocked from reaching the agent. "
                f"Findings: {'; '.join(findings)}"
            )

        result.findings = findings
        return result
