"""Query interceptor — SQL/embedding query security layer (§12).

Defends against:
  - SQL injection in agent-constructed queries
  - Table/column RBAC violations
  - Query complexity abuse (full-table scans)
  - Vector store embedding inversion + enumeration

IMPORTANT: The SQL-injection DETECTOR itself is injection-safe — only parameterized checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class QueryDecision:
    allowed: bool
    findings: list[str] = field(default_factory=list)
    sanitized_query: str = ""


# SQL injection detection patterns (the detector itself uses regex, not SQL execution)
_SQL_INJECTION_PATTERNS = [
    re.compile(r";\s*(?:drop|delete|truncate|alter|create)\s+", re.IGNORECASE),
    re.compile(r"union\s+(?:all\s+)?select\s+", re.IGNORECASE),
    re.compile(r"'\s*or\s*'?\d+'?\s*=\s*'?\d+'?", re.IGNORECASE),  # classic ' OR '1'='1
    re.compile(r"--\s*$", re.MULTILINE),                             # SQL comment stripping
    re.compile(r"/\*.*?\*/", re.DOTALL),                             # block comment injection
    re.compile(r"xp_\w+", re.IGNORECASE),                           # MSSQL extended procedures
    re.compile(r"exec\s*\(", re.IGNORECASE),                         # SQL EXEC
    re.compile(r"0x[0-9a-f]{4,}", re.IGNORECASE),                   # hex injection
]

# Allowed tables per role (RBAC)
_TABLE_RBAC: dict[str, set[str]] = {
    "research": {"accounts"},
    "data": {"accounts", "transactions"},
    "admin": {"accounts", "transactions", "customers"},
}

_TABLE_PATTERN = re.compile(
    r"\bfrom\s+(\w+)|\bjoin\s+(\w+)|\binto\s+(\w+)|\bupdate\s+(\w+)",
    re.IGNORECASE,
)

# Query complexity: flag queries without WHERE that touch large tables
_FULL_SCAN_PATTERN = re.compile(
    r"\bselect\b.+\bfrom\b.+(?!\bwhere\b)",
    re.IGNORECASE | re.DOTALL,
)

# Embedding enumeration detection (vector store abuse)
_ENUM_PATTERNS = [
    re.compile(r"select\s+\*", re.IGNORECASE),  # SELECT * in vector context
]


class QueryInterceptor:
    """Intercepts agent-constructed queries before execution."""

    def check_sql(self, query: str, agent_role: str) -> QueryDecision:
        """Check a SQL query for injection, RBAC, and complexity issues."""
        findings = []

        # ── SQL injection detection ──────────────────────────────────────────
        for pat in _SQL_INJECTION_PATTERNS:
            if pat.search(query):
                findings.append(f"SQL injection pattern: {pat.pattern[:60]}")

        # ── Table RBAC ───────────────────────────────────────────────────────
        allowed_tables = _TABLE_RBAC.get(agent_role, set())
        for m in _TABLE_PATTERN.finditer(query):
            table = next(g for g in m.groups() if g is not None).lower()
            if table not in allowed_tables:
                findings.append(
                    f"Table RBAC violation: role '{agent_role}' "
                    f"cannot access table '{table}'"
                )

        # ── Query complexity (no unindexed full-table scans) ─────────────────
        if _FULL_SCAN_PATTERN.search(query) and "where" not in query.lower():
            findings.append("Query complexity: full-table scan without WHERE clause")

        allowed = not any("injection" in f or "RBAC" in f for f in findings)
        return QueryDecision(
            allowed=allowed,
            findings=findings,
            sanitized_query=query if allowed else "",
        )

    def check_vector_query(self, query: str, agent_role: str) -> QueryDecision:
        """Check a vector store query for enumeration/inversion attacks."""
        findings = []
        for pat in _ENUM_PATTERNS:
            if pat.search(query):
                findings.append("Vector store enumeration pattern detected")
        return QueryDecision(
            allowed=not findings,
            findings=findings,
            sanitized_query=query if not findings else "",
        )
