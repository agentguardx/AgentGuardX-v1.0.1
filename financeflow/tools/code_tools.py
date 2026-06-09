"""execute_code tool — simulated code execution (gVisor isolation floor).

In production this would execute inside a gVisor sandbox.
For the demo: executes a very restricted subset of Python expressions
in a sandboxed eval context with no imports or builtins.

This tool demonstrates:
  - LLM06: Excessive agency (code execution)
  - The gVisor isolation floor requirement (see §0 and §13)
  - Why code execution ops are BLOCKED when gVisor is unavailable (WSL2 default)

SECURITY NOTE: The demo simulation intentionally restricts what runs.
The real AgentGuard-X path blocks this tool outright when runsc is unavailable.
"""

from __future__ import annotations

import ast
import sys
from typing import Any

from langchain_core.tools import tool


# Whitelist of safe AST node types for demo simulation
_ALLOWED_NODES = frozenset({
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Compare,
    ast.Constant, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod,
    ast.Pow, ast.USub, ast.UAdd, ast.Eq, ast.NotEq, ast.Lt,
    ast.LtE, ast.Gt, ast.GtE, ast.BoolOp, ast.And, ast.Or, ast.Not,
    ast.Name, ast.IfExp,
})


def _is_safe_expression(code: str) -> bool:
    try:
        tree = ast.parse(code.strip(), mode="eval")
        for node in ast.walk(tree):
            if type(node) not in _ALLOWED_NODES:
                return False
        return True
    except SyntaxError:
        return False


@tool
def execute_code_tool(code: str, language: str = "python") -> str:
    """Execute a code snippet (SIMULATED — restricted sandbox in demo).

    In a production AgentGuard-X deployment this would run inside a
    gVisor (runsc) container. On WSL2 without KVM, this operation is
    BLOCKED by AgentGuard-X as gVisor unavailable.

    For the FinanceFlow standalone demo, this evaluates simple arithmetic
    expressions only — no imports, no I/O, no real execution.

    Args:
        code: Code snippet to execute.
        language: Programming language (only 'python' supported in demo).

    Returns:
        Execution result or error.

    OWASP: LLM06 (Excessive Agency)
    Reversibility: IRREVERSIBLE (gVisor isolation floor required)
    Risk tier: CRITICAL
    """
    if language.lower() != "python":
        return f"ERROR: Only 'python' supported in demo mode. Got: {language}"

    print(
        f"[execute_code] CODE EXECUTION ATTEMPTED:\n  {code[:200]}",
        file=sys.stderr,
    )

    # Demo simulation: only allow safe arithmetic/comparison expressions
    code_stripped = code.strip()

    if not _is_safe_expression(code_stripped):
        return (
            f"CODE EXECUTION (SIMULATED SANDBOX)\n"
            f"Code: {code_stripped[:100]}\n"
            f"Result: [BLOCKED by demo sandbox — only arithmetic expressions allowed]\n"
            f"Note: In production, this would run in a gVisor container.\n"
            f"      AgentGuard-X blocks this operation when gVisor is unavailable."
        )

    try:
        # Safe eval: no builtins, no globals beyond math constants
        result: Any = eval(  # noqa: S307 — intentionally restricted
            compile(code_stripped, "<demo>", "eval"),
            {"__builtins__": {}},
            {},
        )
        return (
            f"CODE EXECUTION (SIMULATED SANDBOX)\n"
            f"Code:   {code_stripped}\n"
            f"Result: {result}\n"
            f"Note: In production, this runs in gVisor. Blocked on WSL2 without KVM."
        )
    except Exception as e:
        return f"CODE EXECUTION ERROR: {type(e).__name__}: {e}"
