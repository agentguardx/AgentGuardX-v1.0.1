"""Sandbox tool runner — executes one FinanceFlow tool call and exits.

Invoked by SandboxExecutor via docker exec:
  python /sandbox/run_tool.py --payload-stdin

Reads JSON payload from stdin:
  {"tool_name": "get_account_tool", "tool_input": {...}, "session_id": "...", "agent_id": "..."}

Prints result JSON to stdout. Exits 0 on success, non-zero on error.

SECURITY: This runs inside an isolated container with no network access.
It must NOT call any external services or import agentguard (security layer is outside).
"""

from __future__ import annotations

import json
import sys
import os

# Ensure financeflow is importable
sys.path.insert(0, "/sandbox")


def run() -> int:
    if "--payload-stdin" not in sys.argv:
        print(json.dumps({"error": "Expected --payload-stdin flag"}), file=sys.stderr)
        return 2

    raw = sys.stdin.read()
    if not raw:
        print(json.dumps({"error": "Empty stdin payload"}), file=sys.stderr)
        return 2

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"Invalid JSON: {exc}"}), file=sys.stderr)
        return 2

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})

    # Import the tool registry from FinanceFlow
    try:
        from financeflow.tools import ADMIN_TOOLS
    except ImportError as exc:
        print(json.dumps({"error": f"Cannot import tools: {exc}"}), file=sys.stderr)
        return 1

    # Find the tool by name
    tool = next((t for t in ADMIN_TOOLS if t.name == tool_name), None)
    if tool is None:
        print(json.dumps({"error": f"Unknown tool: {tool_name}"}), file=sys.stderr)
        return 1

    # Execute the tool
    try:
        result = tool.invoke(tool_input)
        print(json.dumps({"result": result, "tool": tool_name, "status": "ok"}))
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc), "tool": tool_name, "status": "error"}),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run())
