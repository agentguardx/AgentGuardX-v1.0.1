#!/usr/bin/env python3
"""AgentGuard-X Integration Demo — scripted before/after attack showcase.

Runs all FinanceFlow attack scenarios through AgentGuardGatewayCallback
WITHOUT the LLM (Ollama not required). Manually fires on_tool_start and
on_tool_end for each scripted tool call to exercise the full enforcement path.

Usage (inside financeflow-runner container):
    python /app/integration/demo.py
    python /app/integration/demo.py --enforcement off
    python /app/integration/demo.py --scenario exfil_kill_chain

Invoked by agentguard.sh:
    ./agentguard.sh demo        (full before/after with gateway toggle)
    ./agentguard.sh attack      (current enforcement state)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ── Result types ─────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    tool_name: str
    status: str          # ALLOWED | BLOCKED | QUARANTINED | ERROR
    reason: Optional[str] = None
    output_preview: Optional[str] = None


@dataclass
class ScenarioResult:
    name: str
    owasp: str
    agent_role: str
    expected_block: str
    steps: list[StepResult] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(s.status in ("BLOCKED", "QUARANTINED") for s in self.steps)


# ── Scenario runner ───────────────────────────────────────────────────────────

def run_scenario(scenario, callback) -> ScenarioResult:
    """Execute one scripted attack scenario through the callback hook.

    Manually fires on_tool_start / on_tool_end so enforcement is exercised
    without the LLM agent executor path.
    """
    from financeflow.tools import ROLE_TOOLS

    role_tool_list = ROLE_TOOLS.get(scenario.agent_role, [])
    tool_map = {t.name: t for t in role_tool_list}

    result = ScenarioResult(
        name=scenario.name,
        owasp=scenario.owasp_category,
        agent_role=scenario.agent_role,
        expected_block=scenario.expected_block_reason,
    )
    prev_outputs: dict[str, str] = {}

    for step in scenario.scripted_tool_calls:
        tool_name = step["tool"]
        raw_input = step["input"]

        # Substitute __PLACEHOLDER__ values from previous steps
        resolved: dict = {}
        for k, v in raw_input.items():
            if isinstance(v, str) and v.startswith("__") and v.endswith("__"):
                prev_key = v.strip("_").lower()
                resolved[k] = next(
                    (out for key, out in prev_outputs.items() if prev_key in key.lower()),
                    f"[placeholder:{v}]",
                )
            else:
                resolved[k] = v

        # ── Pre-execution hook ────────────────────────────────────────────────
        try:
            callback.on_tool_start({"name": tool_name}, json.dumps(resolved))
        except PermissionError as exc:
            result.steps.append(StepResult(
                tool_name=tool_name,
                status="BLOCKED",
                reason=str(exc),
            ))
            break  # kill chain stopped
        except Exception as exc:
            result.steps.append(StepResult(
                tool_name=tool_name,
                status="ERROR",
                reason=f"pre-hook error: {exc}",
            ))
            break

        # ── Tool execution ────────────────────────────────────────────────────
        tool_fn = tool_map.get(tool_name)
        if tool_fn is None:
            output = f"TOOL UNAVAILABLE FOR ROLE '{scenario.agent_role}': {tool_name}"
        else:
            try:
                output = str(tool_fn.invoke(resolved))
            except Exception as exc:
                output = f"TOOL ERROR: {exc}"

        prev_outputs[tool_name] = output

        # ── Post-execution hook ───────────────────────────────────────────────
        try:
            callback.on_tool_end(output)
            result.steps.append(StepResult(
                tool_name=tool_name,
                status="ALLOWED",
                output_preview=output[:120],
            ))
        except ValueError as exc:
            result.steps.append(StepResult(
                tool_name=tool_name,
                status="QUARANTINED",
                reason=str(exc),
                output_preview=output[:60],
            ))
            break

    return result


# ── Report printer ────────────────────────────────────────────────────────────

_STATUS_ICON = {
    "ALLOWED": ("✓", "green"),
    "BLOCKED": ("✗", "red"),
    "QUARANTINED": ("⚠", "yellow"),
    "ERROR": ("!", "red"),
}


def print_report(results: list[ScenarioResult], enforcement: bool) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box

        console = Console()
        mode = "ENFORCEMENT ON" if enforcement else "ENFORCEMENT OFF (observe-only)"
        mode_style = "bold green" if enforcement else "bold red"
        console.print(Panel(
            f"[{mode_style}]{mode}[/{mode_style}]",
            title="AgentGuard-X Integration Demo",
            border_style="cyan",
        ))

        t = Table(box=box.ROUNDED, show_lines=True, expand=True)
        t.add_column("Scenario", style="cyan", width=26)
        t.add_column("OWASP", style="yellow", width=7)
        t.add_column("Steps", min_width=36)
        t.add_column("Outcome", width=20)

        blocked_total = 0
        for r in results:
            step_lines = []
            for s in r.steps:
                icon, colour = _STATUS_ICON.get(s.status, ("?", "white"))
                step_lines.append(f"[{colour}]{icon} {s.tool_name[:32]}[/{colour}]")

            if r.blocked:
                blocked_total += 1
                outcome = "[green]BLOCKED / HELD[/green]"
            else:
                outcome = "[red]SUCCEEDED (attack through)[/red]"

            t.add_row(
                r.name,
                r.owasp,
                "\n".join(step_lines) if step_lines else "(no tool steps)",
                outcome,
            )

        console.print(t)

        total = len(results)
        if enforcement:
            colour = "green" if blocked_total == total else "red"
            console.print(
                f"\n[{colour}]{blocked_total}/{total} attacks blocked.[/{colour}]"
                + ("" if blocked_total == total
                   else f" [red]{total - blocked_total} unexpected pass-through(s).[/red]")
            )
        else:
            console.print(
                f"\n[yellow]{total - blocked_total}/{total} attacks passed through"
                f" (observe-only). Logs and metrics are live.[/yellow]"
            )

    except ImportError:
        # Fallback: plain text
        print(f"\n=== AgentGuard-X Demo | {'ENFORCEMENT ON' if enforcement else 'ENFORCEMENT OFF'} ===")
        for r in results:
            status = "BLOCKED" if r.blocked else "ALLOWED (attack through)"
            print(f"  {r.name:<34} [{r.owasp}]  {status}")
        print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AgentGuard-X integration demo — scripted attack showcase",
    )
    parser.add_argument(
        "--enforcement",
        choices=["on", "off"],
        default=None,
        help="Override enforcement state (default: AGENTGUARD_ENFORCEMENT env var)",
    )
    parser.add_argument(
        "--scenario",
        metavar="NAME",
        default=None,
        help="Run a single scenario by name (default: all scripted scenarios)",
    )
    args = parser.parse_args()

    # Resolve enforcement from arg → env → default true
    if args.enforcement is not None:
        enforcement = args.enforcement == "on"
    else:
        enforcement = os.getenv("AGENTGUARD_ENFORCEMENT", "true").lower() in (
            "true", "on", "1", "yes",
        )

    gateway_url = os.getenv("GATEWAY_URL", "http://gateway:8080")

    from integration.gateway_callback import AgentGuardGatewayCallback
    from financeflow.workflows.attacks import ATTACK_WORKFLOWS, ATTACK_BY_NAME

    if args.scenario:
        s = ATTACK_BY_NAME.get(args.scenario)
        if s is None:
            print(f"ERROR: unknown scenario '{args.scenario}'", file=sys.stderr)
            sys.exit(1)
        scenarios = [s]
    else:
        # Skip scenarios with no scripted tool calls (e.g. pure-LLM attacks)
        scenarios = [s for s in ATTACK_WORKFLOWS if s.scripted_tool_calls]

    results: list[ScenarioResult] = []
    for scenario in scenarios:
        callback = AgentGuardGatewayCallback(
            agent_id=f"financeflow-{scenario.agent_role}",
            agent_role=scenario.agent_role,
            gateway_url=gateway_url,
            enforcement=enforcement,
        )
        results.append(run_scenario(scenario, callback))
        time.sleep(0.3)

    print_report(results, enforcement)

    # Exit non-zero if enforcement=on but any attack passed through
    if enforcement and any(not r.blocked for r in results):
        sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
