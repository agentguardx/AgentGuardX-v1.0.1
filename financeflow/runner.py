"""FinanceFlow CLI runner — executes benign and attack workflows.

Usage:
    python runner.py benign [--name <workflow>] [--list]
    python runner.py attack [--name <scenario>] [--all] [--scripted] [--report]
    python runner.py seed
    python runner.py server  (start exfil capture server)

The runner knows NOTHING about AgentGuard-X.
AgentGuard-X attaches via callbacks in the integration phase.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()


def cmd_seed() -> None:
    """Initialize and seed the database."""
    from financeflow.database.seed import seed
    console.print("[bold cyan]Seeding FinanceFlow database...[/bold cyan]")
    seed()
    console.print("[bold green]✓ Database seeded.[/bold green]")


def cmd_server() -> None:
    """Start the exfil capture server."""
    import uvicorn
    from financeflow.config import EXFIL_CAPTURE_PORT
    console.print(f"[bold yellow]Starting exfil capture server on :{EXFIL_CAPTURE_PORT}[/bold yellow]")
    uvicorn.run(
        "financeflow.exfil_server.server:app",
        host="0.0.0.0",
        port=EXFIL_CAPTURE_PORT,
        log_level="warning",
        reload=False,
    )


def cmd_list_benign() -> None:
    from financeflow.workflows.benign import BENIGN_WORKFLOWS
    t = Table(title="FinanceFlow Benign Workflows", box=box.ROUNDED)
    t.add_column("Name", style="cyan")
    t.add_column("Agent Role", style="green")
    t.add_column("Description")
    for w in BENIGN_WORKFLOWS:
        t.add_row(w.name, w.agent_role, w.description)
    console.print(t)


def cmd_list_attacks() -> None:
    from financeflow.workflows.attacks import ATTACK_WORKFLOWS
    t = Table(title="FinanceFlow Attack Scenarios", box=box.ROUNDED)
    t.add_column("Name", style="red")
    t.add_column("OWASP", style="yellow")
    t.add_column("Role", style="green")
    t.add_column("Description")
    for a in ATTACK_WORKFLOWS:
        t.add_row(a.name, a.owasp_category, a.agent_role, a.description)
    console.print(t)


def _get_agent(role: str, extra_callbacks: list | None = None):
    from financeflow.agents import AdminAgent, DataAgent, ResearchAgent
    mapping = {
        "research": ResearchAgent,
        "data": DataAgent,
        "admin": AdminAgent,
    }
    cls = mapping.get(role)
    if cls is None:
        console.print(f"[red]Unknown agent role: {role}[/red]")
        sys.exit(1)
    return cls(extra_callbacks=extra_callbacks)


def run_benign(name: str | None = None) -> None:
    from financeflow.workflows.benign import BENIGN_WORKFLOWS

    workflows = BENIGN_WORKFLOWS
    if name:
        workflows = [w for w in BENIGN_WORKFLOWS if w.name == name]
        if not workflows:
            console.print(f"[red]Benign workflow '{name}' not found.[/red]")
            sys.exit(1)

    for wf in workflows:
        console.print(Panel(
            f"[bold]{wf.description}[/bold]\n"
            f"Agent: [cyan]{wf.agent_role}[/cyan]  |  Task: {wf.task[:100]}...",
            title=f"BENIGN: {wf.name}",
            border_style="green",
        ))
        agent = _get_agent(wf.agent_role)
        start = time.monotonic()
        result = agent.run(wf.task)
        elapsed = time.monotonic() - start
        console.print(f"[green]Result ({elapsed:.2f}s):[/green]\n{result}\n")


def run_attack_scripted(scenario, report_data: list[dict]) -> None:
    """Execute a scripted attack (bypasses LLM, directly invokes tools)."""
    from financeflow.tools import ROLE_TOOLS

    console.print(Panel(
        f"[bold red]{scenario.description}[/bold red]\n"
        f"OWASP: [yellow]{scenario.owasp_category}[/yellow]\n"
        f"Agent role: [cyan]{scenario.agent_role}[/cyan]\n"
        f"Expected block: {scenario.expected_block_reason}",
        title=f"[SCRIPTED ATTACK] {scenario.name}",
        border_style="red",
    ))

    # Build a map of tool name → tool object for direct invocation
    role_tool_list = ROLE_TOOLS.get(scenario.agent_role, [])
    tool_map = {t.name: t for t in role_tool_list}

    results = []
    prev_outputs: dict[str, str] = {}

    for step in scenario.scripted_tool_calls:
        tool_name = step["tool"]
        raw_input = step["input"]

        # Substitute __PLACEHOLDER__ values from previous steps
        resolved_input = {}
        for k, v in raw_input.items():
            if isinstance(v, str) and v.startswith("__") and v.endswith("__"):
                prev_key = v.strip("_").lower()
                resolved = next(
                    (out for key, out in prev_outputs.items() if prev_key in key.lower()),
                    f"[placeholder:{v}]",
                )
                resolved_input[k] = resolved
            else:
                resolved_input[k] = v

        tool_fn = tool_map.get(tool_name)
        if tool_fn is None:
            output = f"TOOL UNAVAILABLE FOR ROLE '{scenario.agent_role}': {tool_name}"
        else:
            try:
                output = tool_fn.invoke(resolved_input)
            except Exception as e:
                output = f"ERROR: {e}"

        prev_outputs[tool_name] = str(output)
        results.append({"tool": tool_name, "input": resolved_input, "output": str(output)})
        console.print(f"  [yellow]→ {tool_name}[/yellow]: {str(output)[:200]}")

    report_data.append({
        "scenario": scenario.name,
        "owasp": scenario.owasp_category,
        "mode": "scripted",
        "steps": results,
        "expected_block": scenario.expected_block_reason,
    })


def run_attack_llm(scenario, report_data: list[dict]) -> None:
    """Execute an attack via the LLM agent."""
    console.print(Panel(
        f"[bold red]{scenario.description}[/bold red]\n"
        f"OWASP: [yellow]{scenario.owasp_category}[/yellow]\n"
        f"Agent role: [cyan]{scenario.agent_role}[/cyan]",
        title=f"[LLM ATTACK] {scenario.name}",
        border_style="red",
    ))
    agent = _get_agent(scenario.agent_role)
    start = time.monotonic()
    result = agent.run(scenario.task)
    elapsed = time.monotonic() - start
    console.print(f"[red]Result ({elapsed:.2f}s):[/red]\n{result}\n")
    report_data.append({
        "scenario": scenario.name,
        "owasp": scenario.owasp_category,
        "mode": "llm",
        "result": result,
        "expected_block": scenario.expected_block_reason,
    })


def cmd_attack(
    name: str | None = None,
    run_all: bool = False,
    scripted: bool = False,
    report: bool = False,
) -> None:
    from financeflow.workflows.attacks import ATTACK_WORKFLOWS, ATTACK_BY_NAME

    scenarios = ATTACK_WORKFLOWS
    if name:
        s = ATTACK_BY_NAME.get(name)
        if s is None:
            console.print(f"[red]Attack scenario '{name}' not found.[/red]")
            sys.exit(1)
        scenarios = [s]
    elif not run_all:
        console.print("[yellow]Specify --name <scenario> or --all[/yellow]")
        cmd_list_attacks()
        return

    report_data: list[dict] = []

    for scenario in scenarios:
        if scripted:
            run_attack_scripted(scenario, report_data)
        else:
            run_attack_llm(scenario, report_data)
        time.sleep(0.5)  # brief pause between scenarios

    if report:
        report_path = _write_report(report_data)
        console.print(f"\n[bold cyan]Attack report written to: {report_path}[/bold cyan]")


def _write_report(data: list[dict]) -> str:
    from financeflow.config import DATA_DIR
    import datetime
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = DATA_DIR / f"attack_report_{ts}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return str(path)


def main() -> None:
    # Ensure DB is seeded on every run
    from financeflow.database.seed import seed
    seed()

    parser = argparse.ArgumentParser(
        description="FinanceFlow CLI runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # seed
    sub.add_parser("seed", help="Seed the database with synthetic data")

    # server
    sub.add_parser("server", help="Start the exfil capture server")

    # benign
    p_benign = sub.add_parser("benign", help="Run benign workflows")
    p_benign.add_argument("--name", help="Run a specific workflow by name")
    p_benign.add_argument("--list", action="store_true", help="List available workflows")

    # attack
    p_attack = sub.add_parser("attack", help="Run attack scenarios")
    p_attack.add_argument("--name", help="Run a specific attack scenario")
    p_attack.add_argument("--all", action="store_true", dest="run_all", help="Run all scenarios")
    p_attack.add_argument(
        "--scripted", action="store_true",
        help="Use scripted tool calls (no LLM — reliable for demo)"
    )
    p_attack.add_argument("--report", action="store_true", help="Write JSON report")
    p_attack.add_argument("--list", action="store_true", help="List available scenarios")

    args = parser.parse_args()

    if args.command == "seed":
        cmd_seed()
    elif args.command == "server":
        cmd_server()
    elif args.command == "benign":
        if args.list:
            cmd_list_benign()
        else:
            run_benign(name=args.name)
    elif args.command == "attack":
        if args.list:
            cmd_list_attacks()
        else:
            cmd_attack(
                name=args.name,
                run_all=args.run_all,
                scripted=args.scripted,
                report=args.report,
            )


if __name__ == "__main__":
    main()
