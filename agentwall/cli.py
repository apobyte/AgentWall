"""AgentWall command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agentwall import __version__
from agentwall.models.types import ContentEnvelope, Decision, ToolCall
from agentwall.policy.parser import default_policy, policy_to_dict
from agentwall.shield import Shield

console = Console()


def _decision_style(action: str) -> str:
    return {
        "allow": "green",
        "review": "yellow",
        "block": "red",
    }.get(action, "white")


def cmd_scan(args: argparse.Namespace) -> int:
    shield = Shield(policy=args.policy, audit_path=args.audit)
    text = args.text
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    if text is None:
        text = sys.stdin.read()

    if args.source or args.trust:
        content: str | ContentEnvelope = ContentEnvelope(
            content=text,
            source=args.source or "unknown",
            trust=args.trust or "unknown",
        )
    else:
        content = text

    result = shield.scan(content) if not args.output else shield.scan_output(text)

    if args.json:
        console.print_json(data=result.to_dict())
    else:
        color = _decision_style(result.action.value)
        console.print(
            Panel(
                str(result),
                title=f"[bold]AgentWall[/bold] · [{color}]{result.action.value.upper()}[/{color}]",
                border_style=color,
            )
        )
    return 0 if result.action != Decision.BLOCK else 2


def cmd_check(args: argparse.Namespace) -> int:
    shield = Shield(policy=args.policy, audit_path=args.audit)

    if args.shell:
        decision = shield.check_shell(args.shell)
    elif args.path:
        decision = shield.check_filesystem(args.path)
    elif args.url:
        decision = shield.check_network(args.url)
    elif args.tool:
        call = ToolCall(tool=args.tool, arguments=json.loads(args.args or "{}"))
        decision = shield.check_tool(call)
    else:
        console.print("[red]Specify --shell, --path, --url, or --tool[/red]")
        return 1

    if args.json:
        console.print_json(data=decision.to_dict())
    else:
        color = _decision_style(decision.action.value)
        console.print(
            Panel(
                str(decision),
                title=f"[bold]AgentWall[/bold] · [{color}]{decision.action.value.upper()}[/{color}]",
                border_style=color,
            )
        )
    return 0 if decision.action != Decision.BLOCK else 2


def cmd_policy(args: argparse.Namespace) -> int:
    if args.init:
        from agentwall.policy.parser import default_policy as dp
        import yaml

        path = Path(args.init)
        data = policy_to_dict(dp())
        path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8")
        console.print(f"[green]Wrote default policy to {path}[/green]")
        return 0

    if args.policy:
        shield = Shield(policy=args.policy)
        data = policy_to_dict(shield.policy)
    else:
        data = policy_to_dict(default_policy())

    console.print_json(data=data)
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    from agentwall.benchmarks.runner import run_benchmarks

    report = run_benchmarks(Path(args.dir) if args.dir else None, policy=args.policy)
    table = Table(title="AgentWall Security Benchmark")
    table.add_column("Suite")
    table.add_column("Tests", justify="right")
    table.add_column("Detection", justify="right")
    table.add_column("False Positives", justify="right")

    for suite in report["suites"]:
        table.add_row(
            suite["name"],
            str(suite["total"]),
            f"{suite['detection_rate']*100:.1f}%",
            f"{suite['false_positive_rate']*100:.1f}%",
        )

    console.print(table)
    console.print(
        Text(
            f"Overall detection {report['overall_detection']*100:.1f}% · "
            f"FP rate {report['overall_false_positive']*100:.1f}% · "
            f"{report['total']} tests in {report['elapsed_s']:.2f}s",
            style="bold",
        )
    )
    if args.json:
        console.print_json(data=report)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    shield = Shield(policy=args.policy, audit_path=args.audit)
    stats = shield.audit.stats()
    recent = shield.audit.recent(10)

    console.print(
        Panel(
            f"Requests   {stats['total']:>8}\n"
            f"Blocked    {stats['blocked']:>8}\n"
            f"Review     {stats['review']:>8}\n"
            f"Critical   {stats['critical']:>8}",
            title="[bold]AgentWall[/bold]  ·  ACTIVE",
            border_style="cyan",
        )
    )
    if recent:
        table = Table(title="Recent events")
        table.add_column("Time")
        table.add_column("Type")
        table.add_column("Action")
        table.add_column("Risk")
        for event in reversed(recent):
            table.add_row(
                event.timestamp[11:19],
                event.event_type,
                event.action,
                f"{event.risk:.0f}",
            )
        console.print(table)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentwall",
        description="AgentWall — open-source security firewall for AI agents",
    )
    parser.add_argument("--version", action="version", version=f"agentwall {__version__}")
    parser.add_argument("--policy", "-p", help="Path to YAML policy file")
    parser.add_argument("--audit", help="Path to audit log JSONL file")

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan text for prompt injection / secrets")
    scan.add_argument("text", nargs="?", help="Text to scan")
    scan.add_argument("--file", "-f", help="Read text from file")
    scan.add_argument("--source", choices=["user", "system", "web", "document", "email", "tool"])
    scan.add_argument("--trust", choices=["trusted", "untrusted", "unknown"])
    scan.add_argument("--output", action="store_true", help="Scan as model output")
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=cmd_scan)

    check = sub.add_parser("check", help="Check a tool call against policy")
    check.add_argument("--shell", help="Shell command to check")
    check.add_argument("--path", help="Filesystem path to check")
    check.add_argument("--url", help="Network URL/host to check")
    check.add_argument("--tool", help="Tool name")
    check.add_argument("--args", help="Tool arguments as JSON object")
    check.add_argument("--json", action="store_true")
    check.set_defaults(func=cmd_check)

    policy = sub.add_parser("policy", help="Show or initialize policy")
    policy.add_argument("--init", metavar="PATH", help="Write default policy YAML")
    policy.set_defaults(func=cmd_policy)

    bench = sub.add_parser("benchmark", help="Run security benchmark suites")
    bench.add_argument("--dir", help="Benchmark data directory")
    bench.add_argument("--json", action="store_true")
    bench.set_defaults(func=cmd_benchmark)

    status = sub.add_parser("status", help="Show audit stats")
    status.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        sys.exit(0)
    code = args.func(args)
    sys.exit(code)


if __name__ == "__main__":
    main()
