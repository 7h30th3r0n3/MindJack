#!/usr/bin/env python3
"""MindJack v2 CLI — Agent workspace exposure mapper."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mindjack import __version__
from mindjack.core.evidence import EvidenceLogger
from mindjack.core.registry import get_registry, load_default_plugins
from mindjack.core.scope import Scope
from mindjack.execution.scan import run_discover
from mindjack.graph.builder import TrustGraph
from mindjack.reporting.hardening import HardeningReport
from mindjack.reporting.json_report import generate_json_report
from mindjack.reporting.markdown_report import generate_markdown_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mindjack",
        description="MindJack v2 — Agent workspace exposure mapper",
    )
    parser.add_argument(
        "--version", action="version", version=f"mindjack {__version__}",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # --- discover ---
    discover_p = sub.add_parser(
        "discover", help="Discover AI assistant artifacts and trust surfaces",
    )
    discover_p.add_argument(
        "--scope", nargs="+", type=Path, default=[],
        help="Directories to scan (default: user-level configs + project detection)",
    )
    discover_p.add_argument(
        "--allow-home-scope", action="store_true",
        help="Allow scanning the entire home directory",
    )
    discover_p.add_argument(
        "--tools", nargs="+", default=None,
        help="Only scan specific tools (e.g. claude-code cursor)",
    )
    discover_p.add_argument(
        "--report", "-r", type=Path, default=None,
        help="Output directory for reports (default: ./mindjack_output/)",
    )
    discover_p.add_argument(
        "--format", choices=["json", "markdown", "both"], default="both",
        help="Report format (default: both)",
    )
    discover_p.add_argument(
        "--json", action="store_true",
        help="Output results as JSON to stdout (no files written)",
    )

    # --- assess ---
    assess_p = sub.add_parser(
        "assess", help="Full assessment: discover + report",
    )
    assess_p.add_argument(
        "--scope", nargs="+", type=Path, default=[],
    )
    assess_p.add_argument("--allow-home-scope", action="store_true")
    assess_p.add_argument("--tools", nargs="+", default=None)
    assess_p.add_argument("--report", "-r", type=Path, default=None)
    assess_p.add_argument(
        "--format", choices=["json", "markdown", "both"], default="both",
    )

    # --- graph ---
    graph_p = sub.add_parser(
        "graph", help="Output the trust graph as JSON",
    )
    graph_p.add_argument(
        "--scope", nargs="+", type=Path, default=[],
        help="Directories to scan",
    )
    graph_p.add_argument("--allow-home-scope", action="store_true")
    graph_p.add_argument("--tools", nargs="+", default=None)
    graph_p.add_argument(
        "--format", choices=["json"], default="json",
        help="Output format (default: json)",
    )
    graph_p.add_argument(
        "--tool-filter", default=None,
        help="Show subgraph for a single tool slug",
    )

    # --- tools ---
    tools_p = sub.add_parser("tools", help="List or probe supported tools")
    tools_sub = tools_p.add_subparsers(dest="tools_command", required=True)
    tools_sub.add_parser("list", help="List all registered tool plugins")
    probe_p = tools_sub.add_parser("probe", help="Probe tool presence")
    probe_p.add_argument("--scope", nargs="+", type=Path, default=[])
    probe_p.add_argument("--allow-home-scope", action="store_true")

    return parser


def cmd_discover(args: argparse.Namespace) -> None:
    scope = Scope(
        paths=args.scope,
        allow_home=args.allow_home_scope,
    )
    ctx = run_discover(scope, tool_filter=args.tools)

    # Console summary
    _print_summary(ctx)

    if args.json:
        import json
        from mindjack.reporting.json_report import _count_by, _count_by_severity
        report_data = {
            "run_id": ctx.run_id,
            "artifacts": [
                {
                    "tool": a.tool_slug,
                    "surface": a.surface_type.value,
                    "path": str(a.path),
                    "exists": a.exists,
                    "state": a.state.value,
                }
                for a in ctx.artifacts
            ],
        }
        print(json.dumps(report_data, indent=2))
        return

    output_dir = args.report or Path("mindjack_output")
    _write_reports(ctx, output_dir, args.format)
    _write_evidence(ctx, output_dir)


def cmd_assess(args: argparse.Namespace) -> None:
    scope = Scope(
        paths=args.scope,
        allow_home=args.allow_home_scope,
    )
    ctx = run_discover(scope, tool_filter=args.tools)

    _print_summary(ctx)

    output_dir = args.report or Path("mindjack_output")
    _write_reports(ctx, output_dir, args.format)
    _write_evidence(ctx, output_dir)


def cmd_graph(args: argparse.Namespace) -> None:
    import json as json_mod

    scope = Scope(
        paths=args.scope,
        allow_home=args.allow_home_scope,
    )
    ctx = run_discover(scope, tool_filter=args.tools)
    graph = TrustGraph().build(ctx)

    if args.tool_filter:
        graph = graph.subgraph_for_tool(args.tool_filter)

    print(json_mod.dumps(graph.to_dict(), indent=2))


def cmd_tools_list(args: argparse.Namespace) -> None:
    registry = load_default_plugins()
    print(f"\n{'Slug':<16} {'Name':<22} {'Surfaces'}")
    print("-" * 65)
    for plugin in registry.all_plugins():
        d = plugin.descriptor
        surfaces = ", ".join(s.value for s in d.supported_surfaces)
        print(f"  {d.slug:<14} {d.display_name:<22} {surfaces}")
    print()


def cmd_tools_probe(args: argparse.Namespace) -> None:
    scope = Scope(
        paths=args.scope,
        allow_home=getattr(args, "allow_home_scope", False),
    )
    registry = load_default_plugins()
    print(f"\n{'Tool':<16} {'Present':<10} {'Artifacts'}")
    print("-" * 45)
    for plugin in registry.all_plugins():
        try:
            arts = plugin.detect(scope)
            existing = [a for a in arts if a.exists]
            status = "YES" if existing else ("maybe" if arts else "no")
            print(f"  {plugin.slug:<14} {status:<10} {len(existing)}/{len(arts)}")
        except Exception as exc:
            print(f"  {plugin.slug:<14} {'ERROR':<10} {exc}")
    print()


def _print_summary(ctx) -> None:
    existing = [a for a in ctx.artifacts if a.exists]
    print()
    print("=" * 60)
    print("  MindJack v2 — Assessment")
    print("=" * 60)
    print(f"  Run ID:     {ctx.run_id}")
    print(f"  Mode:       {ctx.mode}")
    print(f"  Artifacts:  {len(existing)} existing / {len(ctx.artifacts)} total")
    print(f"  Surfaces:   {len(ctx.surfaces)}")
    print()

    # Per-tool breakdown
    by_tool: dict[str, list] = {}
    for a in ctx.artifacts:
        by_tool.setdefault(a.tool_slug, []).append(a)

    for tool in sorted(by_tool):
        arts = by_tool[tool]
        exist = sum(1 for a in arts if a.exists)
        if exist > 0:
            print(f"  [+] {tool:<18} {exist:>3} existing artifacts")
        else:
            print(f"  [ ] {tool:<18}     ({len(arts)} creatable)")

    # Severity summary
    sev_counts: dict[str, int] = {}
    for s in ctx.surfaces:
        sev = s.risk_dimensions.get("_severity", "unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    if sev_counts:
        print()
        parts = []
        for sev in ("critical", "high", "medium", "low"):
            if sev in sev_counts:
                parts.append(f"{sev_counts[sev]} {sev.upper()}")
        if parts:
            print(f"  Risk: {' / '.join(parts)}")

    print()


def _write_reports(ctx, output_dir: Path, fmt: str) -> None:
    if fmt in ("json", "both"):
        p = generate_json_report(ctx, output_dir)
        print(f"  -> {p}")
    if fmt in ("markdown", "both"):
        p = generate_markdown_report(ctx, output_dir)
        print(f"  -> {p}")

    # Always generate hardening report alongside other reports
    hardening = HardeningReport()
    items = hardening.generate(ctx)
    p = hardening.generate_markdown(items, output_dir)
    print(f"  -> {p}")


def _write_evidence(ctx, output_dir: Path) -> None:
    evidence = EvidenceLogger(ctx)
    p = evidence.write(output_dir)
    print(f"  -> {p}")
    print()


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    load_default_plugins()

    dispatch = {
        "discover": cmd_discover,
        "assess": cmd_assess,
        "graph": cmd_graph,
        "tools": lambda a: (
            cmd_tools_list(a) if a.tools_command == "list"
            else cmd_tools_probe(a)
        ),
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
