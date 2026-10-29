"""CLI: inject-scout check|scan|demo|rules — thin adapter over command handlers."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from inject_scout import __version__
from inject_scout.commands._results import (
    CheckResult,
    DemoResult,
    RulesResult,
    ScanResultAggregate,
)
from inject_scout.commands.check import handle_check
from inject_scout.commands.demo import handle_demo
from inject_scout.commands.rules import handle_rules
from inject_scout.commands.scan import handle_scan
from inject_scout.report import render_text

ATTACKS = Path(__file__).parent / "data" / "attacks.json"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="inject-scout",
        description="On-device prompt injection & jailbreak scanner for LLM apps. "
        "Deterministic rule engine; zero API keys; works offline.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="Scan one text string")
    c.add_argument("text", nargs="?", help="Text to scan (or read from stdin when '-')")
    c.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    c.add_argument("-o", "--output", help="Write report to a file")
    c.add_argument("--strict", action="store_true", help="Exit 1 on any error-level finding")

    s = sub.add_parser("scan", help="Scan files or directories")
    s.add_argument("paths", nargs="+", help="Files or directories to scan")
    s.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    s.add_argument("--strict", action="store_true")

    d = sub.add_parser("demo", help="Run the bundled attack corpus and summarize hits")
    d.add_argument("--format", choices=["text", "markdown", "json"], default="text")

    r = sub.add_parser("rules", help="List the rule catalog")
    r.add_argument("--category", choices=list(__import__("inject_scout.rules", fromlist=["CATEGORIES"]).CATEGORIES), help="Filter by category")

    p.add_argument("--version", action="version", version=f"inject-scout {__version__}")
    return p


def _emit_check(result: CheckResult) -> int:
    if result.output_path:
        path = Path(result.output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(result.rendered + "\n", encoding="utf-8")
        print(f"report written to {path}")
    else:
        sys.stdout.write(result.rendered.rstrip() + "\n")
    return result.exit_code


def _emit_scan(agg: ScanResultAggregate) -> int:
    for item in agg.items:
        print(f"== {item.path}")
        print(render_text(item.result))
    for path, msg in agg.errors:
        print(f"error: {path}: {msg}", file=sys.stderr)
    return agg.exit_code


def _emit_demo(result: DemoResult) -> int:
    if result.json_payload:
        print(result.json_payload)
    else:
        print(result.summary)
        if result.missed:
            print("missed:", ", ".join(m["id"] for m in result.missed))
    return result.exit_code


def _emit_rules(result: RulesResult) -> int:
    for line in result.lines:
        print(line)
    return result.exit_code


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "check":
        if args.text in (None, "-"):
            text = sys.stdin.read()
        else:
            text = args.text
        result = handle_check(text, fmt=args.format, out=args.output, strict=args.strict)
        return _emit_check(result)

    if args.command == "scan":
        result = handle_scan(args.paths, strict=args.strict)
        return _emit_scan(result)

    if args.command == "demo":
        result = handle_demo(fmt=args.format)
        return _emit_demo(result)

    if args.command == "rules":
        result = handle_rules(category=args.category)
        return _emit_rules(result)

    return 2


if __name__ == "__main__":
    sys.exit(main())
