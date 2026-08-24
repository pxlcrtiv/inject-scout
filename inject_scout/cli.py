"""CLI: inject-scout check|scan|demo|rules"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from inject_scout import __version__
from inject_scout.engine import ScanResult, scan, scan_file
from inject_scout.report import render_json, render_markdown, render_text
from inject_scout.rules import CATEGORIES, RULES

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
    r.add_argument("--category", choices=list(CATEGORIES), help="Filter by category")

    p.add_argument("--version", action="version", version=f"inject-scout {__version__}")
    return p


def _emit(result: ScanResult, fmt: str, out: str | None, strict: bool) -> int:
    rendered = {"text": render_text, "markdown": render_markdown, "json": render_json}[fmt](result)
    if out:
        path = Path(out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
        print(f"report written to {path}")
    else:
        sys.stdout.write(rendered.rstrip() + "\n")
    return 1 if (strict and result.errors) else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "check":
        if args.text in (None, "-"):
            text = sys.stdin.read()
        else:
            text = args.text
        return _emit(scan(text), args.format, args.output, args.strict)

    if args.command == "scan":
        worst = 0
        for p in args.paths:
            path = Path(p)
            if path.is_dir():
                files = sorted(path.rglob("*"))
                files = [f for f in files if f.is_file() and not f.name.startswith(".")]
            else:
                files = [path]
            for f in files:
                try:
                    res = scan_file(f)
                except OSError as e:
                    print(f"error: {f}: {e}", file=sys.stderr)
                    continue
                print(f"== {f}")
                print(render_text(res))
                if args.strict and res.errors:
                    worst = 1
        return worst

    if args.command == "demo":
        corpus = json.loads(ATTACKS.read_text(encoding="utf-8"))
        hits, misses = [], []
        for item in corpus["attacks"]:
            res = scan(item["text"])
            cats = set(res.categories_hit())
            expected = set(item["expected"])
            if cats & expected:
                hits.append(item["id"])
            else:
                misses.append((item["id"], expected, sorted(cats)))
        summary = (
            f"demo: {len(hits)}/{len(corpus['attacks'])} attacks detected "
            f"({len(hits) * 100 // len(corpus['attacks'])}%)"
        )
        if args.format == "json":
            print(json.dumps({"detected": hits, "missed": [m[0] for m in misses], "summary": summary}, indent=2))
        else:
            print(summary)
            if misses:
                print("missed:", ", ".join(m[0] for m in misses))
        return 0

    if args.command == "rules":
        for rule in RULES:
            if args.category and rule.category != args.category:
                continue
            print(f"{rule.id:<28} {rule.severity:<6} {rule.category:<20} {rule.explanation[:70]}")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())