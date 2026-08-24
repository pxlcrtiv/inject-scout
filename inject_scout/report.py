"""Report rendering: text, markdown, JSON."""

from __future__ import annotations

import json

from inject_scout.engine import ScanResult

SEV = {"error": "ERROR", "warn": "WARN", "info": "info"}


def render_text(result: ScanResult) -> str:
    lines = [
        f"inject-scout · {len(result.text)} chars",
        f"Score: {result.score:.0f}/100 — band {result.band}",
        "",
    ]
    if not result.findings:
        lines.append("No injection patterns found.")
        return "\n".join(lines)
    for f in result.findings:
        lines.append(f"[{SEV[f.severity]}] {f.id} ({f.category})")
        lines.append(f"    matched: {f.matched!r}")
        lines.append(f"    {f.rule.explanation}")
        lines.append(f"    fix: {f.rule.suggestion}")
        lines.append("")
    lines.append(result.summary())
    return "\n".join(lines)


def render_markdown(result: ScanResult) -> str:
    lines = [
        "# inject-scout report",
        "",
        f"- **Input:** {len(result.text)} chars",
        f"- **Score:** {result.score:.0f}/100 — band **{result.band}**",
        f"- **Findings:** {result.errors} error(s), {result.warnings} warning(s), {result.infos} info",
        "",
        "| Severity | Rule | Category | Match | Explanation | Suggestion |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for f in result.findings:
        esc = f.matched.replace("|", "\\|")
        lines.append(
            f"| {f.severity} | `{f.id}` | {f.category} | `{esc}` | {f.rule.explanation} | {f.rule.suggestion} |"
        )
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "chars": len(result.text),
            "score": result.score,
            "band": result.band,
            "counts": {"errors": result.errors, "warnings": result.warnings, "infos": result.infos},
            "categories": result.categories_hit(),
            "findings": [
                {
                    "id": f.id,
                    "severity": f.severity,
                    "category": f.category,
                    "matched": f.matched,
                    "explanation": f.rule.explanation,
                    "suggestion": f.rule.suggestion,
                }
                for f in result.findings
            ],
        },
        indent=2,
    )