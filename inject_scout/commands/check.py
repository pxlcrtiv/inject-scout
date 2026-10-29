"""Handler for the ``check`` subcommand."""

from __future__ import annotations

from inject_scout.commands._results import CheckResult
from inject_scout.engine import scan
from inject_scout.report import render_json, render_markdown, render_text

_RENDERERS = {
    "text": render_text,
    "markdown": render_markdown,
    "json": render_json,
}


def handle_check(
    text: str,
    fmt: str = "text",
    out: str | None = None,
    strict: bool = False,
) -> CheckResult:
    """Scan a single text string and return a structured result.

    No argparse, no sys.stdout writes.
    """
    result = scan(text)
    rendered = _RENDERERS[fmt](result)
    exit_code = 1 if (strict and result.errors) else 0
    return CheckResult(exit_code=exit_code, rendered=rendered, output_path=out)
