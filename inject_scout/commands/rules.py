"""Handler for the ``rules`` subcommand."""

from __future__ import annotations

from inject_scout.commands._results import RulesResult
from inject_scout.rules import RULES


def handle_rules(category: str | None = None) -> RulesResult:
    """Return formatted rule catalog lines, optionally filtered by category.

    No argparse, no sys.stdout writes.
    """
    lines: list[str] = []
    for rule in RULES:
        if category and rule.category != category:
            continue
        lines.append(
            f"{rule.id:<28} {rule.severity:<6} {rule.category:<20} {rule.explanation[:70]}"
        )
    return RulesResult(exit_code=0, lines=lines)
