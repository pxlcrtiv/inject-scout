"""Handler for the ``demo`` subcommand."""

from __future__ import annotations

import json

from inject_scout.commands._results import DemoResult
from inject_scout.engine import scan

_ATTACKS_PATH = __import__("inject_scout").__path__[0] + "/data/attacks.json"


def handle_demo(fmt: str = "text") -> DemoResult:
    """Run the bundled attack corpus and return a structured result.

    No argparse, no sys.stdout writes.
    """
    with open(_ATTACKS_PATH, encoding="utf-8") as fh:
        corpus = json.load(fh)

    hits: list[str] = []
    misses: list[dict] = []
    for item in corpus["attacks"]:
        res = scan(item["text"])
        cats = set(res.categories_hit())
        expected = set(item["expected"])
        if cats & expected:
            hits.append(item["id"])
        else:
            misses.append({"id": item["id"], "expected": sorted(expected), "got": sorted(cats)})

    total = len(corpus["attacks"])
    summary = (
        f"demo: {len(hits)}/{total} attacks detected "
        f"({len(hits) * 100 // total}%)"
    )
    payload: dict = {
        "detected": hits,
        "missed": [m["id"] for m in misses],
        "summary": summary,
    }
    return DemoResult(
        exit_code=0,
        summary=summary,
        detected=hits,
        missed=misses,
        json_payload=json.dumps(payload, indent=2) if fmt == "json" else None,
    )
