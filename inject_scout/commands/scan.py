"""Handler for the ``scan`` subcommand."""

from __future__ import annotations

from pathlib import Path

from inject_scout.commands._results import ScanPathResult, ScanResultAggregate
from inject_scout.engine import scan_file


def _iter_files(path_str: str) -> list[Path]:
    p = Path(path_str)
    if p.is_dir():
        return sorted(
            f for f in p.rglob("*")
            if f.is_file() and not f.name.startswith(".")
        )
    return [p]


def handle_scan(paths: list[str], strict: bool = False) -> ScanResultAggregate:
    """Scan files or directories and return a structured result.

    No argparse, no sys.stdout writes.
    """
    aggregate = ScanResultAggregate()
    for path_str in paths:
        for filepath in _iter_files(path_str):
            try:
                result = scan_file(filepath)
                aggregate.items.append(ScanPathResult(path=str(filepath), result=result))
                if strict and result.errors:
                    aggregate.exit_code = 1
            except OSError as exc:
                aggregate.errors.append((str(filepath), str(exc)))
    return aggregate
