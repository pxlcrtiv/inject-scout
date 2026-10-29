"""Result objects returned by command handlers (test-friendly, no I/O)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from inject_scout.engine import ScanResult


@dataclass
class CheckResult:
    """Result of the ``check`` subcommand."""
    exit_code: int = 0
    rendered: str = ""
    output_path: str | None = None


@dataclass
class ScanPathResult:
    """Per-file result inside a ``scan`` run."""
    path: str
    result: ScanResult


@dataclass
class ScanResultAggregate:
    """Aggregate result of the ``scan`` subcommand."""
    exit_code: int = 0
    items: list[ScanPathResult] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)  # (path, message)


@dataclass
class DemoResult:
    """Result of the ``demo`` subcommand."""
    exit_code: int = 0
    summary: str = ""
    detected: list[str] = field(default_factory=list)
    missed: list[dict[str, Any]] = field(default_factory=list)
    json_payload: str | None = None


@dataclass
class RulesResult:
    """Result of the ``rules`` subcommand."""
    exit_code: int = 0
    lines: list[str] = field(default_factory=list)
