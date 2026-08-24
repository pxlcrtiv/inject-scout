"""Scan engine: run the rule catalog over text, dedupe, order, score."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from inject_scout.rules import RULES, Rule, normalize

SEVERITY_WEIGHT = {"error": 1.0, "warn": 0.5, "info": 0.25}
BANDS = [(90, "A (clean)"), (70, "B (review)"), (40, "C (suspicious)"), (0, "D (blocked)")]


@dataclass
class Finding:
    rule: Rule
    matched: str
    start: int

    @property
    def id(self) -> str:
        return self.rule.id

    @property
    def category(self) -> str:
        return self.rule.category

    @property
    def severity(self) -> str:
        return self.rule.severity


@dataclass
class ScanResult:
    text: str
    findings: list[Finding] = field(default_factory=list)
    score: float = 100.0
    band: str = "A (clean)"
    errors: int = 0
    warnings: int = 0
    infos: int = 0

    def finding_ids(self) -> list[str]:
        return [f.id for f in self.findings]

    def categories_hit(self) -> list[str]:
        return sorted({f.category for f in self.findings})

    def summary(self) -> str:
        return (
            f"inject-scout: {len(self.findings)} finding(s) "
            f"({self.errors} error, {self.warnings} warn, {self.infos} info) — "
            f"score {self.score:.0f}/100 ({self.band})"
        )


def scan(text: str) -> ScanResult:
    """Run all rules; one finding per (rule, first match); deterministic order."""
    norm = normalize(text)
    result = ScanResult(text=text)
    findings: list[Finding] = []
    for rule in RULES:
        pattern = re.compile("|".join(f"(?:{p})" for p in rule.patterns), re.IGNORECASE)
        m = pattern.search(norm)
        if m:
            findings.append(Finding(rule=rule, matched=m.group(0)[:120], start=m.start()))
    # Deterministic order: position in text, then rule id.
    findings.sort(key=lambda f: (f.start, f.id))
    result.findings = findings
    result.errors = sum(1 for f in findings if f.severity == "error")
    result.warnings = sum(1 for f in findings if f.severity == "warn")
    result.infos = sum(1 for f in findings if f.severity == "info")
    if findings:
        penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings) * 15
        result.score = max(0.0, 100.0 - penalty)
    result.score = round(result.score, 1)
    result.band = next(b for cutoff, b in BANDS if result.score >= cutoff)
    return result


def scan_file(path) -> ScanResult:
    """Scan a text file (UTF-8, errors replaced)."""
    from pathlib import Path

    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return scan(text)