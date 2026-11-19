"""Core data models for SlopGuard findings and scan reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 7,
            Severity.LOW: 2,
        }[self]

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }[self]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    file_path: str
    line: int
    column: int = 1
    message: str = ""
    snippet: str = ""
    suggestion: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "snippet": self.snippet,
            "suggestion": self.suggestion,
        }


@dataclass
class ScanReport:
    target: str
    files_scanned: int
    duration_ms: float
    findings: list[Finding] = field(default_factory=list)
    declared_dependencies: set[str] = field(default_factory=set)

    @property
    def slop_score(self) -> int:
        """0 = spotless, 100 = pure AI slop."""
        raw = sum(f.severity.weight for f in self.findings)
        return min(100, raw)

    @property
    def grade(self) -> str:
        s = self.slop_score
        if s == 0:
            return "A+"
        if s <= 10:
            return "A"
        if s <= 25:
            return "B"
        if s <= 50:
            return "C"
        if s <= 75:
            return "D"
        return "F"

    def counts_by_severity(self) -> dict[str, int]:
        counts = {sev.value: 0 for sev in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def has_findings_at_or_above(self, threshold: Severity) -> bool:
        return any(f.severity.rank >= threshold.rank for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "duration_ms": round(self.duration_ms, 2),
            "slop_score": self.slop_score,
            "grade": self.grade,
            "summary": self.counts_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
        }
