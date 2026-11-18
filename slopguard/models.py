"""Core data model shared by every detector, the triage agent and the reporters."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {valid})") from exc


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Category(str, Enum):
    SECURITY = "security"
    SLOP = "slop"
    GAP = "gap"
    LOOSE_END = "loose-end"

    @property
    def label(self) -> str:
        return _CATEGORY_LABELS[self]


_CATEGORY_LABELS = {
    Category.SECURITY: "Security",
    Category.SLOP: "AI Slop",
    Category.GAP: "Coding Gap",
    Category.LOOSE_END: "Loose End",
}


class Verdict(str, Enum):
    """Outcome of AI triage. UNTRIAGED means the finding never went through the agent."""

    UNTRIAGED = "untriaged"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


@dataclass
class Finding:
    rule_id: str
    title: str
    category: Category
    severity: Severity
    path: str  # repo-relative, forward slashes; "" for repository-level findings
    line: int  # 1-based; 0 for repository-level findings
    message: str
    snippet: str = ""
    fix: str = ""
    confidence: float = 0.8
    source: str = "heuristic"  # heuristic | ast | ai
    verdict: Verdict = Verdict.UNTRIAGED
    ai_rationale: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable identity used by baselines. Ignores line numbers so unrelated edits don't churn it."""
        basis = "|".join([self.rule_id, self.path, " ".join(self.snippet.split())])
        return hashlib.sha1(basis.encode("utf-8"), usedforsecurity=False).hexdigest()[:16]

    @property
    def location(self) -> str:
        if not self.path:
            return "<repository>"
        return f"{self.path}:{self.line}" if self.line else self.path

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["category"] = self.category.value
        data["severity"] = self.severity.value
        data["verdict"] = self.verdict.value
        data["fingerprint"] = self.fingerprint
        return data


@dataclass
class ScanStats:
    files_scanned: int = 0
    lines_scanned: int = 0
    files_skipped: int = 0
    languages: dict[str, int] = field(default_factory=dict)
    duration_s: float = 0.0
    suppressed: int = 0
    baselined: int = 0


@dataclass
class ScanResult:
    root: str
    findings: list[Finding]
    stats: ScanStats
    score: int = 100
    grade: str = "A"
    ai_summary: str = ""
    ai_usage: dict[str, Any] = field(default_factory=dict)

    def by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def by_category(self) -> dict[str, int]:
        counts = {c.value: 0 for c in Category}
        for f in self.findings:
            counts[f.category.value] += 1
        return counts
