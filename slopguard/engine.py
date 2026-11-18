"""Scan orchestration: discover -> detect -> suppress -> filter -> score."""

from __future__ import annotations

import json
import re
import subprocess
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import rules as _rules  # noqa: F401  (registers built-in rules)
from .config import Config, load_config
from .context import FileContext, RepoContext, discover
from .models import Finding, ScanResult, ScanStats, Severity
from .rules.base import Rule, all_rules
from .scoring import score_findings

_SUPPRESS = re.compile(r"slopguard:\s*ignore(?:\[(?P<ids>[A-Z0-9_,\s]+)\])?", re.IGNORECASE)
_SUPPRESS_FILE = re.compile(r"slopguard:\s*ignore-file", re.IGNORECASE)


@dataclass
class ScanOptions:
    min_severity: Severity = Severity.INFO
    categories: set[str] | None = None
    only_rules: set[str] | None = None
    baseline: Path | None = None
    diff_ref: str | None = None
    config_path: Path | None = None
    extra_excludes: list[str] = field(default_factory=list)


def select_rules(config: Config, options: ScanOptions) -> list[Rule]:
    selected = []
    for rule in all_rules():
        if rule.meta.id in config.disable_rules:
            continue
        if options.only_rules and rule.meta.id not in options.only_rules:
            continue
        if options.categories and rule.meta.category.value not in options.categories:
            continue
        selected.append(rule)
    return selected


def scan(root: Path, options: ScanOptions | None = None) -> tuple[ScanResult, RepoContext]:
    options = options or ScanOptions()
    started = time.perf_counter()
    # Reports show the path as the user typed it - never the absolute path (which leaks usernames).
    display_root = root.resolve().name if root.as_posix() in {".", ""} else root.as_posix()
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"{root} is not a directory")
    config = load_config(root, options.config_path)
    config.exclude.extend(options.extra_excludes)
    repo = discover(root, config)

    findings: list[Finding] = []
    by_path = {f.rel: f for f in repo.files}
    for rule in select_rules(config, options):
        for ctx in repo.files:
            if rule.applies_to(ctx):
                findings.extend(rule.check_file(ctx))
        findings.extend(rule.check_repo(repo))

    stats = ScanStats(
        files_scanned=len(repo.files),
        lines_scanned=sum(len(f.lines) for f in repo.files),
        files_skipped=repo.skipped,
        languages=dict(Counter(f.language.name for f in repo.files).most_common()),
    )

    findings = _apply_overrides(findings, config)
    findings, stats.suppressed = _apply_suppressions(findings, by_path)
    findings = _dedupe(findings)
    if options.diff_ref:
        findings = filter_to_diff(findings, root, options.diff_ref)
    if options.baseline:
        findings, stats.baselined = apply_baseline(findings, options.baseline)
    findings = [f for f in findings if f.severity.rank >= options.min_severity.rank]
    findings.sort(key=lambda f: (-f.severity.rank, f.category.value, f.path, f.line))

    score, grade = score_findings(findings, stats.lines_scanned)
    stats.duration_s = round(time.perf_counter() - started, 3)
    return ScanResult(root=display_root, findings=findings, stats=stats, score=score, grade=grade), repo


def _apply_overrides(findings: list[Finding], config: Config) -> list[Finding]:
    for f in findings:
        override = config.severity_overrides.get(f.rule_id)
        if override:
            f.severity = Severity.parse(override)
    return findings


def _apply_suppressions(findings: list[Finding], files: dict[str, FileContext]) -> tuple[list[Finding], int]:
    kept, suppressed = [], 0
    for f in findings:
        ctx = files.get(f.path)
        if ctx and _is_suppressed(ctx, f):
            suppressed += 1
        else:
            kept.append(f)
    return kept, suppressed


def _is_suppressed(ctx: FileContext, finding: Finding) -> bool:
    if _SUPPRESS_FILE.search("\n".join(ctx.lines[:5])):
        return True
    for lineno in (finding.line, finding.line - 1):
        match = _SUPPRESS.search(ctx.line(lineno))
        if match:
            ids = match.group("ids")
            if not ids or finding.rule_id in {i.strip().upper() for i in ids.split(",")}:
                return True
    return False


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int]] = set()
    unique = []
    for f in findings:
        key = (f.rule_id, f.path, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# -- baselines ------------------------------------------------------------------------

def write_baseline(findings: list[Finding], path: Path) -> None:
    payload = {
        "tool": "slopguard",
        "version": 1,
        "fingerprints": sorted({f.fingerprint for f in findings}),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def apply_baseline(findings: list[Finding], path: Path) -> tuple[list[Finding], int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    known = set(data.get("fingerprints", []))
    kept = [f for f in findings if f.fingerprint not in known]
    return kept, len(findings) - len(kept)


# -- diff mode ------------------------------------------------------------------------

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_lines(root: Path, ref: str) -> dict[str, set[int]]:
    """Lines added or modified relative to ``ref`` (committed, staged and unstaged changes)."""
    if ref.startswith("-"):
        raise ValueError("diff ref must not start with '-'")
    proc = subprocess.run(
        ["git", "diff", "--unified=0", "--no-color", "--no-ext-diff", ref, "--"],
        cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git diff failed: {proc.stderr.strip()}")
    changes: dict[str, set[int]] = {}
    current: str | None = None
    for line in proc.stdout.splitlines():
        if line.startswith("+++ "):
            target = line[4:]
            current = target[2:] if target.startswith("b/") else None
            if current is not None:
                changes.setdefault(current, set())
        elif current and (match := _HUNK.match(line)):
            start, count = int(match.group(1)), int(match.group(2) or 1)
            changes[current].update(range(start, start + count))
    return changes


def filter_to_diff(findings: list[Finding], root: Path, ref: str) -> list[Finding]:
    changes = changed_lines(root, ref)
    return [f for f in findings if f.path in changes and (f.line == 0 or f.line in changes[f.path])]
