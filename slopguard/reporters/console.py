"""Human-friendly terminal output (ANSI colours, no third-party dependencies)."""

from __future__ import annotations

import os
import sys
from typing import TextIO

from ..models import Category, ScanResult, Severity, Verdict

_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m", Severity.HIGH: "\033[1;31m", Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m", Severity.INFO: "\033[2m",
}
_RESET, _BOLD, _DIM, _GREEN = "\033[0m", "\033[1m", "\033[2m", "\033[32m"
_GRADE_COLOR = {"A": "\033[1;32m", "B": "\033[1;32m", "C": "\033[1;33m", "D": "\033[1;31m", "F": "\033[1;97;41m"}


def _use_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def render(result: ScanResult, stream: TextIO = sys.stdout, show_dismissed: bool = False, limit: int = 60) -> None:
    color = _use_color(stream)

    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    out = stream.write
    visible = [f for f in result.findings if show_dismissed or f.verdict is not Verdict.FALSE_POSITIVE]
    dismissed = len(result.findings) - len([f for f in result.findings if f.verdict is not Verdict.FALSE_POSITIVE])

    out("\n" + c(_BOLD, "SlopGuard report") + c(_DIM, f"  {result.root}") + "\n")
    s = result.stats
    langs = ", ".join(f"{k} {v}" for k, v in list(s.languages.items())[:6])
    out(c(_DIM, f"{s.files_scanned} files, {s.lines_scanned:,} lines ({langs}) in {s.duration_s:.2f}s") + "\n\n")

    current_category = None
    for f in sorted(visible, key=lambda f: (f.category.value, -f.severity.rank, f.path, f.line))[:limit]:
        if f.category != current_category:
            current_category = f.category
            count = sum(1 for x in visible if x.category == f.category)
            out(c(_BOLD, f"== {f.category.label} ({count}) ") + "\n")
        sev = c(_COLORS[f.severity], f" {f.severity.value.upper():<8}") + " "
        tag = ""
        if f.verdict is Verdict.CONFIRMED:
            tag = c(_GREEN, " [AI confirmed]") if f.source != "ai" else c(_GREEN, " [AI found]")
        elif f.verdict is Verdict.NEEDS_REVIEW:
            tag = c(_COLORS[Severity.MEDIUM], " [needs review]")
        elif f.verdict is Verdict.FALSE_POSITIVE:
            tag = c(_DIM, " [AI dismissed]")
        out(f"{sev}{c(_BOLD, f.rule_id)} {f.title}{tag}\n")
        out(f"          {c(_DIM, f.location)}  {f.ai_rationale or f.message}\n")
        if f.snippet and f.path:
            out(f"          {c(_DIM, '> ' + f.snippet[:110])}\n")
        out(f"          {c(_GREEN, 'fix:')} {f.fix.splitlines()[0][:140] if f.fix else '-'}\n")
    if len(visible) > limit:
        out(c(_DIM, f"\n... {len(visible) - limit} more findings - see the full report (--format md/html/json)\n"))

    if result.ai_summary:
        out("\n" + c(_BOLD, "AI triage summary") + "\n" + result.ai_summary + "\n")

    counts = {sev: sum(1 for f in visible if f.severity == sev) for sev in Severity}
    summary = "  ".join(c(_COLORS[sev], f"{sev.value}: {n}") for sev, n in counts.items() if n)
    cats = "  ".join(f"{cat.label}: {sum(1 for f in visible if f.category == cat)}" for cat in Category)
    out("\n" + c(_BOLD, "Summary  ") + (summary or c(_GREEN, "no findings")) + "\n")
    out(c(_DIM, f"         {cats}") + "\n")
    extras = []
    if s.suppressed:
        extras.append(f"{s.suppressed} suppressed inline")
    if s.baselined:
        extras.append(f"{s.baselined} in baseline")
    if dismissed:
        extras.append(f"{dismissed} dismissed by AI triage")
    if extras:
        out(c(_DIM, "         " + ", ".join(extras)) + "\n")
    if result.ai_usage:
        u = result.ai_usage
        cost = f", ~${u['estimated_cost_usd']}" if u.get("estimated_cost_usd") is not None else ""
        out(c(_DIM, f"         AI: {u['model']}, {u['requests']} requests, {u['tool_calls']} tool calls{cost}") + "\n")
        for err in u.get("errors", [])[:3]:
            out(c(_COLORS[Severity.MEDIUM], f"         AI warning: {err[:160]}") + "\n")
    grade = c(_GRADE_COLOR.get(result.grade, ""), f" {result.grade} ")
    out(f"\n{c(_BOLD, 'Health score')} {result.score}/100  {grade}\n\n")
