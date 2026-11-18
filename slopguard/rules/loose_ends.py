"""Loose ends: work that was started, parked, or stubbed out and never finished."""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..context import FileContext
from ..models import Category, Finding, Severity
from .base import PatternRule, Rule, RuleMeta, compile_all, register

_LOOSE = Category.LOOSE_END

_MARKER = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG|KLUDGE|TEMP|WIP)\b[:(\s]?(.*)")
_MARKER_SEVERITY = {"FIXME": Severity.MEDIUM, "BUG": Severity.MEDIUM, "HACK": Severity.MEDIUM,
                    "XXX": Severity.MEDIUM, "KLUDGE": Severity.MEDIUM}


@register
class TodoMarkerRule(Rule):
    meta = RuleMeta(
        id="LOOSE001", title="Unresolved TODO/FIXME", category=_LOOSE, severity=Severity.LOW,
        description="A work-in-progress marker was committed. FIXME/HACK/XXX/BUG usually mean known-broken code.",
        fix="Resolve it, or move it into the issue tracker and link the ticket in the comment.",
    )

    def check_file(self, ctx: FileContext) -> Iterator[Finding]:
        for lineno, text in ctx.comments.items():
            match = _MARKER.search(text)
            if not match or match.group(1) in {"TEMP", "WIP"} and match.start() != 0:
                continue
            tag, note = match.group(1), match.group(2).strip(" :-")
            tracked = re.search(r"(?i)(#\d+|[A-Z]{2,}-\d+|https?://)", note)
            severity = _MARKER_SEVERITY.get(tag, Severity.LOW)
            if tracked:
                severity = Severity.INFO
            yield self.finding(
                ctx, lineno, f"{tag} left in code: {note or '(no description)'}",
                severity=severity, confidence=0.95,
            )


# Comment content that is syntactically code, not prose.
_CODE_LIKE = compile_all(
    r"^(?:def|class|import|from\s+\S+\s+import|return|raise|elif|else:|try:|except\b|finally:|with\s+.+:|for\s+.+\s+in\s+.+:|while\s+.+:|if\s+.+:)",
    r"^(?:const|let|var|function|public|private|protected|static|void|int|String|return|throw|await|async|func|fmt\.|import\s+[\w{*])\b",
    r"^[\w.\[\]\"']+\s*(?:=|\+=|-=|\*=|==)\s*[^=].*$",
    r"^[\w.]+\s*\(.*\)\s*;?$",
    r".*[;{}]\s*$",
)
_PROSE = re.compile(r"[A-Za-z]+\s+[a-z]+\s+[a-z]+\s+[a-z]+(?:\s|$)")


def _looks_like_code(text: str) -> bool:
    if len(text) < 4 or text.startswith(("TODO", "FIXME", "NOTE", "http", "e.g.", "i.e.", "-", "*", ">>>")):
        return False
    if any(p.match(text) for p in _CODE_LIKE):
        # "if the user is admin, then:" is prose that happens to match - long runs of words
        # without any code punctuation are rejected.
        return not (_PROSE.match(text) and not re.search(r"[()=\[\];{}]", text))
    return False


@register
class CommentedOutCodeRule(Rule):
    meta = RuleMeta(
        id="LOOSE002", title="Commented-out code", category=_LOOSE, severity=Severity.LOW,
        description="A block of code was disabled by commenting it out. Version control already remembers old code.",
        fix="Delete the block; if it must come back, recover it from git history.",
    )
    min_run = 2

    def check_file(self, ctx: FileContext) -> Iterator[Finding]:
        run: list[int] = []
        for lineno in [*sorted(ctx.comments), -1]:
            text = ctx.comments.get(lineno, "")
            is_code = lineno > 0 and ctx.comment_only(lineno) and _looks_like_code(text)
            if is_code and (not run or lineno == run[-1] + 1):
                run.append(lineno)
                continue
            if len(run) >= self.min_run:
                yield self.finding(
                    ctx, run[0], f"{len(run)} consecutive lines of commented-out code (lines {run[0]}-{run[-1]}).",
                    confidence=0.75,
                )
            run = [lineno] if is_code else []


@register
class StubImplementationRule(PatternRule):
    meta = RuleMeta(
        id="LOOSE003", title="Stubbed-out implementation", category=_LOOSE, severity=Severity.MEDIUM,
        description="The function body only throws 'not implemented' - callers will crash at runtime.",
        fix="Implement the behaviour, or remove the code path and its callers.",
        include_tests=False,
    )
    patterns = compile_all(
        r"^\s*raise\s+NotImplementedError\b",
        r"(?i)^\s*throw\s+new\s+(?:Error|UnsupportedOperationException|NotImplementedException|NotImplementedError)\s*\(\s*(?:[\"'`](?:not\s+(?:yet\s+)?implemented|todo|implement\s+me|unimplemented)|\))",
        r"\b(?:todo|unimplemented)!\s*\(",
        r"(?i)\bpanic\s*\(\s*\"(?:todo|not\s+implemented|unimplemented)",
        r"(?i)\bthrow\s+new\s+NotImplementedException\b",
    )

    def accept(self, ctx: FileContext, lineno: int, line: str, match: re.Match[str]) -> bool:
        # Abstract base classes legitimately raise NotImplementedError.
        window = "\n".join(ctx.lines[max(0, lineno - 8):lineno])
        return not re.search(r"@(?:abc\.)?abstractmethod|\babstract\b|class\s+\w+\((?:ABC|Protocol)", window)
