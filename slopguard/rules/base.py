"""Rule plumbing: every detector is a small class registered in a global registry."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from functools import cached_property

from ..context import FileContext, RepoContext
from ..models import Category, Finding, Severity

MAX_SNIPPET = 160


@dataclass(frozen=True)
class RuleMeta:
    id: str
    title: str
    category: Category
    severity: Severity
    description: str
    fix: str
    languages: frozenset[str] | None = None  # None = every code language
    include_config_files: bool = False  # also run on yaml/json/.env/... files
    include_tests: bool = True


class Rule:
    """Base class. Override ``check_file`` and/or ``check_repo``."""

    meta: RuleMeta

    def applies_to(self, ctx: FileContext) -> bool:
        if not ctx.language.is_code and not self.meta.include_config_files:
            return False
        if self.meta.languages is not None and ctx.language.name not in self.meta.languages:
            return False
        return self.meta.include_tests or not ctx.is_test

    def check_file(self, ctx: FileContext) -> Iterable[Finding]:
        return ()

    def check_repo(self, repo: RepoContext) -> Iterable[Finding]:
        return ()

    # -- helpers -----------------------------------------------------------------
    def finding(
        self,
        ctx: FileContext | None,
        line: int,
        message: str,
        *,
        snippet: str | None = None,
        severity: Severity | None = None,
        confidence: float = 0.8,
        source: str = "heuristic",
        fix: str | None = None,
        path: str | None = None,
    ) -> Finding:
        if snippet is None and ctx is not None:
            snippet = ctx.line(line).strip()
        return Finding(
            rule_id=self.meta.id,
            title=self.meta.title,
            category=self.meta.category,
            severity=severity or self.meta.severity,
            path=path if path is not None else (ctx.rel if ctx else ""),
            line=line,
            message=message,
            snippet=(snippet or "")[:MAX_SNIPPET],
            fix=fix or self.meta.fix,
            confidence=confidence,
            source=source,
        )


class PatternRule(Rule):
    """A rule defined by one or more regexes applied line-by-line.

    ``in_comments`` controls where a match counts: ``"code"`` ignores matches that are
    inside a comment, ``"comment"`` only accepts matches inside comments, ``"any"`` both.
    """

    patterns: tuple[re.Pattern[str], ...] = ()
    in_comments: str = "code"
    message: str = ""

    @cached_property
    def _prefilter(self) -> re.Pattern[str]:
        """All patterns OR-ed together, run once over the whole file to skip clean files fast."""
        parts = []
        for p in self.patterns:
            src = p.pattern
            if src.startswith("(?i)"):
                src = f"(?i:{src[4:]})"
            elif p.flags & re.IGNORECASE:
                src = f"(?i:{src})"
            parts.append(f"(?:{src})")
        return re.compile("|".join(parts), re.MULTILINE)

    def check_file(self, ctx: FileContext) -> Iterator[Finding]:
        if not self._prefilter.search(ctx.text):
            return
        for lineno, line in enumerate(ctx.lines, 1):
            for pattern in self.patterns:
                match = pattern.search(line)
                if not match or not self._location_ok(ctx, lineno, line, match):
                    continue
                if self.accept(ctx, lineno, line, match):
                    yield self.finding(ctx, lineno, self.describe(match))
                break

    def _location_ok(self, ctx: FileContext, lineno: int, line: str, match: re.Match[str]) -> bool:
        if self.in_comments == "any":
            return True
        comment = ctx.comments.get(lineno)
        in_comment = ctx.comment_only(lineno) or (
            bool(comment) and match.start() >= line.rfind(comment) - 3
        )
        return in_comment if self.in_comments == "comment" else not in_comment

    def accept(self, ctx: FileContext, lineno: int, line: str, match: re.Match[str]) -> bool:
        return True

    def describe(self, match: re.Match[str]) -> str:
        return self.message or self.meta.description


_REGISTRY: dict[str, Rule] = {}


def register(cls: type[Rule]) -> type[Rule]:
    rule = cls()
    if rule.meta.id in _REGISTRY:
        raise ValueError(f"duplicate rule id {rule.meta.id}")
    _REGISTRY[rule.meta.id] = rule
    return cls


def all_rules() -> list[Rule]:
    return sorted(_REGISTRY.values(), key=lambda r: r.meta.id)


def compile_all(*patterns: str, flags: int = 0) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, flags) for p in patterns)
