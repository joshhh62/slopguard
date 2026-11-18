"""Coding gaps: missing error handling, timeouts, tests and project hygiene."""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..context import FileContext, RepoContext
from ..models import Category, Finding, Severity
from .base import PatternRule, Rule, RuleMeta, compile_all, register

_GAP = Category.GAP


@register
class SwallowedErrorRule(Rule):
    meta = RuleMeta(
        id="GAP001", title="Error silently swallowed", category=_GAP, severity=Severity.HIGH,
        description="An exception/error is caught and discarded, hiding failures and corrupting state silently.",
        fix="Handle the error, log it with context, or let it propagate. Catch the narrowest error type possible.",
        languages=frozenset({"javascript", "typescript", "java", "kotlin", "csharp", "php", "dart", "swift",
                             "scala", "vue", "svelte", "go"}),
    )
    _EMPTY_CATCH = re.compile(r"\bcatch\s*(?:\([^)]*\))?\s*\{\s*(?://[^\n]*)?\}")
    _CATCH_OPEN = re.compile(r"\bcatch\s*(?:\([^)]*\))?\s*\{\s*$|\bif\s+(?:[^{]*;\s*)?err\s*!=\s*nil\s*\{\s*$")
    _GO_EMPTY = re.compile(r"\bif\s+err\s*!=\s*nil\s*\{\s*\}")
    _PROMISE = re.compile(r"\.catch\s*\(\s*(?:\(\s*\w*\s*\)|\w+)\s*=>\s*(?:\{\s*\}|null|undefined)\s*\)")

    def check_file(self, ctx: FileContext) -> Iterator[Finding]:
        lines = ctx.lines
        for lineno, line in enumerate(lines, 1):
            if ctx.comment_only(lineno):
                continue
            hit = self._EMPTY_CATCH.search(line) or self._GO_EMPTY.search(line) or self._PROMISE.search(line)
            if not hit and self._CATCH_OPEN.search(line):
                # catch (e) {\n   // ignore\n}
                body: list[str] = []
                for nxt in lines[lineno:lineno + 4]:
                    if nxt.strip().startswith("}"):
                        hit = not any(b and not b.startswith(("//", "/*", "*")) for b in body)
                        break
                    body.append(nxt.strip())
            if hit:
                yield self.finding(ctx, lineno, "Error is caught and ignored.", confidence=0.9)


@register
class MissingTimeoutRule(PatternRule):
    meta = RuleMeta(
        id="GAP006", title="Network call without timeout", category=_GAP, severity=Severity.MEDIUM,
        description="HTTP requests without a timeout can hang a worker forever when the remote end stalls.",
        fix="Pass an explicit timeout (e.g. requests.get(url, timeout=10)).",
        languages=frozenset({"python"}),
    )
    patterns = compile_all(r"\brequests\.(?:get|post|put|patch|delete|head|request)\s*\(")

    def accept(self, ctx: FileContext, lineno: int, line: str, match: re.Match[str]) -> bool:
        # Look ahead a few lines for multi-line calls.
        call = "\n".join(ctx.lines[lineno - 1:lineno + 6])
        depth, end = 0, len(call)
        for i, ch in enumerate(call[match.end() - 1:], match.end() - 1):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0:
                end = i
                break
        return "timeout" not in call[match.start():end]


@register
class IgnoredGoErrorRule(PatternRule):
    meta = RuleMeta(
        id="GAP007", title="Discarded error return", category=_GAP, severity=Severity.MEDIUM,
        description="The error result of a call is assigned to `_` and never checked.",
        fix="Check the error and handle or wrap it (`if err != nil { return fmt.Errorf(...: %w, err) }`).",
        languages=frozenset({"go"}),
        include_tests=False,
    )
    patterns = compile_all(r"^\s*(?:\w+\s*,\s*)?_\s*:?=\s*[\w.]+\(")


_UNPINNED = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*(?:;.*)?$")


@register
class UnpinnedDependencyRule(Rule):
    meta = RuleMeta(
        id="GAP009", title="Unpinned dependency", category=_GAP, severity=Severity.LOW,
        description="A requirement has no version constraint, so builds are not reproducible and can pull breaking or malicious releases.",
        fix="Pin a version or compatible range (package>=1.2,<2) and commit a lock file.",
    )

    def check_repo(self, repo: RepoContext) -> Iterator[Finding]:
        for rel in repo.inventory:
            name = rel.rsplit("/", 1)[-1]
            if not re.fullmatch(r"requirements[\w.\-]*\.txt", name):
                continue
            text = repo.read_text(rel) or ""
            for lineno, line in enumerate(text.splitlines(), 1):
                match = _UNPINNED.match(line)
                if match and not line.strip().startswith(("-", "#")):
                    yield self.finding(None, lineno, f"`{match.group(1)}` has no version constraint.",
                                       snippet=line.strip(), path=rel, confidence=0.9)


_SOURCE_LANGS = {"python", "javascript", "typescript", "java", "kotlin", "go", "rust", "csharp", "ruby", "php",
                 "swift", "scala", "dart", "elixir", "c", "cpp"}


@register
class MissingTestsRule(Rule):
    meta = RuleMeta(
        id="GAP004", title="No automated tests", category=_GAP, severity=Severity.MEDIUM,
        description="The repository has source code but no test files, so regressions go unnoticed.",
        fix="Add a test suite for the critical paths and run it in CI.",
    )

    def check_repo(self, repo: RepoContext) -> Iterator[Finding]:
        source = [f for f in repo.files if f.language.name in _SOURCE_LANGS and not f.is_test]
        tests = [f for f in repo.files if f.is_test and f.language.name in _SOURCE_LANGS]
        source_lines = sum(len(f.lines) for f in source)
        # A test directory counts even when config excludes it from scanning.
        has_test_dir = bool(repo.top_level_names & {"tests", "test", "__tests__", "spec", "specs"})
        if source_lines >= 150 and not tests and not has_test_dir:
            yield self.finding(None, 0, f"{len(source)} source files ({source_lines} lines) and zero test files.",
                               snippet="", path="", confidence=0.9)
        elif tests and source_lines >= 1000:
            ratio = sum(len(f.lines) for f in tests) / source_lines
            if ratio < 0.05:
                yield self.finding(None, 0, f"Test code is only {ratio:.0%} of source code size.",
                                   severity=Severity.LOW, snippet="", path="", confidence=0.6)


@register
class RepoHygieneRule(Rule):
    meta = RuleMeta(
        id="GAP005", title="Missing project hygiene file", category=_GAP, severity=Severity.LOW,
        description="Standard project files are missing (README, .gitignore, license, dependency manifest).",
        fix="Add the missing file so others can build, run and safely contribute to the project.",
    )

    def check_repo(self, repo: RepoContext) -> Iterator[Finding]:
        names = {n.lower() for n in repo.top_level_names}
        if not any(n.startswith("readme") for n in names):
            yield self.finding(None, 0, "No README at the repository root.", snippet="", path="")
        if ".gitignore" not in names:
            yield self.finding(None, 0, "No .gitignore - build output and secrets are easy to commit by accident.",
                               snippet="", path="", severity=Severity.MEDIUM)
        langs = {f.language.name for f in repo.files if not f.is_test}
        if "typescript" in langs:
            langs.add("javascript")
        anywhere = {rel.rsplit("/", 1)[-1].lower() for rel in repo.inventory}
        manifests = {
            "python": {"requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "pipfile"},
            "javascript": {"package.json"},
            "go": {"go.mod"}, "rust": {"cargo.toml"}, "java": {"pom.xml", "build.gradle", "build.gradle.kts"},
        }
        for lang, files in manifests.items():
            if lang in langs and not anywhere & files:
                yield self.finding(None, 0, f"{lang.title()} code but no dependency manifest ({', '.join(sorted(files))}).",
                                   snippet="", path="", severity=Severity.MEDIUM)
