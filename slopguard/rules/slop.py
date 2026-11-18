"""AI slop: residue left behind when generated code is pasted in without review."""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..context import FileContext
from ..models import Category, Finding, Severity
from .base import PatternRule, Rule, RuleMeta, compile_all, register

_SLOP = Category.SLOP


@register
class ChatArtifactRule(PatternRule):
    meta = RuleMeta(
        id="SLOP001", title="LLM chat residue in code", category=_SLOP, severity=Severity.HIGH,
        description="Conversational assistant text or a markdown fence was pasted into a source file.",
        fix="Delete the conversational text and review the surrounding code - it was likely never read by a human.",
    )
    in_comments = "any"
    patterns = compile_all(
        r"(?i)\bas\s+an\s+ai(?:\s+language)?\s+model\b",
        r"(?i)\bI\s+(?:hope|trust)\s+this\s+helps\b",
        r"(?i)^\W*(?:certainly|sure|absolutely|of\s+course)!\s+(?:here|below|I)",
        r"(?i)\bhere(?:'s|\s+is)\s+(?:the|an?|your)\s+(?:updated|modified|revised|corrected|complete|improved|refactored)\s+(?:code|version|implementation|function|file)\b",
        r"(?i)\b(?:let\s+me\s+know|feel\s+free\s+to\s+ask)\s+if\s+you\s+(?:need|have|want)\b",
        r"(?i)\bI(?:'ve|\s+have)\s+(?:updated|modified|added|refactored|fixed)\s+the\s+code\b",
        r"(?i)\b(?:my\s+)?knowledge\s+cutoff\b",
        r"^\s*```[a-zA-Z+#]*\s*$",
    )

    def accept(self, ctx: FileContext, lineno: int, line: str, match: re.Match[str]) -> bool:
        if "```" in match.group(0):  # markdown fences are normal inside docstrings and doc comments
            return ctx.language.name != "python" and lineno not in ctx.comments
        return True


@register
class ElisionPlaceholderRule(PatternRule):
    meta = RuleMeta(
        id="SLOP002", title="Elided or placeholder implementation", category=_SLOP, severity=Severity.HIGH,
        description="Generated code was truncated (an elided 'rest of the code' marker or a 'your logic here' stub), so behaviour is missing.",
        fix="Write the missing implementation, or delete the stub and fail loudly until it exists.",
    )
    in_comments = "any"
    patterns = compile_all(
        r"(?i)\.\.\.\s*(?:\(?\s*)?(?:rest|remainder)\s+of\s+(?:the\s+)?(?:code|file|implementation|function|class)",
        r"(?i)(?:#|//|/\*)\s*\.\.\.\s*(?:existing|previous|other|same|more)\s+(?:code|logic|methods|imports|implementation)",
        r"(?i)(?:#|//|/\*)\s*(?:your|add\s+your|insert\s+(?:your\s+)?|put\s+your)\s+(?:own\s+)?(?:code|logic|implementation)\s+here",
        r"(?i)(?:#|//|/\*)\s*(?:implementation|logic|code)\s+(?:goes|would\s+go)\s+here",
        r"(?i)(?:#|//|/\*)\s*(?:same\s+as\s+(?:before|above)|unchanged\s+from\s+(?:before|above))\b",
        r"(?i)(?:#|//)\s*(?:in\s+a\s+real\s+(?:app|application|implementation|scenario|system)|in\s+production\s+you\s+would)\b",
        r"(?i)(?:#|//)\s*(?:simulate|mock|fake|dummy|hardcoded?)\s+(?:the\s+)?(?:api|response|data|result|call|database|db)\b",
    )


@register
class PlaceholderValueRule(PatternRule):
    meta = RuleMeta(
        id="SLOP003", title="Placeholder value left in code", category=_SLOP, severity=Severity.MEDIUM,
        description="A template value (an API-key placeholder, 'change me', lorem ipsum) was never replaced.",
        fix="Read the value from configuration and fail fast with a clear error when it is missing.",
        include_config_files=True,
        include_tests=False,
    )
    in_comments = "code"
    patterns = compile_all(
        r"(?i)[\"'](?:your[_\- ]?(?:api[_\- ]?key|token|secret|password|key|username|email|domain|project[_\- ]?id)[_\- ]?(?:here)?|"
        r"<your[_\- ][^>\"']+>|changeme|change[_\-]me|replace[_\-]?me|insert[_\- ]\w+[_\- ]here|sk-x{6,}|"
        r"lorem\s+ipsum[^\"']*)[\"']",
    )


# Comments that narrate obvious code - a signature of unedited generated code.
_OBVIOUS_COMMENT = compile_all(
    r"(?i)^(?:step\s+\d+\s*:\s*)?import\s+(?:the\s+)?(?:necessary|required|needed)\s+(?:libraries|modules|packages|dependencies)\.?$",
    r"(?i)^(?:define|create)\s+(?:a|the)\s+(?:main\s+)?(?:function|class|method|variable|constants?)(?:\s+to\s+\w+.*)?\.?$",
    r"(?i)^(?:initiali[sz]e|declare)\s+(?:the\s+)?(?:variables?|counter|list|array|dictionary|result)\.?$",
    r"(?i)^return\s+(?:the\s+)?(?:result|output|value|response)\.?$",
    r"(?i)^call\s+the\s+(?:main\s+)?function\.?$",
    r"(?i)^(?:loop|iterate)\s+(?:through|over)\s+(?:the|each|all)\s+\w+\.?$",
    r"(?i)^increment\s+(?:the\s+)?(?:counter|index|i|count)(?:\s+by\s+(?:one|1))?\.?$",
    r"(?i)^(?:main\s+function|end\s+of\s+(?:function|class|file|loop))\.?$",
    r"(?i)^(?:print|log|display)\s+(?:the\s+)?(?:result|output|value)s?\.?$",
    r"(?i)^check\s+if\s+(?:the\s+)?\w+\s+is\s+(?:valid|empty|none|null)\.?$",
)


@register
class ObviousCommentRule(Rule):
    meta = RuleMeta(
        id="SLOP006", title="Comment narrates obvious code", category=_SLOP, severity=Severity.LOW,
        description="Boilerplate comments like '# Initialize variables' or '// Return the result' add noise, not intent.",
        fix="Delete the comment, or replace it with the *why* behind the code.",
        include_tests=False,
    )

    def check_file(self, ctx: FileContext) -> Iterator[Finding]:
        hits = [
            lineno for lineno, text in ctx.comments.items()
            if ctx.comment_only(lineno) and any(p.match(text) for p in _OBVIOUS_COMMENT)
        ]
        # A single one is fine; a cluster is the generated-code smell worth reporting.
        if len(hits) >= 2:
            for lineno in sorted(hits):
                yield self.finding(ctx, lineno, "Comment restates what the code obviously does.", confidence=0.7)


@register
class DebugLeftoverRule(PatternRule):
    meta = RuleMeta(
        id="SLOP007", title="Debugging leftover", category=_SLOP, severity=Severity.LOW,
        description="A debugger hook or ad-hoc debug print was left in committed code.",
        fix="Remove it, or route the message through the project's logger at debug level.",
        include_tests=False,
    )
    patterns = compile_all(
        r"^\s*debugger\s*;?\s*$",
        r"\b(?:pdb|ipdb|pudb)\.set_trace\s*\(|^\s*breakpoint\s*\(\s*\)",
        r"^\s*console\.(?:log|debug|dir|trace)\s*\(",
        r"\b(?:var_dump|print_r|dd)\s*\(",
        r"(?i)^\s*print\s*\(\s*f?[\"'](?:debug|here|test|xxx|>>>|-{3,}|\*{3,}|got here)",
        r"^\s*(?:System\.out\.println|fmt\.Println)\s*\(\s*\"(?i:debug|here|test)",
        r"^\s*dbg!\s*\(",
    )

    def accept(self, ctx: FileContext, lineno: int, line: str, match: re.Match[str]) -> bool:
        # CLIs and scripts legitimately print; only flag console.* outside obvious CLI entry points.
        return not (ctx.rel.endswith(("cli.js", "cli.ts", "bin.js")) and "console." in line)
