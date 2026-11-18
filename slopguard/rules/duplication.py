"""Copy-paste duplication - the most common shape of AI slop at repository scale."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterator

from ..context import FileContext, RepoContext
from ..models import Category, Finding, Severity
from .base import Rule, RuleMeta, register

_TRIVIAL = re.compile(r"^[\s{}()\[\];,]*$|^(?:else|end|try|finally|pass|break|continue|return)\s*[:;]?$|^(?:import|from|#include|using|package)\b")


def _normalized(ctx: FileContext) -> list[tuple[int, str]]:
    """Meaningful lines with whitespace collapsed; comments, blanks and brace-only lines dropped."""
    out = []
    for lineno, line in enumerate(ctx.lines, 1):
        stripped = " ".join(line.split())
        if not stripped or ctx.comment_only(lineno) or _TRIVIAL.match(stripped):
            continue
        out.append((lineno, stripped))
    return out


@register
class DuplicateBlockRule(Rule):
    meta = RuleMeta(
        id="SLOP005", title="Duplicated code block", category=Category.SLOP, severity=Severity.MEDIUM,
        description="The same block of logic appears in more than one place; fixes applied to one copy will miss the others.",
        fix="Extract the shared logic into one function/module and call it from both places.",
        include_tests=False,
    )

    def check_repo(self, repo: RepoContext) -> Iterator[Finding]:
        window = max(3, repo.config.duplicate_min_lines)
        seen: dict[str, tuple[str, int]] = {}
        groups: dict[tuple[str, int], list[tuple[FileContext, int]]] = defaultdict(list)
        for ctx in repo.files:
            if not ctx.language.is_code or ctx.is_test:
                continue
            lines = _normalized(ctx)
            covered_until = -1
            for i in range(len(lines) - window + 1):
                chunk = lines[i:i + window]
                text = "\n".join(t for _, t in chunk)
                if len(text) < 25 * window:  # tiny lines (e.g. `x = 1`) are not interesting
                    continue
                digest = hashlib.blake2b(text.encode(), digest_size=12).hexdigest()
                start = chunk[0][0]
                if digest not in seen:
                    seen[digest] = (ctx.rel, start)
                    continue
                first = seen[digest]
                if first[0] == ctx.rel and abs(first[1] - start) < window:
                    continue  # overlapping window in the same file
                if start <= covered_until:
                    continue  # already reported as part of a longer run
                groups[first].append((ctx, start))
                covered_until = chunk[-1][0]
        # Collapse to one finding per file so a cloned module is one finding, not fifty.
        per_file: dict[str, list[tuple[FileContext, int, str, int]]] = defaultdict(list)
        for (first_path, first_line), dupes in groups.items():
            for ctx, start in dupes:
                per_file[ctx.rel].append((ctx, start, first_path, first_line))
        for _, blocks in sorted(per_file.items()):
            ctx, start, first_path, first_line = min(blocks, key=lambda b: b[1])
            where = "earlier in this file" if first_path == ctx.rel else f"`{first_path}`"
            origins = len({b[2] for b in blocks})
            extra = f" ({len(blocks)} duplicated blocks from {origins} place(s) in total)" if len(blocks) > 1 else ""
            yield self.finding(
                ctx, start, f"{window}+ line block duplicated from {where} (line {first_line}){extra}.",
                confidence=0.85,
            )
