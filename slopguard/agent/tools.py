"""Read-only, sandboxed tools the triage agent can call.

The scanned repository is untrusted input. Every tool is read-only, confined to the repo root
(no path traversal, no symlink escape) and bounded in output size, so a malicious repository
cannot use the agent to read or modify anything else on the machine.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..context import RepoContext

MAX_READ_LINES = 200
MAX_SEARCH_HITS = 40
MAX_TOOL_OUTPUT = 12_000

_SEVERITIES = ["critical", "high", "medium", "low", "info"]
_CATEGORIES = ["security", "slop", "gap", "loose-end"]

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "read_file",
        "description": "Read a line range of a repository file (max 200 lines per call). "
                       "Use it to inspect the code around a candidate finding before judging it.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Repo-relative path with forward slashes."},
                "start_line": {"type": "integer", "description": "1-based first line."},
                "end_line": {"type": "integer", "description": "1-based last line (inclusive)."},
            },
            "required": ["path", "start_line", "end_line"],
            "additionalProperties": False,
        },
    },
    {
        "name": "search_code",
        "description": "Regex search across all scanned files. Use it to check whether input is sanitised "
                       "elsewhere, whether a function is called, or where a value comes from.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Python regular expression."},
                "path_glob": {"type": "string", "description": "Optional substring filter on the path, e.g. 'api/'."},
            },
            "required": ["pattern"],
            "additionalProperties": False,
        },
    },
    {
        "name": "record_verdict",
        "description": "Record your judgement on ONE candidate finding produced by the static scanner.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
                "verdict": {"type": "string", "enum": ["confirmed", "false_positive", "needs_review"]},
                "severity": {"type": "string", "enum": _SEVERITIES,
                             "description": "Corrected severity given the real context."},
                "rationale": {"type": "string", "description": "One or two sentences of evidence."},
                "fix": {"type": "string", "description": "Concrete fix for this codebase (code welcome)."},
            },
            "required": ["finding_id", "verdict", "severity", "rationale", "fix"],
            "additionalProperties": False,
        },
    },
    {
        "name": "report_issue",
        "description": "Report a NEW problem the static scanner missed (logic bugs, missing auth/validation, "
                       "unhandled edge cases, half-finished features). Only report issues you verified in the code.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "line": {"type": "integer"},
                "category": {"type": "string", "enum": _CATEGORIES},
                "severity": {"type": "string", "enum": _SEVERITIES},
                "title": {"type": "string", "description": "Short title, under 70 characters."},
                "explanation": {"type": "string"},
                "fix": {"type": "string"},
            },
            "required": ["path", "line", "category", "severity", "title", "explanation", "fix"],
            "additionalProperties": False,
        },
    },
    {
        "name": "finish",
        "description": "Call once every candidate has a verdict. Summarise the most important risks in this batch.",
        "input_schema": {
            "type": "object",
            "properties": {"summary": {"type": "string"}},
            "required": ["summary"],
            "additionalProperties": False,
        },
    },
]


class ToolError(Exception):
    """Raised for invalid tool input; returned to the model as an is_error tool_result."""


class RepoTools:
    def __init__(self, repo: RepoContext):
        self.repo = repo
        self.root = repo.root.resolve()
        self._files = {f.rel: f for f in repo.files}

    def _safe_path(self, rel: str) -> Path:
        rel = rel.replace("\\", "/").lstrip("/")
        candidate = (self.root / rel).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ToolError(f"path {rel!r} is outside the repository")
        return candidate

    def read_file(self, path: str, start_line: int, end_line: int) -> str:
        self._safe_path(path)
        ctx = self._files.get(path.replace("\\", "/").lstrip("/"))
        if ctx is None:
            raise ToolError(f"{path!r} is not a scanned file; use search_code to locate files")
        start = max(1, int(start_line))
        end = min(len(ctx.lines), int(end_line), start + MAX_READ_LINES - 1)
        if start > end:
            raise ToolError(f"empty range; file has {len(ctx.lines)} lines")
        width = len(str(end))
        body = "\n".join(f"{n:>{width}} | {ctx.lines[n - 1]}" for n in range(start, end + 1))
        return f"{path} (lines {start}-{end} of {len(ctx.lines)})\n{body}"

    def search_code(self, pattern: str, path_glob: str = "") -> str:
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            raise ToolError(f"invalid regex: {exc}") from exc
        hits = []
        for rel, ctx in self._files.items():
            if path_glob and path_glob not in rel:
                continue
            for lineno, line in enumerate(ctx.lines, 1):
                if regex.search(line):
                    hits.append(f"{rel}:{lineno}: {line.strip()[:200]}")
                    if len(hits) >= MAX_SEARCH_HITS:
                        return "\n".join(hits) + f"\n... (truncated at {MAX_SEARCH_HITS} hits)"
        return "\n".join(hits) if hits else "no matches"


def clip(text: str, limit: int = MAX_TOOL_OUTPUT) -> str:
    return text if len(text) <= limit else text[:limit] + "\n... (output truncated)"
