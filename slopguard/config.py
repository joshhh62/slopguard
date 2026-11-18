"""Configuration loaded from ``.slopguard.toml`` (or ``[tool.slopguard]`` in pyproject.toml)."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

import tomllib

DEFAULT_EXCLUDED_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", "third_party",
    "__pycache__", ".venv", "venv", "env", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "dist", "build", "out", "target", "bin", "obj", ".next", ".nuxt",
    ".gradle", ".idea", ".vscode", "coverage", "htmlcov", ".terraform", "site-packages",
    "Pods", ".dart_tool", ".slopguard",
})

DEFAULT_EXCLUDED_GLOBS = (
    "*.min.js", "*.min.css", "*.map", "*.lock", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "poetry.lock", "*.pb.go", "*_pb2.py", "*.generated.*",
    "slopguard-report.*", "*.sarif",  # our own reports quote the code they flag
)

MAX_FILE_BYTES = 1_000_000


@dataclass
class Config:
    exclude: list[str] = field(default_factory=list)  # extra glob patterns (repo-relative)
    disable_rules: set[str] = field(default_factory=set)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    max_file_bytes: int = MAX_FILE_BYTES
    duplicate_min_lines: int = 6

    def is_excluded(self, rel_path: str) -> bool:
        name = rel_path.rsplit("/", 1)[-1]
        for pattern in (*DEFAULT_EXCLUDED_GLOBS, *self.exclude):
            if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(name, pattern):
                return True
            # "examples/" or "examples/**" excludes the whole directory
            prefix = pattern.rstrip("*").rstrip("/")
            if prefix and pattern.endswith(("/", "/**")) and (
                rel_path == prefix or rel_path.startswith(prefix + "/")
            ):
                return True
        return False


def load_config(root: Path, explicit: Path | None = None) -> Config:
    """Load config from an explicit file, ``.slopguard.toml`` or ``pyproject.toml``."""
    data: dict = {}
    if explicit and not explicit.is_file():
        raise ValueError(f"config file {explicit} does not exist")
    candidates = [explicit] if explicit else [root / ".slopguard.toml", root / "pyproject.toml"]
    for candidate in candidates:
        if candidate.is_file():
            with candidate.open("rb") as fh:
                parsed = tomllib.load(fh)
            if candidate.name == "pyproject.toml":
                parsed = parsed.get("tool", {}).get("slopguard", {})
            if parsed:
                data = parsed
                break

    return Config(
        exclude=list(data.get("exclude", [])),
        disable_rules={r.upper() for r in data.get("disable", [])},
        severity_overrides={k.upper(): v for k, v in data.get("severity", {}).items()},
        max_file_bytes=int(data.get("max_file_bytes", MAX_FILE_BYTES)),
        duplicate_min_lines=int(data.get("duplicate_min_lines", 6)),
    )
