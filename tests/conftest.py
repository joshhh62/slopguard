from __future__ import annotations

import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

from slopguard.engine import ScanOptions, scan
from slopguard.models import Finding

EXAMPLE_APP = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-app"


@pytest.fixture
def make_repo(tmp_path: Path) -> Callable[[dict[str, str]], Path]:
    """Write ``{relative_path: source}`` into a temp repo and return its root."""

    def _make(files: dict[str, str]) -> Path:
        for rel, content in files.items():
            target = tmp_path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
        return tmp_path

    return _make


def run(root: Path, **options) -> list[Finding]:
    result, _ = scan(root, ScanOptions(**options))
    return result.findings


def ids(findings: list[Finding]) -> list[str]:
    return [f.rule_id for f in findings]
