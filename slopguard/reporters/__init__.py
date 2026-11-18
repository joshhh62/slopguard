"""Report renderers. ``console`` writes to a stream; the others return a string."""

from collections.abc import Callable

from ..models import ScanResult
from .documents import to_html, to_markdown
from .machine import to_json, to_sarif

FILE_FORMATS: dict[str, tuple[str, Callable[[ScanResult], str]]] = {
    "json": ("slopguard-report.json", to_json),
    "sarif": ("slopguard.sarif", to_sarif),
    "md": ("slopguard-report.md", to_markdown),
    "html": ("slopguard-report.html", to_html),
}

__all__ = ["FILE_FORMATS", "to_html", "to_json", "to_markdown", "to_sarif"]
