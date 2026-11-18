"""Vercel serverless entry point - the same handler that powers `slopguard serve`."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from slopguard.web.server import Handler as handler  # noqa: E402,N813 - Vercel looks up `handler`

__all__ = ["handler"]
