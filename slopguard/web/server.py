"""`slopguard serve` - a local web dashboard on top of the scan engine.

Standard library only. Binds to 127.0.0.1 by default: the dashboard can scan local folders, so
it must never be exposed to a network. Public GitHub repositories are shallow-cloned into a
temporary directory that is removed after the scan.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .. import __version__
from ..engine import ScanOptions, scan
from ..models import Severity
from ..reporters import to_html, to_json, to_markdown, to_sarif
from ..rules import all_rules
from ..scoring import score_findings

STATIC_DIR = Path(__file__).resolve().parent / "static"
DEMO_APP = Path(__file__).resolve().parents[2] / "examples" / "vulnerable-app"
_GITHUB_URL = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(?:\.git)?/?$")
MAX_BODY = 64 * 1024
CLONE_TIMEOUT_S = 90

_last_result: dict[str, Any] = {}
_lock = threading.Lock()


def _ai_available() -> bool:
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def _clone(url: str, into: Path) -> Path:
    if not _GITHUB_URL.match(url):
        raise ValueError("Only public https://github.com/<owner>/<repo> URLs are supported")
    target = into / "repo"
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", "--", url, str(target)],
        capture_output=True, text=True, timeout=CLONE_TIMEOUT_S, check=False,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if proc.returncode != 0:
        raise ValueError(f"git clone failed: {proc.stderr.strip()[:300] or 'repository not found or private'}")
    return target


def run_scan(request: dict[str, Any]) -> dict[str, Any]:
    """Execute one scan request from the UI and return the JSON payload it renders."""
    source = str(request.get("source", "")).strip()
    use_ai = bool(request.get("ai"))
    tmp: tempfile.TemporaryDirectory[str] | None = None
    try:
        if source in {"", "demo"}:
            root, label = DEMO_APP, "examples/vulnerable-app (demo)"
        elif source.startswith("https://"):
            tmp = tempfile.TemporaryDirectory(prefix="slopguard-")
            root, label = _clone(source, Path(tmp.name)), source.removesuffix(".git").rstrip("/")
        else:
            root, label = Path(source).expanduser(), source
            if not root.is_dir():
                raise ValueError(f"'{source}' is not a folder on this machine")

        result, repo = scan(root, ScanOptions())
        result.root = label
        if use_ai:
            if not _ai_available():
                raise ValueError("AI triage needs ANTHROPIC_API_KEY set before starting `slopguard serve`")
            from ..agent import TriageAgent

            outcome = TriageAgent(repo).run(result.findings)
            result.findings = sorted(outcome.findings, key=lambda f: (-f.severity.rank, f.path, f.line))
            result.ai_summary, result.ai_usage = outcome.summary, outcome.usage
            result.score, result.grade = score_findings(result.findings, result.stats.lines_scanned)

        payload = json.loads(to_json(result))
        payload["files"] = _file_hotspots(payload["findings"])
        with _lock:
            _last_result.clear()
            _last_result.update({"result": result})
        return payload
    finally:
        if tmp is not None:
            shutil.rmtree(tmp.name, ignore_errors=True)


def _file_hotspots(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    weights = {"critical": 25, "high": 8, "medium": 3, "low": 1, "info": 0}
    files: dict[str, dict[str, Any]] = {}
    for f in findings:
        if not f["path"] or f["verdict"] == "false_positive":
            continue
        entry = files.setdefault(f["path"], {"path": f["path"], "risk": 0, "count": 0, "worst": "info"})
        entry["risk"] += weights[f["severity"]]
        entry["count"] += 1
        if Severity(f["severity"]).rank > Severity(entry["worst"]).rank:
            entry["worst"] = f["severity"]
    return sorted(files.values(), key=lambda e: -e["risk"])[:10]


_EXPORTS = {
    "json": ("application/json", "slopguard-report.json", to_json),
    "sarif": ("application/sarif+json", "slopguard.sarif", to_sarif),
    "md": ("text/markdown; charset=utf-8", "slopguard-report.md", to_markdown),
    "html": ("text/html; charset=utf-8", "slopguard-report.html", to_html),
}


class Handler(BaseHTTPRequestHandler):
    server_version = f"SlopGuard/{__version__}"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        return  # keep the terminal clean; the UI shows progress

    def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: Any) -> None:
        self._send(status, json.dumps(data).encode("utf-8"), "application/json")

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        path = self.path.split("?", 1)[0]
        if path in {"/", "/index.html"}:
            self._send(HTTPStatus.OK, (STATIC_DIR / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif path == "/api/meta":
            rules = [{"id": r.meta.id, "title": r.meta.title, "category": r.meta.category.value,
                      "severity": r.meta.severity.value, "description": r.meta.description} for r in all_rules()]
            self._json(HTTPStatus.OK, {"version": __version__, "ai": _ai_available(), "rules": rules})
        elif path.startswith("/api/export/"):
            fmt = path.rsplit("/", 1)[-1]
            with _lock:
                result = _last_result.get("result")
            if fmt not in _EXPORTS or result is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "run a scan first"})
                return
            ctype, filename, render = _EXPORTS[fmt]
            self._send(HTTPStatus.OK, render(result).encode("utf-8"), ctype,
                       {"Content-Disposition": f'attachment; filename="{filename}"'})
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        if self.path != "/api/scan":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if self.headers.get("Origin") not in {None, f"http://{self.headers.get('Host')}"}:
            self._json(HTTPStatus.FORBIDDEN, {"error": "cross-origin requests are not allowed"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request too large"})
            return
        try:
            request = json.loads(self.rfile.read(length) or b"{}")
            self._json(HTTPStatus.OK, run_scan(request if isinstance(request, dict) else {}))
        except (ValueError, OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})


def serve(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{'localhost' if host in {'127.0.0.1', '0.0.0.0'} else host}:{port}"
    print(f"SlopGuard dashboard running at {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
