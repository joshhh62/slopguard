"""`slopguard serve` - the web dashboard, locally or as a hosted serverless app.

Standard library only. Locally it binds to 127.0.0.1 and can scan folders on this machine. When
hosted (``SLOPGUARD_HOSTED=1`` or running on Vercel) it only accepts public GitHub repositories,
which are downloaded as a size-capped tarball snapshot (no git binary needed), extracted with
path-traversal protection into a temp directory, scanned and deleted.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import tarfile
import tempfile
import threading
import urllib.error
import urllib.request
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .. import __version__
from ..engine import ScanOptions, scan
from ..models import Severity
from ..reporters import to_html, to_markdown, to_sarif
from ..rules import all_rules
from ..scoring import score_findings

STATIC_DIR = Path(__file__).resolve().parent / "static"
DEMO_APP = Path(__file__).resolve().parents[2] / "examples" / "vulnerable-app"
_GITHUB_URL = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
MAX_BODY = 64 * 1024
MAX_ARCHIVE_BYTES = 40 * 1024 * 1024
MAX_EXPORT_FINDINGS = 1500
FETCH_TIMEOUT_S = 45


def hosted() -> bool:
    return bool(os.environ.get("SLOPGUARD_HOSTED") or os.environ.get("VERCEL"))


def _ai_available() -> bool:
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def fetch_github(url: str, into: Path) -> Path:
    """Download the default branch of a public GitHub repo as a tarball and extract it safely."""
    match = _GITHUB_URL.match(url)
    if not match:
        raise ValueError("Only public https://github.com/<owner>/<repo> URLs are supported")
    owner, repo = match.groups()
    archive_url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD"
    request = urllib.request.Request(archive_url, headers={"User-Agent": f"slopguard/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_S) as response:
            data = response.read(MAX_ARCHIVE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise ValueError("Repository not found, private, or empty" if exc.code == 404
                         else f"GitHub returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise ValueError(f"Could not reach GitHub: {exc.reason}") from exc
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("Repository is larger than 40 MB - run the CLI locally for big repos")
    target = into / "repo"
    target.mkdir()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        archive.extractall(target, filter="data")  # rejects absolute paths, '..', links outside
    children = [p for p in target.iterdir() if p.is_dir()]
    return children[0] if len(children) == 1 else target


def run_scan(request: dict[str, Any]) -> dict[str, Any]:
    """Execute one scan request from the UI and return the JSON payload it renders."""
    source = str(request.get("source", "")).strip()
    use_ai = bool(request.get("ai"))
    tmp: str | None = None
    try:
        if source in {"", "demo"}:
            root, label = DEMO_APP, "examples/vulnerable-app (demo)"
        elif source.startswith("https://"):
            tmp = tempfile.mkdtemp(prefix="slopguard-")
            root, label = fetch_github(source, Path(tmp)), source.removesuffix(".git").rstrip("/")
        elif hosted():
            raise ValueError("The hosted dashboard scans public GitHub URLs only - use the CLI for local folders")
        else:
            root, label = Path(source).expanduser(), source
            if not root.is_dir():
                raise ValueError(f"'{source}' is not a folder on this machine")

        result, repo = scan(root, ScanOptions())
        result.root = label
        if use_ai:
            if not _ai_available():
                raise ValueError("AI triage needs ANTHROPIC_API_KEY configured on the server")
            from ..agent import TriageAgent

            outcome = TriageAgent(repo).run(result.findings)
            result.findings = sorted(outcome.findings, key=lambda f: (-f.severity.rank, f.path, f.line))
            result.ai_summary, result.ai_usage = outcome.summary, outcome.usage
            result.score, result.grade = score_findings(result.findings, result.stats.lines_scanned)

        payload = {
            "tool": {"name": "slopguard", "version": __version__},
            "root": result.root, "score": result.score, "grade": result.grade,
            "stats": vars(result.stats),
            "ai": {"summary": result.ai_summary, "usage": result.ai_usage} if result.ai_usage else None,
            "findings": [f.to_dict() for f in result.findings],
        }
        payload["files"] = _file_hotspots(payload["findings"])
        small = len(result.findings) <= MAX_EXPORT_FINDINGS
        payload["exports"] = {
            "md": to_markdown(result),
            "sarif": to_sarif(result),
            "html": to_html(result) if small else "",
        }
        return payload
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)


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


def meta() -> dict[str, Any]:
    rules = [{"id": r.meta.id, "title": r.meta.title, "category": r.meta.category.value,
              "severity": r.meta.severity.value} for r in all_rules()]
    return {"version": __version__, "ai": _ai_available(), "hosted": hosted(), "rules": rules}


class Handler(BaseHTTPRequestHandler):
    server_version = f"SlopGuard/{__version__}"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        return  # keep the terminal clean; the UI shows progress

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data: blob:; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: Any) -> None:
        self._send(status, json.dumps(data).encode("utf-8"), "application/json")

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        path = self.path.split("?", 1)[0]
        if path in {"/", "/index.html", "/api/page"}:
            self._send(HTTPStatus.OK, (STATIC_DIR / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif path == "/api/meta":
            self._json(HTTPStatus.OK, meta())
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        if self.path.split("?", 1)[0] != "/api/scan":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        origin = self.headers.get("Origin")
        if origin is not None and origin.split("://", 1)[-1] != self.headers.get("Host"):
            self._json(HTTPStatus.FORBIDDEN, {"error": "cross-origin requests are not allowed"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request too large"})
            return
        try:
            request = json.loads(self.rfile.read(length) or b"{}")
            self._json(HTTPStatus.OK, run_scan(request if isinstance(request, dict) else {}))
        except (ValueError, OSError, RuntimeError, tarfile.TarError) as exc:
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
