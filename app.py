"""WSGI entry point for hosting the SlopGuard dashboard (Vercel, gunicorn, waitress, ...).

Pure standard library. Hosted mode is forced on, so the public app only ever scans public
GitHub repositories (never the server's own filesystem).
"""

from __future__ import annotations

import json
import os
import tarfile
from collections.abc import Callable, Iterable
from typing import Any

os.environ.setdefault("SLOPGUARD_HOSTED", "1")

from slopguard.web.server import MAX_BODY, STATIC_DIR, meta, run_scan  # noqa: E402

_SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                "script-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'"),
]


def _respond(start_response: Callable[..., Any], status: str, body: bytes, ctype: str) -> Iterable[bytes]:
    start_response(status, [("Content-Type", ctype), ("Content-Length", str(len(body))), *_SECURITY_HEADERS])
    return [body]


def _json(start_response: Callable[..., Any], status: str, data: Any) -> Iterable[bytes]:
    return _respond(start_response, status, json.dumps(data).encode("utf-8"), "application/json")


def app(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/") or "/"
    if method == "GET" and path in {"/", "/index.html"}:
        return _respond(start_response, "200 OK", (STATIC_DIR / "index.html").read_bytes(), "text/html; charset=utf-8")
    if method == "GET" and path == "/api/meta":
        return _json(start_response, "200 OK", meta())
    if method == "POST" and path == "/api/scan":
        origin = environ.get("HTTP_ORIGIN")
        if origin is not None and origin.split("://", 1)[-1] != environ.get("HTTP_HOST"):
            return _json(start_response, "403 Forbidden", {"error": "cross-origin requests are not allowed"})
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            return _json(start_response, "413 Payload Too Large", {"error": "request too large"})
        try:
            request = json.loads(environ["wsgi.input"].read(length) or b"{}")
            return _json(start_response, "200 OK", run_scan(request if isinstance(request, dict) else {}))
        except (ValueError, OSError, RuntimeError, tarfile.TarError) as exc:
            return _json(start_response, "400 Bad Request", {"error": str(exc)})
    return _json(start_response, "404 Not Found", {"error": "not found"})
