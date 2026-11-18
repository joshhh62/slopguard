import io
import json

from app import app


def call(method, path, body=b"", headers=None):
    captured = {}
    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "CONTENT_LENGTH": str(len(body)),
               "wsgi.input": io.BytesIO(body), "HTTP_HOST": "slopguard.test", **(headers or {})}
    out = b"".join(app(environ, lambda status, hdrs: captured.update(status=status)))
    return captured["status"], out


def test_wsgi_serves_page_meta_and_demo_scan():
    assert call("GET", "/")[0].startswith("200")
    status, body = call("GET", "/api/meta")
    assert json.loads(body)["hosted"] is True
    status, body = call("POST", "/api/scan", json.dumps({"source": "demo"}).encode())
    assert status.startswith("200") and json.loads(body)["grade"] == "F"


def test_wsgi_hosted_refuses_local_paths_and_cross_origin():
    status, _ = call("POST", "/api/scan", json.dumps({"source": "C:/"}).encode())
    assert status.startswith("400")
    status, _ = call("POST", "/api/scan", b"{}", {"HTTP_ORIGIN": "https://evil.example"})
    assert status.startswith("403")
