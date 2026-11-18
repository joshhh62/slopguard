import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from slopguard.web.server import Handler, run_scan


@pytest.fixture(scope="module")
def base_url():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _post(url, body, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    return urllib.request.urlopen(req, timeout=30)


def test_dashboard_page_and_meta(base_url):
    page = urllib.request.urlopen(base_url + "/").read().decode()
    assert "Find the" in page and "/api/scan" in page
    meta = json.loads(urllib.request.urlopen(base_url + "/api/meta").read())
    assert len(meta["rules"]) == 38 and "ai" in meta


def test_demo_scan_and_exports(base_url):
    data = json.loads(_post(base_url + "/api/scan", {"source": "demo"}).read())
    assert data["grade"] == "F" and data["files"][0]["path"] == "api/app.py"
    sarif = json.loads(urllib.request.urlopen(base_url + "/api/export/sarif").read())
    assert sarif["version"] == "2.1.0"


def test_rejects_bad_sources_and_cross_origin(base_url, tmp_path):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(base_url + "/api/scan", {"source": "https://evil.example/repo"})
    assert exc.value.code == 400
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(base_url + "/api/scan", {"source": "demo"}, {"Origin": "http://evil.example"})
    assert exc.value.code == 403
    with pytest.raises(ValueError):
        run_scan({"source": str(tmp_path / "missing")})
