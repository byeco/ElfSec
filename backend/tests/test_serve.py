"""Web API testleri — canlı server (127.0.0.1, geçici port), urllib istemci."""

import json
import threading
import urllib.request
import urllib.error

import pytest

from app import serve as S


@pytest.fixture()
def srv(monkeypatch):
    monkeypatch.delenv("ELFSEC_API_TOKEN", raising=False)
    s = S.serve("127.0.0.1", 0, rate_limit=60)
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    yield s
    s.shutdown()
    s.server_close()


def _url(srv, path):
    return f"http://127.0.0.1:{srv.server_address[1]}{path}"


def _call(srv, path, payload=None, token=None, origin=None, raw=None):
    data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
    req = urllib.request.Request(_url(srv, path), data=data, method="POST" if data is not None else "GET")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if origin:
        req.add_header("Origin", origin)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), json.loads(e.read().decode())


def test_health(srv):
    code, _, body = _call(srv, "/v1/health")
    assert code == 200 and body["ok"] is True
    assert body["engine"] == "elfsec-local/1.0" and body["version"]


def test_analyze_temiz_ve_phish(srv):
    code, _, ok = _call(srv, "/v1/analyze", {"subject": "Merhaba", "body": "Yarın toplantı var mı?", "sender": "a@b.com"})
    assert code == 200 and ok["risk_level"] == "LOW"
    code, _, ph = _call(srv, "/v1/analyze", {"subject": "Hesabınız kapanacak!", "sender": "x@banka-secure.tk",
                                             "body": "Hemen tıkla http://evil.tk/verify"})
    assert code == 200 and ph["phishing_detected"] is True
    assert len(ph["plain_text"]) <= 2000  # siteye ham PII dönmez


def test_sanitize(srv):
    code, _, b = _call(srv, "/v1/sanitize", {"body": "<script>x</script><p>selam</p>"})
    assert code == 200 and "script" not in b["safe_html"] and "selam" in b["plain_text"]


def test_auth_tokenli_rejim(monkeypatch):
    monkeypatch.setenv("ELFSEC_API_TOKEN", "gizli123")
    s = S.serve("127.0.0.1", 0)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        code, _, _ = _call(s, "/v1/analyze", {"body": "x"})
        assert code == 401  # tokensuz red
        code, _, _ = _call(s, "/v1/analyze", {"body": "x"}, token="yanlis")
        assert code == 401  # yanlış token red
        code, _, b = _call(s, "/v1/analyze", {"body": "selam"}, token="gizli123")
        assert code == 200 and b["ok"] is True
    finally:
        s.shutdown()
        s.server_close()


def test_fail_closed_agda_tokensuz():
    assert S.check_bind_policy("0.0.0.0", "") is not None  # başlamayı reddeder
    assert S.check_bind_policy("0.0.0.0", "x") is None
    assert S.check_bind_policy("127.0.0.1", "") is None  # yerel deneme serbest


def test_rate_limit():
    s = S.serve("127.0.0.1", 0, rate_limit=2)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        assert _call(s, "/v1/health")[0] == 200
        assert _call(s, "/v1/health")[0] == 200
        code, headers, _ = _call(s, "/v1/health")
        assert code == 429  # 3. istek kota üstü
    finally:
        s.shutdown()
        s.server_close()


def test_girdi_sinirlari(srv):
    code, _, b = _call(srv, "/v1/analyze", {"subject": 5, "body": "x"})
    assert code == 400  # yanlış tip
    big = "x" * (S.MAX_HTTP_BODY + 1)
    code, _, b = _call(srv, "/v1/analyze", raw=b'{"body":"' + big.encode() + b'"}')
    assert code == 413  # DoS kesmesi
    code, _, _ = _call(srv, "/v1/analyze", raw=b"bozuk{json")
    assert code == 400
    code, _, _ = _call(srv, "/yok", None)
    assert code == 404


def test_cors_allowlist():
    s = S.serve("127.0.0.1", 0, cors_origins=("https://benimsitem.com",))
    threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        _, h, _ = _call(s, "/v1/health", origin="https://benimsitem.com")
        assert h.get("Access-Control-Allow-Origin") == "https://benimsitem.com"
        _, h2, _ = _call(s, "/v1/health", origin="https://kotu.com")
        assert "Access-Control-Allow-Origin" not in h2  # liste dışı yankılanmaz
    finally:
        s.shutdown()
        s.server_close()


def _kod(src: str) -> str:
    """Modül docstring'ini at (örnek komutlar secret sayılmaz), geri kalanı denetle."""
    parts = src.split('"""', 2)
    return parts[2] if len(parts) == 3 else src


def test_kodda_gomulu_secret_yok():
    import pathlib
    for f in ("app/serve.py", "app/cli.py"):
        code = _kod(pathlib.Path(f).read_text(encoding="utf-8"))
        assert "ELFSEC_API_TOKEN=" not in code  # atama yok, sadece okuma
        assert "gizli123" not in code and "test-token" not in code
    assert 'os.environ.get("ELFSEC_API_TOKEN"' in _kod(pathlib.Path("app/serve.py").read_text(encoding="utf-8"))
