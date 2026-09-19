"""API kimlik doğrulaması testleri."""

from fastapi.testclient import TestClient

from app import settings_store


def _client():
    import importlib
    import app.main as main_mod
    importlib.reload(main_mod)
    return TestClient(main_mod.app)


def test_tokensuz_modda_acik(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("API_TOKEN", raising=False)
    settings_store.set_explicit(None)
    c = _client()
    assert c.get("/health").status_code == 200
    assert c.post("/api/analyze", json={"subject": "s", "body": "merhaba", "sender": "a@b.com"}).status_code == 200
    settings_store.set_explicit(None)


def test_token_varken_korunur(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("API_TOKEN", "super-gizli-token")
    settings_store.set_explicit(None)
    c = _client()
    assert c.get("/health").status_code == 200  # health açık kalır
    assert c.post("/api/analyze", json={"subject": "s", "body": "x", "sender": "y"}).status_code == 401
    assert c.get("/api/emails/folders").status_code == 401
    ok = c.post("/api/analyze", json={"subject": "s", "body": "merhaba", "sender": "y"},
                headers={"Authorization": "Bearer super-gizli-token"})
    assert ok.status_code == 200
    assert c.post("/api/analyze", json={"subject": "s", "body": "x", "sender": "y"},
                  headers={"Authorization": "Bearer yanlis"}).status_code == 401
    settings_store.set_explicit(None)
