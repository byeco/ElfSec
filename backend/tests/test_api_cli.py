"""API + CLI sözleşme testleri (geliştirici odaklı)."""

from fastapi.testclient import TestClient

from app.cli import fail_on_exceeded, main as cli_main
from app.main import app

c = TestClient(app)


def test_health_200():
    r = c.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_analyze_benign_low():
    r = c.post("/api/analyze", json={"subject": "selam", "body": "<p>merhaba</p>", "sender": "a@b.com"})
    assert r.status_code == 200
    assert r.json()["risk_level"] == "LOW"


def test_fail_on_sozlesmesi():
    assert fail_on_exceeded("HIGH", "MEDIUM") is True
    assert fail_on_exceeded("LOW", "MEDIUM") is False
    assert fail_on_exceeded("LOW", "NEVER") is False


def test_cli_analyze_fail_on_exit_code(tmp_path):
    f = tmp_path / "evil.html"
    f.write_text("<p>Hesabiniz kapanacak hemen tikla http://evil.tk/verify sifrenizi gonderin</p>", encoding="utf-8")
    code = cli_main(["analyze-file", "--path", str(f), "--fail-on", "MEDIUM", "--quiet"])
    assert code == 1  # şüpheli -> CI kapısı kapanmalı
