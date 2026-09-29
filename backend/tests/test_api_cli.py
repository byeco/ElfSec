"""TOOL CLI sözleşme testleri (serversiz)."""

import pytest

from app.cli import clamp_limit, fail_on_exceeded, main as cli_main, validate_folder
from app.sdk import scan_text


def test_health_ok():
    assert cli_main(["health"]) == 0


def test_analyze_benign_low_sdk():
    r = scan_text(subject="selam", body="<p>merhaba</p>", sender="a@b.com")
    assert r["risk_level"] == "LOW"


def test_fail_on_sozlesmesi():
    assert fail_on_exceeded("HIGH", "MEDIUM") is True
    assert fail_on_exceeded("LOW", "MEDIUM") is False
    assert fail_on_exceeded("LOW", "NEVER") is False


def test_cli_analyze_fail_on_exit_code(tmp_path):
    f = tmp_path / "evil.html"
    f.write_text("<p>Hesabiniz kapanacak hemen tikla http://evil.tk/verify sifrenizi gonderin</p>", encoding="utf-8")
    code = cli_main(["analyze-file", "--path", str(f), "--fail-on", "MEDIUM", "--quiet"])
    assert code == 1  # şüpheli -> CI kapısı kapanmalı


def test_folder_enjeksiyon_reddi():
    with pytest.raises(ValueError):
        validate_folder("../INBOX")
    assert validate_folder("INBOX") == "INBOX"
    assert validate_folder("[Gmail]/Spam") == "[Gmail]/Spam"


def test_limit_clamp():
    assert clamp_limit(20) == 20
    with pytest.raises(ValueError):
        clamp_limit(0)
    with pytest.raises(ValueError):
        clamp_limit(9999)


def test_guard_interval_min_reddi():
    assert cli_main(["guard", "--interval", "0", "--once", "--quiet"]) == 2
