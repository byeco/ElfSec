"""v0.4.0 başlık doğrulaması: SPF/DKIM/DMARC + spoof çelişkileri."""

import types

from app.cli import main as cli_main
from app.services.ai_analyzer import local_analyze
from app.services.imap_client import extract_headers


def test_auth_results_fail():
    h = {"reply_to": "", "return_path": "",
         "auth_results": "mx.google.com; spf=fail dkim=fail dmarc=fail", "message_id": ""}
    r = local_analyze("fatura", "borcunuz var", [], "a@b.com", h)
    assert r["risk_score"] >= 50
    assert any("SPF" in x or "spf" in x.lower() or "Kimlik" in x for x in r["reasons"])


def test_auth_results_pass_temiz():
    h = {"reply_to": "", "return_path": "",
         "auth_results": "mx.google.com; spf=pass dkim=pass dmarc=pass", "message_id": ""}
    r = local_analyze("selam", "merhaba", [], "a@b.com", h)
    assert r["risk_level"] == "LOW"


def test_reply_to_mismatch():
    h = {"reply_to": "destek@evil.tk", "return_path": "", "auth_results": "", "message_id": ""}
    r = local_analyze("hesap", "bilgi", [], "destek@banka.com", h)
    assert r["risk_score"] >= 20
    assert any("Reply-To" in x for x in r["reasons"])


def test_reply_to_ayni_temiz():
    h = {"reply_to": "destek@banka.com", "return_path": "", "auth_results": "", "message_id": ""}
    r = local_analyze("hesap", "bilgi", [], "destek@banka.com", h)
    assert not any("Reply-To" in x for x in r["reasons"])


def test_return_path_mismatch():
    h = {"reply_to": "", "return_path": "<bounce@evil.tk>", "auth_results": "", "message_id": ""}
    r = local_analyze("hesap", "bilgi", [], "destek@banka.com", h)
    assert any("Return-Path" in x for x in r["reasons"])


def test_message_id_yabanci():
    h = {"reply_to": "", "return_path": "",
         "auth_results": "", "message_id": "<123@evil.tk>"}
    r = local_analyze("hesap", "bilgi", [], "destek@banka.com", h)
    assert any("Message-ID" in x for x in r["reasons"])


def test_marka_display_name():
    h = {"reply_to": "", "return_path": "", "auth_results": "", "message_id": ""}
    r = local_analyze("Garanti Bankasi", "bilgi", [], "Garanti Bankasi <destek@evil-bank.tk>", h)
    assert r["risk_score"] >= 20
    assert any("Marka" in x for x in r["reasons"])


def test_basliksiz_ceza_yok():
    r = local_analyze("selam", "merhaba nasilsin", [], "a@b.com", None)
    assert r["risk_level"] == "LOW"


def test_extract_headers_fake():
    m = types.SimpleNamespace(
        headers={"Return-Path": "<b@x.com>", "Authentication-Results": "spf=pass",
                 "Message-ID": "<1@x.com>"},
        reply_to="r@x.com",
    )
    h = extract_headers(m)
    assert h["reply_to"] == "r@x.com"
    assert "spf=pass" in h["auth_results"]
    assert h["message_id"] == "<1@x.com>"


def test_cli_header_uctan_uca(tmp_path):
    f = tmp_path / "m.html"
    f.write_text("<p>merhaba</p>", encoding="utf-8")
    code = cli_main(["analyze-file", "--path", str(f), "--sender", "destek@banka.com",
                     "--header", "Reply-To: evil@evil.tk", "--fail-on", "LOW", "--quiet"])
    assert code == 1  # reply-to çelişkisi (+20) LOW eşiğini aştı
