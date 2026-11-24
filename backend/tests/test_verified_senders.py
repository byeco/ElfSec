"""v1.5.0: Doğrulanmış resmi marka göndericileri ve anti-taklit motoru testleri."""

import json

from app.cli import main as cli_main
from app.kontrol import run_kontrol
from app.services.ai_analyzer import local_analyze
from app.verified_senders import (
    add_verified_sender,
    load_verified_senders,
    remove_verified_sender,
    reset_verified_senders,
    verify_sender,
)


def test_apple_official_verified_strong_reduces_fp():
    r = local_analyze(
        subject="Apple ID güvenlik bildirimi",
        plain_text="Apple ID hesabınızla yeni bir oturum açıldı. Şifrenizi siz değiştirmediyseniz kontrol edin.",
        urls=[],
        sender="Apple <appleid@id.apple.com>",
        headers={
            "reply_to": "no_reply@email.apple.com",
            "return_path": "",
            "auth_results": "mx.google.com; spf=pass dkim=pass dmarc=pass",
            "message_id": "<msg1@email.apple.com>",
        },
    )
    sv = r["sender_verification"]
    assert sv["status"] == "VERIFIED_STRONG"
    assert sv["brand"] == "Apple"
    assert sv["exact_official_address"] is True
    assert sv["auth_passed"] is True
    assert r["risk_level"] == "LOW"


def test_apple_official_with_malicious_url_still_flagged():
    r = local_analyze(
        subject="Apple ID",
        plain_text="Hemen tıklayın http://evil.tk/verify",
        urls=["http://evil.tk/verify"],
        sender="Apple <no_reply@email.apple.com>",
        headers={"auth_results": "spf=pass dkim=pass", "reply_to": "", "return_path": "", "message_id": ""},
    )
    assert r["risk_score"] >= 20
    assert "http://evil.tk/verify" in r["suspicious_urls"]


def test_apple_fake_lookalike_domains_caught_without_headers():
    for fake_sender in (
        "Apple Support <security@apple-id-verify.com>",
        "iCloud Destek <alert@icloud-security-check.net>",
    ):
        r = local_analyze(
            subject="Verify your Apple ID",
            plain_text="Hesabınız askıya alınacak.",
            urls=[],
            sender=fake_sender,
            headers=None,
        )
        sv = r["sender_verification"]
        assert sv["status"] == "IMPERSONATION"
        assert sv["brand"] == "Apple"
        assert r["phishing_detected"] is True
        assert r["risk_score"] >= 30


def test_apple_spoofed_auth_fail_or_reply_to_mismatch():
    r_fail = local_analyze(
        subject="Apple ID",
        plain_text="Bilgi",
        urls=[],
        sender="Apple <appleid@id.apple.com>",
        headers={"auth_results": "spf=fail dkim=fail", "reply_to": "", "return_path": "", "message_id": ""},
    )
    assert r_fail["sender_verification"]["status"] == "SPOOFED"
    assert r_fail["risk_score"] >= 50
    assert r_fail["phishing_detected"] is True

    r_rt = local_analyze(
        subject="Apple ID",
        plain_text="Bilgi",
        urls=[],
        sender="Apple <no_reply@email.apple.com>",
        headers={"auth_results": "spf=pass", "reply_to": "steal@evil.tk", "return_path": "", "message_id": ""},
    )
    assert r_rt["sender_verification"]["status"] == "SPOOFED"
    assert r_rt["risk_score"] >= 50


def test_turkish_brands_verified_vs_impersonation():
    sv_ok = verify_sender(
        "Garanti BBVA <bilgilendirme@garantibbva.com.tr>",
        headers={"auth_results": "dkim=pass spf=pass"},
    )
    assert sv_ok["status"] == "VERIFIED_STRONG" and sv_ok["brand"] == "Garanti BBVA"

    sv_bad = verify_sender("e-Devlet Kapısı <ceza@edevlet-odeme.tk>", subject="e-Devlet borcunuz")
    assert sv_bad["status"] == "IMPERSONATION" and sv_bad["brand"] == "e-Devlet"


def test_verified_senders_custom_crud_and_cli(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path))

    add_verified_sender("okul", ["uni.edu.tr"], ["duyuru@uni.edu.tr"], label="Üniversitem", aliases=["rektörlük", "öğrenci işleri"])
    reg = load_verified_senders()
    assert "okul" in reg
    assert verify_sender("Öğrenci İşleri <duyuru@uni.edu.tr>")["status"] == "VERIFIED_DOMAIN"
    assert verify_sender("Öğrenci İşleri <sahte@gmail.com>")["status"] == "IMPERSONATION"

    assert remove_verified_sender("okul") is True
    assert "okul" not in load_verified_senders()
    reset_verified_senders()

    # CLI verified list/check/add/remove/reset
    assert cli_main(["verified", "list", "--json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert "apple" in listed

    assert cli_main([
        "verified", "check", "Apple <appleid@id.apple.com>",
        "--auth-results", "spf=pass dkim=pass", "--json",
    ]) == 0
    chk_ok = json.loads(capsys.readouterr().out)
    assert chk_ok["status"] == "VERIFIED_STRONG"

    assert cli_main(["verified", "check", "Apple <alert@apple-verify.tk>"]) == 1
    assert cli_main(["verified", "add", "sirketim", "--domain", "sirketim.com.tr", "--email", "ik@sirketim.com.tr"]) == 0
    assert cli_main(["verified", "remove", "sirketim"]) == 0
    assert cli_main(["verified", "reset"]) == 0


def test_kontrol_ver_checks_pass():
    r = run_kontrol(["ANALIZ"])
    assert r["fail"] == 0, r
    by_id = {b["id"]: b for b in r["bulgular"]}
    for cid in ("VER-01", "VER-02", "VER-03"):
        assert by_id[cid]["durum"] == "PASS", by_id[cid]
