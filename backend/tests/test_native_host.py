"""v1.4.0: Browser Native Messaging Host, MV3 eklenti ID ve masaüstü mail önbelleği testleri."""

import io
import json
from pathlib import Path

import pytest

from app.cli import main as cli_main
from app.kontrol import run_kontrol
from app.native_host import (
    DEFAULT_EXTENSION_ID,
    DEV_UNPACKED_PUBLIC_KEY,
    NATIVE_HOST_NAME,
    build_chromium_manifest,
    build_firefox_manifest,
    derive_chrome_extension_id,
    handle_native_request,
    read_native_message,
    run_native_host,
    write_native_host_files,
    write_native_message,
)
from app.watchers.file_watcher import default_mail_app_dirs, default_watch_dirs
from app.win_plugin import build_browser_registry_entries, browser_status


def test_native_framing_roundtrip_and_limits():
    buf = io.BytesIO()
    write_native_message(buf, {"action": "ping", "tr": "ğüşöçı"})
    buf.seek(0)
    assert read_native_message(buf) == {"action": "ping", "tr": "ğüşöçı"}
    assert read_native_message(buf) is None  # EOF

    bad_hdr = io.BytesIO(b"\xff\xff\xff\x7f")
    with pytest.raises(ValueError):
        read_native_message(bad_hdr)


def test_handle_native_request_ping_email_and_url(tmp_path):
    pong = handle_native_request({"action": "ping"})
    assert pong["ok"] is True and pong["mode"] == "native-host"

    alert_log = tmp_path / "webmail_alerts.jsonl"
    phish = handle_native_request(
        {
            "action": "analyze_email",
            "provider": "gmail",
            "subject": "Hesabiniz kapanacak!",
            "sender": "Garanti Destek <destek@gmail.com>",
            "body": "<p>Hemen tikla http://evil.tk/verify sifrenizi gonderin</p>",
            "urls": ["http://evil.tk/verify"],
        },
        alert_log=str(alert_log),
    )
    assert phish["ok"] is True
    assert phish["source"] == "browser_webmail"
    assert phish["provider"] == "gmail"
    assert phish["risk_score"] >= 75
    assert phish["risk_level"] == "CRITICAL"
    assert alert_log.exists()

    clean = handle_native_request(
        {
            "action": "analyze_email",
            "provider": "outlook",
            "subject": "Toplanti notlari",
            "sender": "ekip@sirket.com",
            "body": "Yarin saat 10:00'da goruselim.",
        },
        alert_log=str(alert_log),
    )
    assert clean["ok"] is True and clean["risk_level"] == "LOW"

    clip = handle_native_request({"action": "analyze_url", "text": "powershell -w hidden -enc JAB4"})
    assert clip["ok"] is True and clip["clickfix_detected"] is True

    unk = handle_native_request({"action": "bilinmeyen"})
    assert unk["ok"] is False


def test_run_native_host_stdio_loop():
    inp = io.BytesIO()
    write_native_message(inp, {"action": "ping"})
    write_native_message(inp, {"action": "analyze_text", "text": "http://evil.tk/login"})
    inp.seek(0)
    out = io.BytesIO()

    assert run_native_host(stdin=inp, stdout=out) == 0
    out.seek(0)
    r1 = read_native_message(out)
    r2 = read_native_message(out)
    assert r1 and r1["ok"] is True
    assert r2 and r2["ok"] is True and r2["risk_score"] >= 20
    assert read_native_message(out) is None


def test_extension_manifest_key_matches_default_id():
    repo_root = Path(__file__).resolve().parents[2]
    mf = json.loads((repo_root / "extension" / "manifest.json").read_text(encoding="utf-8"))
    assert "key" not in mf
    assert mf["default_locale"] == "en"
    assert derive_chrome_extension_id(DEV_UNPACKED_PUBLIC_KEY) == DEFAULT_EXTENSION_ID
    matches = [m for cs in mf["content_scripts"] for m in cs["matches"]]
    assert "https://mail.google.com/*" in matches
    assert "https://outlook.live.com/*" in matches
    assert "https://outlook.office.com/*" in matches


def test_native_host_files_and_browser_registry(tmp_path, capsys):
    files = write_native_host_files(tmp_path, r"C:\Program Files\ElfSec\elfsec.exe")
    cm = json.loads(Path(files["chromium_manifest"]).read_text(encoding="utf-8"))
    fm = json.loads(Path(files["firefox_manifest"]).read_text(encoding="utf-8"))
    assert cm["name"] == NATIVE_HOST_NAME
    assert f"chrome-extension://{DEFAULT_EXTENSION_ID}/" in cm["allowed_origins"]
    assert fm["name"] == NATIVE_HOST_NAME
    assert build_chromium_manifest("x.cmd")["type"] == "stdio"
    assert build_firefox_manifest("x.cmd")["type"] == "stdio"

    hklm = build_browser_registry_entries(files["chromium_manifest"], files["firefox_manifest"], user_only=False)
    hkcu = build_browser_registry_entries(files["chromium_manifest"], files["firefox_manifest"], user_only=True)
    assert len(hklm) == 4 and all(e["hive"] == "HKLM" for e in hklm)
    assert len(hkcu) == 4 and all(e["hive"] == "HKCU" for e in hkcu)

    assert isinstance(browser_status(), dict)
    assert cli_main(["browser", "status", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert set(out) == {"chrome", "edge", "brave", "firefox"}


def test_mail_app_dirs_and_kontrol_win():
    assert isinstance(default_mail_app_dirs(all_users=False), list)
    assert isinstance(default_watch_dirs(all_users=False, include_mail_apps=True), list)

    r = run_kontrol(["WIN"])
    assert r["fail"] == 0, r
    assert r["warn"] == 0, r
    by_id = {b["id"]: b for b in r["bulgular"]}
    assert by_id["WIN-09"]["durum"] == "PASS"
    assert by_id["WIN-10"]["durum"] == "PASS"


def test_discover_extension_ids_preserves_existing_manifest(tmp_path):
    from app.native_host import discover_installed_extension_ids, write_native_host_files

    custom_id = "miockdlgjjkjkmphpicmjahakecoemoj"
    files = write_native_host_files(tmp_path, r"C:\Program Files\ElfSec\elfsec.exe", extension_ids=[custom_id])
    ids = discover_installed_extension_ids(existing_manifest=Path(files["chromium_manifest"]))
    assert DEFAULT_EXTENSION_ID in ids
    assert custom_id in ids


def test_native_host_scan_file_auto_quarantine_and_url_alert_logging(monkeypatch, tmp_path):
    from app import settings_store
    from app.services.local_ai import save_ai_settings

    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "cfg"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "pd"))
    monkeypatch.setenv("ELFSEC_NO_TOAST", "1")
    settings_store.set_explicit(None)

    try:
        alert_log = tmp_path / "cfg" / "guard_alerts.jsonl"
        dl = tmp_path / "Downloads"
        dl.mkdir()
        evil_ps1 = dl / "evil.pdf.exe"
        evil_ps1.write_bytes(b"MZ")

        url_rep = handle_native_request(
            {"action": "analyze_url", "text": "powershell -w hidden -enc JAB4"},
            alert_log=str(alert_log),
        )
        assert url_rep["ok"] is True and url_rep["risk_score"] >= 40

        # Native host scan_file hiçbir koşulda (auto_protect açık olsa bile) dosyayı karantinaya taşımamalı
        save_ai_settings({"auto_protect": True, "auto_quarantine_level": "CRITICAL"})
        bad_script = dl / "payload.ps1"
        bad_script.write_text("powershell -w hidden -enc JAB4\nAdd-MpPreference -ExclusionPath C:\\", encoding="utf-8")
        rep = handle_native_request(
            {"action": "scan_file", "path": str(bad_script), "auto_protect": True},
            alert_log=str(alert_log),
        )
        assert rep["ok"] is True
        assert rep["risk_level"] == "CRITICAL"
        assert rep.get("auto_protected") is False
        assert bad_script.exists()
        assert alert_log.exists() and "payload.ps1" in alert_log.read_text(encoding="utf-8")
    finally:
        settings_store.set_explicit(None)


def test_desktop_ui_collect_alerts_and_browser_test_endpoint(monkeypatch, tmp_path):
    from app import settings_store
    from app.desktop_ui import DesktopPanelServer, _collect_alerts

    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "cfg"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "pd"))
    settings_store.set_explicit(None)

    try:
        user_log = tmp_path / "cfg" / "guard_alerts.jsonl"
        user_log.parent.mkdir(parents=True, exist_ok=True)
        user_log.write_text(json.dumps({"subject": "Tarayıcı Test", "risk_score": 80, "risk_level": "HIGH"}) + "\n", encoding="utf-8")
        alerts = _collect_alerts()
        assert any(a.get("subject") == "Tarayıcı Test" for a in alerts)

        import urllib.request

        srv = DesktopPanelServer()
        srv.start()
        try:
            base = f"http://127.0.0.1:{srv.port}"
            req = urllib.request.Request(
                f"{base}/api/browser/test",
                data=b"{}",
                method="POST",
                headers={"X-ElfSec-Token": srv.token, "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            assert data["ok"] is True
            assert "self_test" in data and "bridge" in data
        finally:
            srv.stop()
    finally:
        settings_store.set_explicit(None)
