"""v1.6.0: Mağaza hazır tarayıcı uzantısı paketleyici ve native_host scan_file testleri."""

import json
import sys
import zipfile
from pathlib import Path

from app.kontrol import run_kontrol
from app.native_host import DEFAULT_EXTENSION_ID, derive_chrome_extension_id, handle_native_request

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import pytest  # noqa: E402

from pack_extensions import pack_all  # noqa: E402


def test_native_host_scan_file_malicious_clean_and_missing(tmp_path):
    evil = tmp_path / "fatura.pdf"
    evil.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00fake-pe")
    alert_log = tmp_path / "alerts.jsonl"

    rep_bad = handle_native_request({"action": "scan_file", "path": str(evil)}, alert_log=str(alert_log))
    assert rep_bad["ok"] is True
    assert rep_bad["source"] == "browser_download"
    assert rep_bad["risk_score"] >= 50
    assert rep_bad["risk_level"] in ("HIGH", "CRITICAL")
    assert alert_log.exists()

    good = tmp_path / "not.txt"
    good.write_text("temiz dosya", encoding="utf-8")
    rep_ok = handle_native_request({"action": "scan_file", "path": str(good)}, alert_log=str(alert_log))
    assert rep_ok["ok"] is True and rep_ok["risk_level"] == "LOW"

    rep_miss = handle_native_request({"action": "scan_file", "path": str(tmp_path / "yok.exe")})
    assert rep_miss["ok"] is False


def test_pack_extensions_generates_valid_store_and_dev_zips(tmp_path):
    repo_root = Path(__file__).resolve().parents[2]
    ext_dir = repo_root / "extension"
    zips = pack_all(ext_dir, tmp_path)

    assert set(zips) == {"chrome_edge", "firefox", "unpacked"}
    for zp in zips.values():
        assert zp.exists() and zp.stat().st_size > 1000

    # 1) Chrome Web Store & Edge Add-ons paketi
    with zipfile.ZipFile(zips["chrome_edge"]) as zf:
        names = set(zf.namelist())
        assert "manifest.json" in names
        assert "_locales/tr/messages.json" in names
        assert "_locales/en/messages.json" in names
        assert "options.html" in names
        assert "PRIVACY.md" in names
        assert "STORE_LISTING.md" not in names
        cmf = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert "key" not in cmf
        assert "browser_specific_settings" not in cmf
        assert cmf["background"] == {"service_worker": "background.js"}
        assert "downloads" in cmf["permissions"]

    # 2) Firefox AMO paketi
    with zipfile.ZipFile(zips["firefox"]) as zf:
        fmf = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert "key" not in fmf
        assert fmf["browser_specific_settings"]["gecko"]["id"] == "elfsec-guard@elfsec.local"
        assert fmf["background"]["scripts"] == ["fallback_analyzer.js", "background.js"]

    # 3) GitHub / Geliştirici Unpacked paketi
    with zipfile.ZipFile(zips["unpacked"]) as zf:
        umf = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert derive_chrome_extension_id(umf["key"]) == DEFAULT_EXTENSION_ID


def test_native_host_scan_file_rejects_unsafe_paths(tmp_path):
    # Ağ (UNC) yolu: SMB/NTLM sızıntısı riski
    assert handle_native_request({"action": "scan_file", "path": r"\\saldirgan\paylasim\x.exe"})["ok"] is False
    # Göreli yol
    assert handle_native_request({"action": "scan_file", "path": "goreli/dosya.exe"})["ok"] is False
    # Aygıt yolu (Windows)
    assert handle_native_request({"action": "scan_file", "path": r"\\.\PhysicalDrive0"})["ok"] is False
    # Aşırı uzun yol
    assert handle_native_request({"action": "scan_file", "path": "C:\\" + "a" * 5000})["ok"] is False


def test_chromium_manifest_rejects_invalid_extension_id():
    from app.native_host import build_chromium_manifest

    with pytest.raises(ValueError):
        build_chromium_manifest("x.cmd", extension_ids=["kötü-id"])
    with pytest.raises(ValueError):
        build_chromium_manifest("x.cmd", extension_ids=["https://evil.example/"])


def test_pack_rejects_secret_files_and_excludes_dev_junk(tmp_path):
    from pack_extensions import _iter_extension_files

    ext = tmp_path / "ext"
    (ext / "_locales" / "tr").mkdir(parents=True)
    (ext / "manifest.json").write_text("{}", encoding="utf-8")
    (ext / "background.js").write_text("// ok", encoding="utf-8")
    (ext / "WS").mkdir()
    (ext / "WS" / "notes.map").write_text("{}", encoding="utf-8")
    (ext / ".DS_Store").write_text("x", encoding="utf-8")
    (ext / "STORE_LISTING.md").write_text("x", encoding="utf-8")

    names = {p.name for p in _iter_extension_files(ext)}
    assert "manifest.json" in names and "background.js" in names
    assert not ({"notes.map", ".DS_Store", "STORE_LISTING.md"} & names)

    (ext / "private.pem").write_text("-----BEGIN PRIVATE KEY-----", encoding="utf-8")
    with pytest.raises(ValueError):
        _iter_extension_files(ext)


def test_pack_rejects_non_mv3_manifest(tmp_path):
    ext = tmp_path / "ext"
    ext.mkdir()
    (ext / "manifest.json").write_text(
        json.dumps({"manifest_version": 2, "name": "x", "version": "1.0", "description": "x"}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        pack_all(ext, tmp_path / "out")


def test_kontrol_win11_passes():
    r = run_kontrol(["WIN"])
    assert r["fail"] == 0, r
    by_id = {b["id"]: b for b in r["bulgular"]}
    assert by_id["WIN-11"]["durum"] == "PASS"
