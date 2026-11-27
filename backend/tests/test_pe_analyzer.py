"""PE / .EXE derin statik zararlı analizi, UI ayarları ve Defender entegrasyon testleri."""

from __future__ import annotations

import json
import os
import struct
import urllib.request
from pathlib import Path
from unittest.mock import patch

from app.desktop_ui import DesktopPanelServer
from app.services.file_scanner import scan_file_security
from app.services.local_ai import load_ai_settings, save_ai_settings
from app.services.pe_analyzer import (
    detect_pe_suspicious_apis,
    inspect_pe_bytes,
    shannon_entropy,
)


def _build_synthetic_pe(
    *,
    section_name: bytes = b".text",
    section_payload: bytes = b"\x90" * 512,
    section_chars: int = 0x60000020,  # CNT_CODE | MEM_EXECUTE | MEM_READ
    signed: bool = False,
    trailing_bytes: bytes = b"",
) -> bytes:
    """Test amaçlı en küçük geçerli PE32 başlığı üretir."""
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    pe_sig = b"PE\x00\x00"
    # COFF: Machine=x86, NumSections=1, SizeOfOptionalHeader=224, Characteristics=0x0102
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)

    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)  # PE32 magic
    struct.pack_into("<I", opt, 92, 16)    # NumberOfRvaAndSizes
    if signed:
        struct.pack_into("<II", opt, 128, 0x4000, 512)  # DataDirectory[4] Certificate Table

    sec_offset = 0x200
    sec_hdr = bytearray(40)
    sname = section_name[:8].ljust(8, b"\x00")
    sec_hdr[0:8] = sname
    struct.pack_into("<IIII", sec_hdr, 8, len(section_payload), 0x1000, len(section_payload), sec_offset)
    struct.pack_into("<I", sec_hdr, 36, section_chars)

    header = bytes(dos) + pe_sig + coff + bytes(opt) + bytes(sec_hdr)
    pad = b"\x00" * max(0, sec_offset - len(header))
    return header + pad + section_payload + trailing_bytes


def test_clean_pe_and_signed_certificate_table(tmp_path, monkeypatch):
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    unsigned_pe = _build_synthetic_pe(signed=False)
    signed_pe = _build_synthetic_pe(signed=True)

    info_u = inspect_pe_bytes(unsigned_pe)
    assert info_u["valid_pe"] is True
    assert info_u["has_authenticode"] is False
    assert info_u["packers"] == []
    assert info_u["high_entropy_sections"] == []

    info_s = inspect_pe_bytes(signed_pe)
    assert info_s["valid_pe"] is True
    assert info_s["has_authenticode"] is True

    exe_path = tmp_path / "clean_tool.exe"
    exe_path.write_bytes(signed_pe)
    rep = scan_file_security(exe_path)
    assert rep["pe_analysis"] is not None
    assert rep["pe_analysis"]["valid_pe"] is True
    assert rep["pe_analysis"]["has_authenticode"] is True
    assert rep["risk_level"] == "LOW"


def test_signed_msi_with_digicert_ca_urls_stays_low_when_valid(tmp_path, monkeypatch):
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    msi = tmp_path / "Cloudflare_WARP_Installer.msi"
    msi.write_bytes(
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        + b"http://ocsp.digicert.com\x00https://www.digicert.com/CPS\x00"
        + b"https://downloads.cloudflareclient.com/v1/download/windows/version/2026\x00"
    )
    motw = {
        "zone_id": 3,
        "host_url": "https://downloads.cloudflareclient.com/v1/download/windows/version/2026\x00",
        "referrer_url": "",
    }
    with patch("app.services.pe_analyzer.verify_authenticode_offline", return_value=True):
        rep = scan_file_security(msi, motw_override=motw)
        assert rep["risk_score"] <= 15
        assert rep["risk_level"] == "LOW"
        assert rep["pe_analysis"]["authenticode_valid"] is True


def test_pe_packed_high_entropy_and_rwx_detected(tmp_path, monkeypatch):
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    random_like = bytes((i * 197 + (i // 3) * 53) & 0xFF for i in range(8192))
    assert shannon_entropy(random_like) >= 7.5

    packed_pe = _build_synthetic_pe(
        section_name=b"UPX0",
        section_payload=random_like,
        section_chars=0xE0000020,  # RWX!
    )
    info = inspect_pe_bytes(packed_pe)
    assert "UPX0" in info["packers"]
    assert "UPX0" in info["high_entropy_sections"]
    assert "UPX0" in info["rwx_sections"]

    f = tmp_path / "packed.exe"
    f.write_bytes(packed_pe)
    rep = scan_file_security(f)
    assert rep["risk_score"] >= 45
    assert any("PE yapısal anomali" in r for r in rep["reasons"])


def test_pe_suspicious_api_injection_and_keylogger_and_ransomware(tmp_path, monkeypatch):
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    apis_blob = (
        b"kernel32.dll\x00VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
        b"user32.dll\x00SetWindowsHookExW\x00GetAsyncKeyState\x00"
        b"urlmon.dll\x00URLDownloadToFileW\x00WinExec\x00"
        b"vssadmin delete shadows /all /quiet\x00"
        b"https://discord.com/api/webhooks/123456789/secret\x00"
    )
    bad_pe = _build_synthetic_pe(section_payload=b"\x90" * 512, trailing_bytes=apis_blob)

    families = [f["family"] for f in detect_pe_suspicious_apis(bad_pe)]
    assert "process_injection" in families
    assert "keylogger_spyware" in families
    assert "dropper_download" in families
    assert "ransomware_destructive" in families

    f = tmp_path / "trojan.exe"
    f.write_bytes(bad_pe)
    rep = scan_file_security(f, motw_override={"zone_id": 3, "host_url": "https://cdn.example.com/trojan.exe", "referrer_url": ""})
    assert rep["risk_score"] >= 75
    assert rep["risk_level"] == "CRITICAL"


def test_unsigned_motw_strict_mode_blocks_exe(tmp_path, monkeypatch):
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    unsigned_pe = _build_synthetic_pe(signed=False)
    f = tmp_path / "setup.exe"
    f.write_bytes(unsigned_pe)
    motw = {"zone_id": 3, "host_url": "https://example.org/download", "referrer_url": ""}

    # Varsayilan mod: attach_risky (20) + motw (15) + unsigned_motw (15) = 50 HIGH
    rep_default = scan_file_security(f, motw_override=motw)
    assert rep_default["risk_score"] == 50
    assert rep_default["risk_level"] == "HIGH"

    # Siki EXE Kalkani acikken -> >= 75 CRITICAL (oto-karantina esigine ulasir)
    save_ai_settings({"exe_block_unsigned_downloads": True})
    rep_strict = scan_file_security(f, motw_override=motw)
    assert rep_strict["risk_score"] >= 75
    assert rep_strict["risk_level"] == "CRITICAL"
    assert any("Sıkı EXE Kalkanı" in r for r in rep_strict["reasons"])


def test_pe_custom_keyword_and_truncated_mz_safety(tmp_path, monkeypatch):
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    save_ai_settings({"custom_keywords": ["gizli-anahtar-kod"]})

    pe_kw = _build_synthetic_pe(trailing_bytes=b"\x00token=gizli-anahtar-kod\x00")
    f = tmp_path / "app.exe"
    f.write_bytes(pe_kw)
    rep = scan_file_security(f)
    assert "gizli-anahtar-kod" in (rep["pe_analysis"] or {}).get("keyword_hits", [])
    assert any("özel güvenlik kelimesi" in r for r in rep["reasons"])

    # Bozuk / kisa MZ basligi hata vermemeli
    bad = inspect_pe_bytes(b"MZ\x90\x00fake-pe")
    assert bad["valid_pe"] is False


def test_defender_optional_integration_mocked(tmp_path, monkeypatch):
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    save_ai_settings({"exe_defender_scan": True})
    f = tmp_path / "sample.exe"
    f.write_bytes(_build_synthetic_pe(signed=True))

    with patch(
        "app.services.pe_analyzer.scan_with_defender",
        return_value={"available": True, "checked": True, "infected": True, "threat_name": "Trojan:Win32/Test!ml", "returncode": 2},
    ):
        rep = scan_file_security(f)
        assert rep["risk_score"] >= 85
        assert rep["risk_level"] == "CRITICAL"
        assert any("Windows Defender" in r for r in rep["reasons"])


def test_desktop_ui_exe_settings_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    srv = DesktopPanelServer()
    srv.start()
    try:
        base = f"http://127.0.0.1:{srv.port}"
        req = urllib.request.Request(
            f"{base}/api/ai/settings",
            data=json.dumps({
                "exe_deep_scan": True,
                "exe_block_unsigned_downloads": True,
                "exe_defender_scan": False,
            }).encode("utf-8"),
            method="POST",
            headers={"X-ElfSec-Token": srv.token, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        assert data["ok"] is True
        assert data["ai"]["exe_deep_scan"] is True
        assert data["ai"]["exe_block_unsigned_downloads"] is True
        assert data["ai"]["exe_defender_scan"] is False
        assert load_ai_settings()["exe_block_unsigned_downloads"] is True
    finally:
        srv.stop()


def test_window_host_resize_and_drag_api(tmp_path, monkeypatch):
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    from app.window_host import NativeWindowController, _WindowJsApi

    class _FakeWin:
        def destroy(self):
            pass

    ctrl = NativeWindowController(_FakeWin())
    # Window headless -> hwnd=None, started=False guvenli donmeli
    res_bad = ctrl.begin_resize("se")
    assert res_bad["started"] is False and res_bad["native"] is True
    api = _WindowJsApi()
    api.controller = ctrl
    assert api.start_drag()["started"] is False
    assert api.start_resize("nw")["started"] is False

    srv = DesktopPanelServer()
    srv.window_controller = ctrl
    srv.start()
    try:
        base = f"http://127.0.0.1:{srv.port}"
        req = urllib.request.Request(
            f"{base}/api/window/resize-start",
            data=json.dumps({"edge": "se"}).encode("utf-8"),
            method="POST",
            headers={"X-ElfSec-Token": srv.token, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        assert data["ok"] is True
        assert data["native"] is True
        assert data["started"] is False
    finally:
        srv.stop()
