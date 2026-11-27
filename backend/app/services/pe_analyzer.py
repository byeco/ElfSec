"""ElfSec Çevrimdışı PE / .EXE Derin Statik Zararlı Analiz Motoru.

Hiçbir çalıştırılabilir dosyayı çalıştırmadan yalnızca ham baytlar üzerinde çalışır:
- PE32 / PE32+ başlık & bölüm (section) ayrıştırma
- Shannon entropi & bilinen packer (UPX, ASPack, VMProtect, Themida vb.) tespiti
- W^X / RWX çalıştırılabilir+yazılabilir bölüm tespiti
- Authenticode dijital imza varlığı kontrolü (DataDirectory[4] Certificate Table)
- Zararlı Win32 API davranış aileleri (Process Injection, Keylogger, AMSI/ETW Evasion, Ransomware, Dropper)
- Gömülü LOLBin, C2 webhook (Discord/Telegram) ve özel güvenlik kelime eşleşmesi
- İsteğe bağlı yerel Windows Defender CLI (MpCmdRun.exe) doğrulaması
"""

from __future__ import annotations

import math
import os
import re
import struct
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.services.ai_analyzer import _W, _check_url
from app.services.local_ai import _normalize_tr, load_ai_settings
from app.services.sanitizer import extract_urls

MAX_PE_READ_BYTES = 2_097_152
MAX_STRING_SAMPLE_BYTES = 1_048_576

_PACKER_SECTION_NAMES = (
    "upx0",
    "upx1",
    "upx2",
    ".aspack",
    ".adata",
    ".vmp0",
    ".vmp1",
    ".vmp2",
    ".themida",
    ".enigma",
    ".mpress",
    ".petite",
    "mew",
    ".nsp0",
    ".pecompact",
    ".obsidium",
)

_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SCN_MEM_WRITE = 0x80000000
_IMAGE_SCN_RWX = _IMAGE_SCN_MEM_EXECUTE | _IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_WRITE

_INJECTION_APIS = (
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"CreateRemoteThread",
    b"NtUnmapViewOfSection",
    b"ZwUnmapViewOfSection",
    b"QueueUserAPC",
    b"SetThreadContext",
    b"RtlCreateUserThread",
)

_KEYLOGGER_APIS = (
    b"SetWindowsHookExA",
    b"SetWindowsHookExW",
    b"GetAsyncKeyState",
    b"GetClipboardData",
    b"GetForegroundWindow",
    b"BitBlt",
)

_EVASION_APIS = (b"AmsiScanBuffer", b"EtwEventWrite")

_DROPPER_DOWNLOAD_APIS = (b"URLDownloadToFileA", b"URLDownloadToFileW")
_DROPPER_EXEC_APIS = (
    b"ShellExecuteA",
    b"ShellExecuteW",
    b"WinExec",
    b"CreateProcessA",
    b"CreateProcessW",
)

_C2_WEBHOOK_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/", "Gömülü Discord Webhook sızıntı hedefi"),
    (r"https?://api\.telegram\.org/bot[0-9]{6,}:", "Gömülü Telegram Bot C2 hedefi"),
)

_CA_PKI_DOMAINS = (
    "digicert.com",
    "verisign.com",
    "sectigo.com",
    "globalsign.com",
    "comodoca.com",
    "entrust.net",
    "symantec.com",
    "symcb.com",
    "symcd.com",
    "microsoft.com",
    "thawte.com",
    "usertrust.com",
    "pki.goog",
    "letsencrypt.org",
    "cloudflare.com",
)


def _is_ca_pki_url(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower().strip(".")
    except Exception:
        return False
    if not host:
        return False
    if host.startswith(("ocsp.", "crl.", "crl3.", "crl4.", "cacerts.", "timestamp.", "ts.", "aia.")):
        return True
    return any(host == d or host.endswith("." + d) for d in _CA_PKI_DOMAINS)


def verify_authenticode_offline(path: Path) -> bool:
    """Windows WinVerifyTrust ile tamamen çevrimdışı Authenticode imza geçerliliğini doğrular."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p),
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p),
            ]

        # WINTRUST_ACTION_GENERIC_VERIFY_V2 {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
        action_guid = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = str(path)

        WTD_UI_NONE = 2
        WTD_REVOKE_NONE = 0
        WTD_CHOICE_FILE = 1
        WTD_STATEACTION_VERIFY = 1
        WTD_STATEACTION_CLOSE = 2
        WTD_REVOCATION_CHECK_NONE = 0x00000010
        WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00000004

        wtd = WINTRUST_DATA()
        wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        wtd.dwUIChoice = WTD_UI_NONE
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE
        wtd.dwUnionChoice = WTD_CHOICE_FILE
        wtd.pFile = ctypes.pointer(file_info)
        wtd.dwStateAction = WTD_STATEACTION_VERIFY
        wtd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL

        wintrust = ctypes.windll.wintrust
        wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]
        wintrust.WinVerifyTrust.restype = ctypes.c_long

        status = int(wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wtd)))
        wtd.dwStateAction = WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wtd))
        return status == 0
    except Exception:
        return False


def shannon_entropy(data: bytes) -> float:
    """Bayt dizisinin Shannon entropisini hesaplar (0.0 - 8.0)."""
    total = len(data)
    if total == 0:
        return 0.0
    counts = Counter(data)
    ent = 0.0
    for cnt in counts.values():
        p = cnt / total
        ent -= p * math.log2(p)
    return round(ent, 3)


def inspect_pe_bytes(raw: bytes) -> dict[str, Any]:
    """PE32/PE32+ başlıklarını, bölümlerini, entropisini ve imzasını inceler."""
    empty: dict[str, Any] = {
        "valid_pe": False,
        "sections": [],
        "packers": [],
        "high_entropy_sections": [],
        "rwx_sections": [],
        "has_authenticode": False,
        "is_dll": False,
        "max_entropy": 0.0,
    }
    if len(raw) < 64 or not raw.startswith(b"MZ"):
        return empty

    try:
        (e_lfanew,) = struct.unpack_from("<I", raw, 0x3C)
    except struct.error:
        return empty

    if e_lfanew < 64 or e_lfanew + 24 > len(raw):
        return empty
    if raw[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return empty

    coff_off = e_lfanew + 4
    try:
        _machine, num_sections, _ts, _sym_off, _num_syms, opt_size, characteristics = struct.unpack_from(
            "<HHIIIHH", raw, coff_off
        )
    except struct.error:
        return empty

    if num_sections == 0 or num_sections > 64 or opt_size < 24:
        return empty

    opt_off = coff_off + 20
    sec_table_off = opt_off + opt_size
    if sec_table_off + num_sections * 40 > len(raw):
        # Kısmen kırpılmış başlıkta mevcut okunabilen bölüm sayısını kullan.
        max_fit = max(0, (len(raw) - sec_table_off) // 40)
        if max_fit == 0:
            return empty
        num_sections = max_fit

    try:
        (magic,) = struct.unpack_from("<H", raw, opt_off)
    except struct.error:
        return empty

    is_dll = bool(characteristics & 0x2000)
    has_authenticode = False
    num_rva_and_sizes = 0
    cert_dir_rel = None

    if magic == 0x10B and opt_size >= 136 and opt_off + 136 <= len(raw):
        # PE32 Optional Header: NumberOfRvaAndSizes @ +92, DataDirectory[4] (Certificate) @ +128
        (num_rva_and_sizes,) = struct.unpack_from("<I", raw, opt_off + 92)
        cert_dir_rel = 128
    elif magic == 0x20B and opt_size >= 152 and opt_off + 152 <= len(raw):
        # PE32+ Optional Header: NumberOfRvaAndSizes @ +108, DataDirectory[4] (Certificate) @ +144
        (num_rva_and_sizes,) = struct.unpack_from("<I", raw, opt_off + 108)
        cert_dir_rel = 144

    if cert_dir_rel is not None and num_rva_and_sizes > 4:
        cert_off, cert_sz = struct.unpack_from("<II", raw, opt_off + cert_dir_rel)
        if cert_off > 0 and cert_sz >= 8:
            has_authenticode = True

    sections: list[dict[str, Any]] = []
    packers: list[str] = []
    high_entropy_sections: list[str] = []
    rwx_sections: list[str] = []
    max_entropy = 0.0

    for idx in range(num_sections):
        sh_off = sec_table_off + idx * 40
        if sh_off + 40 > len(raw):
            break
        raw_name = raw[sh_off : sh_off + 8]
        sec_name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace").strip() or f"sec_{idx}"
        virtual_size, _va, raw_size, raw_offset = struct.unpack_from("<IIII", raw, sh_off + 8)
        (sec_chars,) = struct.unpack_from("<I", raw, sh_off + 36)

        ent = 0.0
        if raw_size > 0 and raw_offset < len(raw):
            slice_end = min(len(raw), raw_offset + raw_size)
            sec_bytes = raw[raw_offset:slice_end]
            if sec_bytes:
                ent = shannon_entropy(sec_bytes)
                if ent > max_entropy:
                    max_entropy = ent

        sections.append({
            "name": sec_name,
            "virtual_size": virtual_size,
            "raw_size": raw_size,
            "entropy": ent,
            "executable": bool(sec_chars & _IMAGE_SCN_MEM_EXECUTE),
            "writable": bool(sec_chars & _IMAGE_SCN_MEM_WRITE),
        })

        sec_low = sec_name.lower()
        if any(sec_low == p or sec_low.startswith(p) for p in _PACKER_SECTION_NAMES):
            if sec_name not in packers:
                packers.append(sec_name)

        if raw_size >= 4096 and ent >= 7.25:
            is_exec_or_unknown = bool(sec_chars & _IMAGE_SCN_MEM_EXECUTE) or sec_low not in (".rsrc", ".reloc", ".pdata")
            if is_exec_or_unknown and sec_name not in high_entropy_sections:
                high_entropy_sections.append(sec_name)

        if (sec_chars & _IMAGE_SCN_RWX) == _IMAGE_SCN_RWX and sec_name not in rwx_sections:
            rwx_sections.append(sec_name)

    return {
        "valid_pe": True,
        "sections": sections,
        "packers": packers,
        "high_entropy_sections": high_entropy_sections,
        "rwx_sections": rwx_sections,
        "has_authenticode": has_authenticode,
        "is_dll": is_dll,
        "max_entropy": max_entropy,
    }


def extract_pe_strings(raw: bytes, max_chars: int = 80_000) -> str:
    """PE ikilisinden yazdırılabilir ASCII ve UTF-16LE dizeleri çıkarır."""
    sample = raw[:MAX_STRING_SAMPLE_BYTES]
    chunks: list[str] = []
    total = 0

    for pat, enc in ((rb"[\x20-\x7e]{6,}", "ascii"), (rb"(?:[\x20-\x7e]\x00){6,}", "utf-16-le")):
        for m in re.finditer(pat, sample):
            s = m.group(0).decode(enc, errors="ignore")
            if not s:
                continue
            chunks.append(s)
            total += len(s) + 1
            if total >= max_chars:
                return "\n".join(chunks)[:max_chars]

    return "\n".join(chunks)[:max_chars]


def detect_pe_suspicious_apis(raw: bytes, extracted_text: str | None = None) -> list[dict[str, Any]]:
    """PE ikilisinde zararlı Win32 API davranış ailelerini arar."""
    findings: list[dict[str, Any]] = []

    inj_hits = [api.decode("ascii") for api in _INJECTION_APIS if api in raw]
    if len(inj_hits) >= 2:
        findings.append({
            "family": "process_injection",
            "label": "Süreç Enjeksiyonu (Process Injection)",
            "apis": inj_hits[:6],
            "score": 35,
        })

    key_trigger = (b"SetWindowsHookExA" in raw or b"SetWindowsHookExW" in raw or b"GetAsyncKeyState" in raw)
    key_hits = [api.decode("ascii") for api in _KEYLOGGER_APIS if api in raw]
    if key_trigger and len(key_hits) >= 2:
        findings.append({
            "family": "keylogger_spyware",
            "label": "Tuş Kaydedici / Ekran İzleme API",
            "apis": key_hits[:6],
            "score": 25,
        })

    eva_hits = [api.decode("ascii") for api in _EVASION_APIS if api in raw]
    if eva_hits and b"VirtualProtect" in raw:
        findings.append({
            "family": "evasion_tamper",
            "label": "Antivirüs / AMSI / ETW Atlatma API",
            "apis": eva_hits + ["VirtualProtect"],
            "score": 25,
        })

    txt = extracted_text if extracted_text is not None else extract_pe_strings(raw)
    txt_low = txt.lower()
    if (
        ("vssadmin" in txt_low and "delete shadows" in txt_low)
        or ("wbadmin" in txt_low and "delete catalog" in txt_low)
        or ("bcdedit" in txt_low and "recoveryenabled" in txt_low)
    ):
        findings.append({
            "family": "ransomware_destructive",
            "label": "Gölge Kopya Silme / Fidye Yazılımı Davranışı",
            "apis": ["shadow_copy_delete"],
            "score": 35,
        })

    dl_hits = [api.decode("ascii") for api in _DROPPER_DOWNLOAD_APIS if api in raw]
    exec_hits = [api.decode("ascii") for api in _DROPPER_EXEC_APIS if api in raw]
    if dl_hits and exec_hits:
        findings.append({
            "family": "dropper_download",
            "label": "İndirici / Dropper API",
            "apis": dl_hits + exec_hits[:3],
            "score": 25,
        })

    return findings


def find_defender_cli() -> Path | None:
    """Yerel Windows Defender CLI (MpCmdRun.exe) yolunu döndürür."""
    if os.name != "nt":
        return None
    prog_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    platform_dir = prog_data / "Microsoft" / "Windows Defender" / "Platform"
    if platform_dir.exists():
        try:
            cands = sorted(platform_dir.glob("*/MpCmdRun.exe"), reverse=True)
            for c in cands:
                if c.is_file():
                    return c
        except OSError:
            pass
    prog_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    std = prog_files / "Windows Defender" / "MpCmdRun.exe"
    return std if std.is_file() else None


def scan_with_defender(path: Path, timeout: int = 15) -> dict[str, Any]:
    """İsteğe bağlı olarak yerel MpCmdRun.exe ile çevrimdışı imza taraması çalıştırır."""
    exe = find_defender_cli()
    if exe is None:
        return {"available": False, "checked": False, "infected": False, "threat_name": "", "returncode": None}

    flags = 0x08000000 if os.name == "nt" else 0
    try:
        proc = subprocess.run(
            [str(exe), "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=flags,
        )
    except Exception as exc:
        return {
            "available": True,
            "checked": False,
            "infected": False,
            "threat_name": "",
            "returncode": None,
            "error": str(exc),
        }

    out = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    threat_name = ""
    m = re.search(r"Threat\s*:\s*(.+)", out, re.IGNORECASE)
    if m:
        threat_name = m.group(1).strip()[:160]
    elif proc.returncode == 2:
        threat_name = "Microsoft Defender Threat"

    return {
        "available": True,
        "checked": True,
        "infected": proc.returncode == 2,
        "threat_name": threat_name,
        "returncode": int(proc.returncode),
    }


def analyze_pe_file(
    path: Path,
    rules: dict,
    motw: dict | None = None,
    ai_settings: dict | None = None,
    run_defender: bool | None = None,
) -> dict[str, Any]:
    """Tek bir PE / .exe dosyasını statik ve isteğe bağlı Defender katmanlarıyla analiz eder."""
    cfg = ai_settings if ai_settings is not None else load_ai_settings()
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_PE_READ_BYTES)
    except OSError:
        raw = b""

    pe_info = inspect_pe_bytes(raw)
    extracted = extract_pe_strings(raw) if raw else ""
    api_families = detect_pe_suspicious_apis(raw, extracted_text=extracted) if raw else []

    score_delta = 0
    reasons: list[str] = []
    suspicious_urls: list[str] = []
    embedded_indicators: list[str] = []
    keyword_hits: list[str] = []

    if pe_info["packers"] or pe_info["high_entropy_sections"] or pe_info["rwx_sections"]:
        w_pack = _W(rules, "pe_packed_entropy", 25)
        if w_pack:
            score_delta += w_pack
            parts: list[str] = []
            if pe_info["packers"]:
                parts.append(f"paketleyici/packer bölümü ({', '.join(pe_info['packers'])})")
            if pe_info["high_entropy_sections"]:
                parts.append(
                    f"yüksek entropili şifreli bölüm ({', '.join(pe_info['high_entropy_sections'])}, max {pe_info['max_entropy']})"
                )
            if pe_info["rwx_sections"]:
                parts.append(f"RWX yazılabilir+çalıştırılabilir bölüm ({', '.join(pe_info['rwx_sections'])})")
            reasons.append("PE yapısal anomali: " + "; ".join(parts) + ".")

    if api_families:
        w_api = _W(rules, "pe_suspicious_api", 35)
        if w_api:
            labels = [fam["label"] for fam in api_families]
            bonus = min(20, max(0, (len(api_families) - 1) * 15))
            score_delta += w_api + bonus
            reasons.append("Şüpheli Win32 API davranışları: " + ", ".join(labels) + ".")

    # Gömülü LOLBin / C2 webhook / şüpheli URL kontrolleri
    if extracted:
        try:
            from app.services.file_scanner import LOLBIN_PATTERNS
        except Exception:
            LOLBIN_PATTERNS = ()

        for pat, desc in LOLBIN_PATTERNS:
            if re.search(pat, extracted, re.IGNORECASE):
                embedded_indicators.append(desc)
                w_lol = _W(rules, "script_lolbin", 35)
                if w_lol:
                    score_delta += w_lol
                    reasons.append(f"PE içinde gömülü komut kalıbı: {desc}.")
                break

        for pat, desc in _C2_WEBHOOK_PATTERNS:
            if re.search(pat, extracted, re.IGNORECASE):
                embedded_indicators.append(desc)
                score_delta += 35
                reasons.append(f"PE ikilisinde şüpheli dış aktarım adresi: {desc}.")
                break

        url_score_total = 0
        for raw_u in extract_urls(extracted)[:25]:
            u = re.sub(r"[^A-Za-z0-9:/?&=._%-]+$", "", str(raw_u or "").replace("\x00", "").strip())
            if not u or _is_ca_pki_url(u):
                continue
            pts, why = _check_url(u, rules)
            if pts and u not in suspicious_urls and url_score_total < 25:
                add_pts = min(pts, 25 - url_score_total)
                score_delta += add_pts
                url_score_total += add_pts
                suspicious_urls.append(u)
                if why:
                    reasons.append(why)

        # Özel güvenlik kelimeleri (.exe içine gömülü özel veri/kelime)
        low, folded = _normalize_tr(extracted)
        for kw in cfg.get("custom_keywords") or []:
            kw_low, kw_fold = _normalize_tr(str(kw))
            if kw_low and (kw_low in low or kw_fold in folded):
                keyword_hits.append(str(kw))
        if keyword_hits:
            score_delta += min(45, 25 + 10 * (len(keyword_hits) - 1))
            reasons.append(f"PE içinde özel güvenlik kelimesi tespit edildi: {', '.join(keyword_hits[:5])}.")

    authenticode_valid = verify_authenticode_offline(path) if path.is_file() else False
    has_auth = bool(pe_info["has_authenticode"] or authenticode_valid)

    zone_id = motw.get("zone_id") if isinstance(motw, dict) else None
    if pe_info["valid_pe"] and not has_auth and zone_id in (3, 4):
        w_uns = _W(rules, "pe_unsigned_motw", 15)
        if w_uns:
            score_delta += w_uns
            reasons.append("İnternetten indirilmiş dijital imzasız PE/EXE dosyası.")
        if cfg.get("exe_block_unsigned_downloads"):
            score_delta += 40
            reasons.append("Sıkı EXE Kalkanı: İnternetten inen dijital imzasız çalıştırılabilir engellendi.")

    use_def = bool(cfg.get("exe_defender_scan", False)) if run_defender is None else bool(run_defender)
    defender_res: dict[str, Any] = {"available": False, "checked": False, "infected": False, "threat_name": ""}
    if use_def:
        try:
            if path.stat().st_size >= 64:
                defender_res = scan_with_defender(path)
                if defender_res.get("infected"):
                    w_def = _W(rules, "pe_defender_hit", 85)
                    if w_def:
                        score_delta += w_def
                        reasons.append(
                            f"Windows Defender zararlı tespit etti: {defender_res.get('threat_name') or 'Bilinmeyen tehdit'}."
                        )
        except OSError:
            pass

    return {
        "valid_pe": pe_info["valid_pe"],
        "is_dll": pe_info["is_dll"],
        "has_authenticode": has_auth,
        "authenticode_valid": authenticode_valid,
        "max_entropy": pe_info["max_entropy"],
        "packers": pe_info["packers"],
        "high_entropy_sections": pe_info["high_entropy_sections"],
        "rwx_sections": pe_info["rwx_sections"],
        "api_families": api_families,
        "embedded_indicators": embedded_indicators,
        "keyword_hits": keyword_hits,
        "defender": defender_res,
        "score_delta": score_delta,
        "reasons": reasons,
        "suspicious_urls": suspicious_urls,
    }
