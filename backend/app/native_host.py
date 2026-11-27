"""Chrome / Edge / Brave / Firefox Native Messaging Host (stdio JSON-framing).

Tarayıcıdaki MV3 eklentisi açılan webmail (Gmail, Outlook Web, Yahoo, Yandex,
iCloud, Proton Mail) içeriğini bu modüle `stdin`/`stdout` üzerinden 4-bayt
little-endian uzunluk + UTF-8 JSON biçiminde gönderir; ElfSec yerel motoru
analizi yapıp sonucu geri döndürür (internet/API anahtarı yok).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from app.__version__ import __version__
from app.services.ai_analyzer import ENGINE, local_analyze
from app.services.sanitizer import sanitize_email
from app.settings_store import default_user_config_path, machine_data_dir
from app.urlintel import maybe_expand
from app.watchers.clipboard_guard import analyze_clipboard_text

NATIVE_HOST_NAME = "com.elfsec.guard"
DEFAULT_EXTENSION_ID = "jkmbfppdffpiodlmikbdfdihdkejcfjj"
DEV_UNPACKED_PUBLIC_KEY = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlv1uyGqqLdCcFb4CZHbjYl/QVBSr9QhA"
    "18qMIJK5KDM1F404eFLS2WrBcZpxwFxQudsO1/OSLpO1qVl9ypdAAv71PVhnboM4WE01FjjDY5a"
    "mtZg94d3D2FLfRXtBT9DM/VflqALRJCFT4EYUmzdGFrx3Qwfxy+M6sK77dfiIGU/vtPRS5+Qb8a"
    "9e/I+FAU2ys/oqpPQVRi3tz1S2wFHVEiiMQ1Ta23ehl88ysTWT9c7bzH2Gn/iKsVmZM2Qrj7dS9"
    "rrtMqA0GDoDnpqmlZGzaFiU1jywbxBzAR3fWT7tGLZAoBmd6MLxBiVslUxxmEatZAMc8yAJPXhJ"
    "unbHZdTgEQIDAQAB"
)
FIREFOX_EXTENSION_ID = "elfsec-guard@elfsec.local"
MAX_NATIVE_MSG_BYTES = 1_048_576  # 1 MB
MAX_SCAN_PATH_CHARS = 4096
MAX_ALERT_LOG_BYTES = 2 * 1024 * 1024  # 2 MB — sonra guard_alerts.jsonl.1'e döndürülür
CHROMIUM_EXT_ID_RE = re.compile(r"^[a-p]{32}$")


def derive_chrome_extension_id(spki_b64: str) -> str:
    """Base64 SPKI açık anahtarından 32 karakterli Chromium eklenti ID'si türet."""
    der = base64.b64decode(spki_b64.strip())
    digest = hashlib.sha256(der).digest()[:16]
    chars: list[str] = []
    for b in digest:
        chars.append(chr(ord("a") + (b >> 4)))
        chars.append(chr(ord("a") + (b & 0x0F)))
    return "".join(chars)


def read_native_message(stream: BinaryIO) -> dict | None:
    """Native Messaging çerçevesini oku (<I uzunluk + JSON). EOF'ta None döner."""
    header = stream.read(4)
    if not header:
        return None
    if len(header) < 4:
        raise ValueError("Eksik Native Messaging uzunluk başlığı.")
    (length,) = struct.unpack("<I", header)
    if length == 0 or length > MAX_NATIVE_MSG_BYTES:
        raise ValueError(f"Geçersiz Native Messaging boyutu: {length} bayt.")
    body = b""
    while len(body) < length:
        chunk = stream.read(length - len(body))
        if not chunk:
            raise ValueError("Native Messaging gövdesi beklenmeden kesildi.")
        body += chunk
    obj = json.loads(body.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("Native Messaging yükü JSON nesnesi olmalı.")
    return obj


def write_native_message(stream: BinaryIO, payload: dict) -> None:
    """Yanıtı 4-bayt little-endian uzunluk + UTF-8 JSON olarak yaz."""
    raw = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    if len(raw) > MAX_NATIVE_MSG_BYTES:
        raw = json.dumps(
            {"ok": False, "error": "Yanıt boyutu sınırı aşıldı."},
            ensure_ascii=False,
        ).encode("utf-8")
    stream.write(struct.pack("<I", len(raw)) + raw)
    stream.flush()


def _default_alert_log_path() -> Path:
    m_dir = machine_data_dir()
    try:
        m_dir.mkdir(parents=True, exist_ok=True)
        probe = m_dir / ".nm_probe"
        probe.write_text("1", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return m_dir / "guard_alerts.jsonl"
    except OSError:
        u_dir = default_user_config_path().parent
        u_dir.mkdir(parents=True, exist_ok=True)
        return u_dir / "guard_alerts.jsonl"


def _append_webmail_alert(report: dict, alert_log: str = "") -> None:
    if report.get("risk_level") not in ("HIGH", "CRITICAL"):
        return
    try:
        from app.privacy import load_privacy_settings, sanitize_alert_for_storage

        lp = Path(alert_log) if alert_log else _default_alert_log_path()
        lp.parent.mkdir(parents=True, exist_ok=True)
        # Sonsuz büyümeyi engelle: eşik aşılınca tek yedek dosyaya döndür.
        try:
            if lp.exists() and lp.stat().st_size >= MAX_ALERT_LOG_BYTES:
                os.replace(lp, lp.with_name(lp.name + ".1"))
        except OSError:
            pass
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        mask = bool(load_privacy_settings().get("kvkk_mask_logs", True))
        row = sanitize_alert_for_storage({**report, "alerted_at": now}, mask=mask)
        with open(lp, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    except Exception:
        pass


def handle_native_request(req: dict, alert_log: str = "", log_alerts: bool = True) -> dict:
    """Tarayıcı eklentisinden gelen isteği yerel ElfSec motoruyla işler."""
    action = str((req or {}).get("action", "") or "").strip().lower()

    if action == "ping":
        ai_on = True
        exe_deep = True
        try:
            from app.services.local_ai import load_ai_settings

            cfg = load_ai_settings()
            ai_on = bool(cfg.get("enabled", True))
            exe_deep = bool(cfg.get("exe_deep_scan", True))
        except Exception:
            pass
        return {
            "ok": True,
            "version": __version__,
            "engine": ENGINE,
            "mode": "native-host",
            "ai_enabled": ai_on,
            "exe_deep_scan": exe_deep,
            "auto_protect": False,
            "auto_quarantine_level": "OFF",
        }

    if action == "analyze_email":
        subject = str(req.get("subject", "") or "")[:1000]
        sender = str(req.get("sender", "") or "")[:500]
        body = str(req.get("body", "") or "")[:30000]
        provider = str(req.get("provider", "webmail") or "webmail")[:64]
        expand_urls = bool(req.get("expand_urls", False))

        headers = req.get("headers")
        if not isinstance(headers, dict):
            headers = None
        attachments = req.get("attachments")
        if not isinstance(attachments, list):
            attachments = None

        clean = sanitize_email(body)
        urls: list[str] = list(clean["urls"])
        raw_urls = req.get("urls")
        if isinstance(raw_urls, list):
            for u in raw_urls[:100]:
                su = str(u or "").strip()
                if su.startswith(("http://", "https://")) and su not in urls:
                    urls.append(su)
        urls = urls[:100]
        urls, mapping = maybe_expand(urls, expand_urls)

        result = local_analyze(
            subject,
            clean["plain_text"],
            urls,
            sender,
            headers,
            attachments,
        )
        out = {
            **result,
            "ok": True,
            "source": "browser_webmail",
            "provider": provider,
            "subject": subject,
            "sender": sender,
            "tracking_pixels_blocked": clean["tracking_pixels_blocked"],
            "version": __version__,
        }
        if mapping:
            out["expanded_urls"] = mapping
        if log_alerts:
            _append_webmail_alert(out, alert_log=alert_log)
        return out

    if action in ("analyze_url", "analyze_text"):
        text = str(req.get("text") or req.get("url") or "")[:10000]
        rep = analyze_clipboard_text(text)
        out = {
            **rep,
            "ok": True,
            "source": "browser_web",
            "version": __version__,
        }
        if log_alerts:
            _append_webmail_alert(out, alert_log=alert_log)
        return out

    if action == "scan_file":
        fpath = str(req.get("path", "") or "").strip()
        if not fpath:
            return {"ok": False, "error": "Dosya yolu boş."}
        # GÜVENLİK: Native host bir "confused deputy" olmasın.
        # - Ağ (UNC) yolları: \\saldirgan\paylasim → SMB/NTLM sızıntısı riski.
        # - Aygıt yolları (\\?\, \\.\): ham disk/cihaz erişimi riski.
        # - Sembolik bağlantılar: beklenmeyen hedefe yönlendirme riski.
        if len(fpath) > MAX_SCAN_PATH_CHARS or "\x00" in fpath:
            return {"ok": False, "error": "Geçersiz dosya yolu."}
        if fpath.startswith(("\\\\", "//")):
            return {"ok": False, "error": "Ağ (UNC) yolları taranamaz."}
        p = Path(fpath)
        if not p.is_absolute():
            return {"ok": False, "error": "Dosya yolu mutlak olmalı."}
        try:
            if p.is_symlink():
                return {"ok": False, "error": "Sembolik bağlantılar taranamaz."}
        except OSError:
            return {"ok": False, "error": "Dosya yolu okunamadı."}
        if not p.exists() or not p.is_file():
            return {"ok": False, "error": f"Dosya bulunamadı: {fpath}"}
        from app.services.file_scanner import scan_file_security
        from app.services.local_ai import load_ai_settings

        rep = scan_file_security(p)
        out = {
            **rep,
            "ok": True,
            "source": "browser_download",
            "auto_protected": False,
            "version": __version__,
        }
        ai_cfg = load_ai_settings()
        if log_alerts:
            _append_webmail_alert(out, alert_log=alert_log)
            if (
                bool(req.get("notify", True))
                and os.environ.get("ELFSEC_NO_TOAST") != "1"
                and ai_cfg.get("notify_on_ai_alert", True)
                and str(out.get("risk_level", "LOW")).upper() in ("HIGH", "CRITICAL")
            ):
                try:
                    from app.notify import notify_file_alarm

                    notify_file_alarm(out)
                except Exception:
                    pass
        return out

    return {"ok": False, "error": f"Bilinmeyen istek: {action or '(boş)'}"}


def run_native_host(
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    alert_log: str = "",
) -> int:
    """Tarayıcı Native Messaging stdio döngüsünü çalıştır."""
    if stdin is None and stdout is None and os.name == "nt":
        try:
            import msvcrt

            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        except Exception:
            pass

    in_stream: BinaryIO = stdin if stdin is not None else sys.stdin.buffer
    out_stream: BinaryIO = stdout if stdout is not None else sys.stdout.buffer

    while True:
        try:
            req = read_native_message(in_stream)
        except Exception as e:
            write_native_message(out_stream, {"ok": False, "error": str(e)})
            return 2
        if req is None:
            return 0
        try:
            resp = handle_native_request(req, alert_log=alert_log)
        except Exception as e:
            resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        write_native_message(out_stream, resp)


def build_chromium_manifest(host_path: str, extension_ids: list[str] | None = None) -> dict:
    """Chrome / Edge / Brave NativeMessagingHosts JSON manifesti üret.

    Eklenti ID'leri `^[a-p]{32}$` biçiminde olmalıdır; aksi halde
    `allowed_origins` içine hatalı/istem dışı bir kaynak yazılmasın diye
    hata verilir (fail-closed).
    """
    ids = [str(eid).strip() for eid in (extension_ids or [DEFAULT_EXTENSION_ID]) if str(eid or "").strip()]
    invalid = [eid for eid in ids if not CHROMIUM_EXT_ID_RE.match(eid)]
    if invalid:
        raise ValueError(f"Geçersiz Chromium eklenti ID'si: {', '.join(invalid)}")
    if DEFAULT_EXTENSION_ID not in ids:
        ids.insert(0, DEFAULT_EXTENSION_ID)
    return {
        "name": NATIVE_HOST_NAME,
        "description": "ElfSec Local Email & Phishing Security Engine",
        "path": str(host_path),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{eid}/" for eid in ids],
    }


def build_firefox_manifest(host_path: str) -> dict:
    """Firefox NativeMessagingHosts JSON manifesti üret."""
    return {
        "name": NATIVE_HOST_NAME,
        "description": "ElfSec Local Email & Phishing Security Engine",
        "path": str(host_path),
        "type": "stdio",
        "allowed_extensions": [FIREFOX_EXTENSION_ID],
    }


def discover_installed_extension_ids(existing_manifest: Path | None = None) -> list[str]:
    """Mevcut manifest ve yüklü Chrome/Edge/Brave profillerinden ElfSec uzantı ID'lerini toplar."""
    ids: list[str] = [DEFAULT_EXTENSION_ID]
    seen: set[str] = {DEFAULT_EXTENSION_ID}

    def _add(cand: str) -> None:
        c = str(cand or "").strip().lower()
        if CHROMIUM_EXT_ID_RE.match(c) and c not in seen:
            seen.add(c)
            ids.append(c)

    if existing_manifest is not None and existing_manifest.exists():
        try:
            mf = json.loads(existing_manifest.read_text(encoding="utf-8"))
            for orig in mf.get("allowed_origins") or []:
                m = re.match(r"^chrome-extension://([a-p]{32})/?$", str(orig).strip(), re.IGNORECASE)
                if m:
                    _add(m.group(1))
        except Exception:
            pass

    if os.name == "nt":
        local_app = os.environ.get("LOCALAPPDATA", "")
        if local_app:
            ud_roots = (
                Path(local_app) / "Google" / "Chrome" / "User Data",
                Path(local_app) / "Microsoft" / "Edge" / "User Data",
                Path(local_app) / "BraveSoftware" / "Brave-Browser" / "User Data",
            )
            for root in ud_roots:
                if not root.exists():
                    continue
                try:
                    prof_dirs = [p for p in root.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile "))]
                except OSError:
                    continue
                for prof in prof_dirs[:10]:
                    for pref_name in ("Preferences", "Secure Preferences"):
                        pf = prof / pref_name
                        try:
                            if not pf.is_file() or pf.stat().st_size > 10_485_760:
                                continue
                            pdata = json.loads(pf.read_text(encoding="utf-8", errors="replace"))
                            ext_settings = ((pdata.get("extensions") or {}).get("settings") or {})
                            if not isinstance(ext_settings, dict):
                                continue
                            for eid, meta in ext_settings.items():
                                if not isinstance(meta, dict):
                                    continue
                                ep = str(meta.get("path") or "").lower()
                                mname = str(((meta.get("manifest") or {}).get("name")) or "").lower()
                                if "elfsec" in ep or "elfsec" in mname:
                                    _add(eid)
                        except Exception:
                            continue
    return ids


def test_native_host_wrapper(wrapper_path: Path, timeout: float = 8.0) -> dict:
    """Native Messaging wrapper (.cmd) üzerinden canlı stdio ping testi yapar."""
    wp = Path(wrapper_path)
    if not wp.exists() or not wp.is_file():
        return {"ok": False, "error": f"Native host wrapper bulunamadı: {wp}"}
    try:
        payload = json.dumps({"action": "ping"}, ensure_ascii=False).encode("utf-8")
        frame = struct.pack("<I", len(payload)) + payload
        cmd = ["cmd.exe", "/c", str(wp)] if os.name == "nt" else [str(wp)]
        flags = 0x08000000 if os.name == "nt" else 0
        proc = subprocess.run(
            cmd,
            input=frame,
            capture_output=True,
            timeout=timeout,
            creationflags=flags,
        )
        out = proc.stdout or b""
        if len(out) < 4:
            err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
            return {"ok": False, "error": err or f"Geçersiz yanıt (exit={proc.returncode})"}
        (length,) = struct.unpack("<I", out[:4])
        if length == 0 or len(out) < 4 + length:
            return {"ok": False, "error": "Eksik Native Messaging yanıt çerçevesi."}
        resp = json.loads(out[4 : 4 + length].decode("utf-8", errors="replace"))
        return {"ok": bool(isinstance(resp, dict) and resp.get("ok")), "response": resp}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def write_native_host_files(
    target_dir: Path,
    exe_path: str,
    extension_ids: list[str] | None = None,
) -> dict:
    """Native host wrapper (.cmd) ve Chromium/Firefox manifest JSON dosyalarını yazar."""
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    exe_p = str(exe_path)
    wrapper = target_dir / "elfsec_native_host.cmd"
    if exe_p.lower().endswith(("python.exe", "pythonw.exe")):
        cmd_line = f'"{exe_p}" -m app.cli native-host\r\n'
    else:
        cmd_line = f'"{exe_p}" native-host\r\n'
    wrapper.write_text(f"@echo off\r\n{cmd_line}", encoding="ascii", errors="replace")

    chromium_path = target_dir / f"{NATIVE_HOST_NAME}.json"
    firefox_path = target_dir / f"{NATIVE_HOST_NAME}.firefox.json"

    chromium_path.write_text(
        json.dumps(build_chromium_manifest(str(wrapper), extension_ids), indent=2),
        encoding="utf-8",
    )
    firefox_path.write_text(
        json.dumps(build_firefox_manifest(str(wrapper)), indent=2),
        encoding="utf-8",
    )
    return {
        "wrapper": str(wrapper),
        "chromium_manifest": str(chromium_path),
        "firefox_manifest": str(firefox_path),
    }
