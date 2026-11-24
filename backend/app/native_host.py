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
import struct
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
FIREFOX_EXTENSION_ID = "elfsec-guard@elfsec.local"
MAX_NATIVE_MSG_BYTES = 1_048_576  # 1 MB


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
        lp = Path(alert_log) if alert_log else _default_alert_log_path()
        lp.parent.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        row = {**report, "alerted_at": now}
        with open(lp, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    except Exception:
        pass


def handle_native_request(req: dict, alert_log: str = "") -> dict:
    """Tarayıcı eklentisinden gelen isteği yerel ElfSec motoruyla işler."""
    action = str((req or {}).get("action", "") or "").strip().lower()

    if action == "ping":
        return {
            "ok": True,
            "version": __version__,
            "engine": ENGINE,
            "mode": "native-host",
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
        _append_webmail_alert(out, alert_log=alert_log)
        return out

    if action in ("analyze_url", "analyze_text"):
        text = str(req.get("text") or req.get("url") or "")[:10000]
        rep = analyze_clipboard_text(text)
        return {
            **rep,
            "ok": True,
            "source": "browser_web",
            "version": __version__,
        }

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
    """Chrome / Edge / Brave NativeMessagingHosts JSON manifesti üret."""
    ids = [eid.strip() for eid in (extension_ids or [DEFAULT_EXTENSION_ID]) if eid and eid.strip()]
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
