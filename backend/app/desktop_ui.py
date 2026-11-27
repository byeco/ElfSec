"""ElfSec Modern Masaüstü Güvenlik Paneli (Yerel Çerçevesiz Pencere + Kontrol Merkezi).

Öncelikle `pywebview` (Edge WebView2) tabanlı kendi çerçevesiz yerel penceresinde
özel başlık çubuğu, Win11 yuvarlatılmış köşeler ve pencere kontrolleriyle çalışır;
kullanılamadığı ortamlarda izole `--app` tarayıcı penceresine düşer.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.__version__ import __version__
from app.game_mode import GameModeController, read_shared_game_mode
from app.kontrol import run_kontrol
from app.notify import notify_clipboard_alarm, notify_file_alarm
from app.privacy import clear_alert_logs, load_privacy_settings, save_privacy_settings
from app.services.ai_analyzer import local_analyze
from app.services.file_scanner import (
    default_quarantine_dir,
    lookup_quarantine_record,
    quarantine_file,
    restore_quarantined_file,
    scan_file_security,
    scan_path,
    sha256_file,
)
from app.services.local_ai import (
    add_custom_keyword,
    add_trusted_hash,
    analyze_with_local_ai,
    check_local_llm,
    load_ai_settings,
    remove_custom_keyword,
    save_ai_settings,
)
from app.settings_store import current_settings, default_user_config_path, machine_data_dir
from app.native_host import test_native_host_wrapper
from app.watchers.clipboard_guard import ClipboardGuard, analyze_clipboard_text
from app.watchers.file_watcher import FileWatchState, default_watch_dirs, scan_watch_dirs_once
from app.win_plugin import (
    _is_agent_already_running,
    browser_bridge_details,
    plugin_status,
    read_autopilot_state,
    register_browser_hosts,
    write_autopilot_state,
)

MAX_POST_BYTES = 262_144

_FALLBACK_LOGO_SVG = (
    "data:image/svg+xml;utf8,"
    "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E"
    "%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E"
    "%3Cstop offset='0%25' stop-color='%2334d399'/%3E"
    "%3Cstop offset='100%25' stop-color='%23059669'/%3E%3C/linearGradient%3E%3C/defs%3E"
    "%3Cpath d='M32 4L8 13v17c0 15.5 10.2 27.6 24 31 13.8-3.4 24-15.5 24-31V13L32 4z' fill='url(%23g)'/%3E"
    "%3Cpath d='M22 33l7 7 14-15' fill='none' stroke='%23ffffff' stroke-width='5.5' stroke-linecap='round' stroke-linejoin='round'/%3E"
    "%3C/svg%3E"
)


def _load_logo_data_uri() -> str:
    """Gerçek ElfSec kalkan logosunu base64 data URI olarak yükler."""
    candidates: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", "")
    if meipass:
        candidates.append(Path(meipass) / "assets" / "icon128.png")
    try:
        candidates.append(Path(sys.executable).resolve().parent / "extension" / "icons" / "icon128.png")
    except Exception:
        pass
    try:
        candidates.append(Path(__file__).resolve().parents[2] / "extension" / "icons" / "icon128.png")
    except Exception:
        pass
    for p in candidates:
        if p.exists() and p.is_file():
            try:
                b64 = base64.b64encode(p.read_bytes()).decode("ascii")
                return f"data:image/png;base64,{b64}"
            except OSError:
                continue
    return _FALLBACK_LOGO_SVG


def _known_quarantine_dirs() -> list[Path]:
    dirs: list[Path] = []
    for cand in (
        machine_data_dir() / "quarantine",
        default_user_config_path().parent / "quarantine",
        default_quarantine_dir(),
    ):
        try:
            res = cand.resolve()
        except OSError:
            res = cand
        if res not in dirs:
            dirs.append(res)
    return dirs


def _is_inside_quarantine_dir(target: Path) -> bool:
    if target.suffix.lower() != ".quarantined":
        return False
    try:
        resolved = target.resolve()
    except OSError:
        return False
    for qdir in _known_quarantine_dirs():
        try:
            resolved.relative_to(qdir)
            return True
        except ValueError:
            continue
    return False


def _collect_alerts(limit: int = 100) -> list[dict]:
    sources = [
        machine_data_dir() / "guard_alerts.jsonl",
        default_user_config_path().parent / "guard_alerts.jsonl",
        Path("guard_alerts.jsonl"),
    ]
    rows: list[dict] = []
    seen_keys: set[str] = set()
    for src in sources:
        if not src.exists():
            continue
        try:
            lines = src.read_text(encoding="utf-8", errors="replace").splitlines()[-300:]
        except OSError:
            continue
        for line in lines:
            raw = line.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            dedup = "|".join([
                str(obj.get("alerted_at") or obj.get("analyzed_at") or obj.get("date") or ""),
                str(obj.get("source") or ""),
                str(obj.get("subject") or obj.get("file") or obj.get("preview") or ""),
                str(obj.get("risk_score") or ""),
            ])
            if dedup in seen_keys:
                continue
            seen_keys.add(dedup)
            rows.append(obj)
    rows.sort(
        key=lambda r: str(r.get("alerted_at") or r.get("analyzed_at") or r.get("date") or ""),
        reverse=True,
    )
    return rows[:limit]


def _collect_quarantine_items() -> list[dict]:
    items: list[dict] = []
    seen: set[str] = set()
    for qdir in _known_quarantine_dirs():
        if not qdir.exists():
            continue
        try:
            files = sorted(qdir.glob("*.quarantined"), key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            continue
        for fp in files:
            key = str(fp.resolve()) if fp.exists() else str(fp)
            if key in seen:
                continue
            seen.add(key)
            try:
                st = fp.stat()
                rec = lookup_quarantine_record(fp) or {}
                items.append({
                    "name": fp.name,
                    "path": str(fp),
                    "original_path": str(rec.get("original_path") or ""),
                    "reasons": list(rec.get("reasons") or []),
                    "size": st.st_size,
                    "modified_at": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                })
            except OSError:
                continue
    return items


def _pick_native_file() -> str:
    """Windows üzerinde sıfır bağımlılıkla dosya seçme penceresi açar."""
    if os.name != "nt":
        return ""
    try:
        import ctypes
        from ctypes import wintypes

        comdlg32 = ctypes.windll.comdlg32

        class OPENFILENAMEW(ctypes.Structure):
            _fields_ = [
                ("lStructSize", wintypes.DWORD),
                ("hwndOwner", wintypes.HWND),
                ("hInstance", wintypes.HINSTANCE),
                ("lpstrFilter", wintypes.LPCWSTR),
                ("lpstrCustomFilter", wintypes.LPWSTR),
                ("nMaxCustFilter", wintypes.DWORD),
                ("nFilterIndex", wintypes.DWORD),
                ("lpstrFile", wintypes.LPWSTR),
                ("nMaxFile", wintypes.DWORD),
                ("lpstrFileTitle", wintypes.LPWSTR),
                ("nMaxFileTitle", wintypes.DWORD),
                ("lpstrInitialDir", wintypes.LPCWSTR),
                ("lpstrTitle", wintypes.LPCWSTR),
                ("Flags", wintypes.DWORD),
                ("nFileOffset", wintypes.WORD),
                ("nFileExtension", wintypes.WORD),
                ("lpstrDefExt", wintypes.LPCWSTR),
                ("lCustData", wintypes.LPARAM),
                ("lpfnHook", ctypes.c_void_p),
                ("lpTemplateName", wintypes.LPCWSTR),
                ("pvReserved", ctypes.c_void_p),
                ("dwReserved", wintypes.DWORD),
                ("FlagsEx", wintypes.DWORD),
            ]

        buf = ctypes.create_unicode_buffer(1024)
        ofn = OPENFILENAMEW()
        ofn.lStructSize = ctypes.sizeof(OPENFILENAMEW)
        ofn.lpstrFilter = "Tüm Dosyalar (*.*)\0*.*\0E-posta & Belgeler\0*.eml;*.msg;*.pdf;*.docm;*.xlsm;*.zip;*.exe;*.ps1\0"
        ofn.nFilterIndex = 1
        ofn.lpstrFile = ctypes.cast(buf, wintypes.LPWSTR)
        ofn.nMaxFile = 1024
        ofn.lpstrTitle = "ElfSec — Taranacak Dosyayı Seçin"
        ofn.Flags = 0x00001000 | 0x00000800 | 0x00000008  # FILEMUSTEXIST | PATHMUSTEXIST | NOCHANGEDIR
        comdlg32.GetOpenFileNameW.argtypes = [ctypes.POINTER(OPENFILENAMEW)]
        comdlg32.GetOpenFileNameW.restype = wintypes.BOOL
        if comdlg32.GetOpenFileNameW(ctypes.byref(ofn)):
            return buf.value
    except Exception:
        pass
    return ""


def _find_chromium_app_browser() -> str | None:
    if os.name != "nt":
        for name in ("google-chrome", "chromium", "microsoft-edge"):
            found = shutil.which(name)
            if found:
                return found
        return None

    env_pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    env_pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    env_local = os.environ.get("LocalAppData", "")
    candidates = [
        Path(env_pf86) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        Path(env_pf) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        Path(env_pf) / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(env_pf86) / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(env_local) / "Google" / "Chrome" / "Application" / "chrome.exe" if env_local else None,
        Path(env_pf) / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe",
    ]
    for cand in candidates:
        if cand and cand.exists():
            return str(cand)
    for exe in ("msedge.exe", "chrome.exe", "brave.exe"):
        found = shutil.which(exe)
        if found:
            return found
    return None


def _ui_profile_dir() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / ".config"))
    profile = base / "ElfSec" / "ui-profile"
    try:
        profile.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return profile


def open_app_window(url: str) -> bool:
    """Paneli izole ElfSec uygulama penceresinde açar; yoksa varsayılan tarayıcıya düşer."""
    browser = _find_chromium_app_browser()
    if browser:
        try:
            flags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
            profile_dir = _ui_profile_dir()
            subprocess.Popen(
                [
                    browser,
                    f"--app={url}",
                    f"--user-data-dir={profile_dir}",
                    "--window-size=860,580",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--class=ElfSecPanel",
                ],
                creationflags=flags,
                close_fds=True,
            )
            return True
        except Exception:
            pass
    try:
        return bool(webbrowser.open(url))
    except Exception:
        return False


class _ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class DesktopPanelServer:
    """Localhost-only, token doğrulamalı modern ElfSec masaüstü kontrol sunucusu."""

    def __init__(
        self,
        port: int = 0,
        controller: GameModeController | None = None,
        token: str | None = None,
        autopilot: bool = False,
    ):
        self.token = token or secrets.token_hex(24)
        self.controller = controller or GameModeController()
        self.autopilot = bool(autopilot)
        self.stop_event = threading.Event()
        self.window_controller: Any = None
        self._server: _ReusableThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._port = int(port)

    @property
    def port(self) -> int:
        if self._server is not None:
            return int(self._server.server_address[1])
        return self._port

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/?token={self.token}"

    def _build_status(self) -> dict:
        pst = plugin_status()
        gm = self.controller.evaluate() if self.controller else read_shared_game_mode()
        s = current_settings()
        q_items = _collect_quarantine_items()
        alerts = _collect_alerts(limit=100)
        ai_cfg = load_ai_settings()
        ap_state = read_autopilot_state()
        return {
            "version": __version__,
            "env": s.env,
            "imap_configured": bool(s.imap_configured),
            "service": pst.get("service", {}),
            "browser": pst.get("browser", {}),
            "browser_bridge": browser_bridge_details(),
            "context_menu_files": bool(pst.get("context_menu_files")),
            "context_menu_dirs": bool(pst.get("context_menu_dirs")),
            "protocol_registered": bool(pst.get("protocol_registered")),
            "agent_autostart": bool(pst.get("agent_autostart")),
            "config_file": pst.get("config_file", ""),
            "machine_data_dir": pst.get("machine_data_dir", ""),
            "alerts_count": len(alerts),
            "quarantine_count": len(q_items),
            "game_mode": gm,
            "privacy": load_privacy_settings(),
            "ai": ai_cfg,
            "autopilot": {
                **ap_state,
                "enabled": bool(ai_cfg.get("autopilot", True)),
                "agent_running": bool(_is_agent_already_running()),
            },
        }

    def _window_state(self) -> dict:
        wc = self.window_controller
        if wc is not None:
            return dict(wc.get_state())
        return {"native": False, "maximized": False, "pinned": False}

    def start(self) -> str:
        if self._server is not None:
            return self.url

        panel = self
        logo_uri = _load_logo_data_uri()

        class _Handler(BaseHTTPRequestHandler):
            server_version = "ElfSecPanel/1.6"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send_headers(self, status: int, content_type: str, length: int) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(length))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';",
                )
                self.end_headers()

            def _send_json(self, status: int, data: dict) -> None:
                body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
                self._send_headers(status, "application/json; charset=utf-8", len(body))
                self.wfile.write(body)

            def _send_html(self, status: int, html: str) -> None:
                body = html.encode("utf-8")
                self._send_headers(status, "text/html; charset=utf-8", len(body))
                self.wfile.write(body)

            def _check_api_token(self) -> bool:
                hdr = self.headers.get("X-ElfSec-Token", "")
                if not hdr or not hmac.compare_digest(hdr, panel.token):
                    self._send_json(403, {"ok": False, "error": "Yetkisiz istek (geçersiz oturum anahtarı)."})
                    return False
                return True

            def _read_json_body(self) -> dict | None:
                try:
                    length = int(self.headers.get("Content-Length", "0") or "0")
                except ValueError:
                    self._send_json(400, {"ok": False, "error": "Geçersiz Content-Length."})
                    return None
                if length < 0 or length > MAX_POST_BYTES:
                    self._send_json(413, {"ok": False, "error": "İstek gövdesi çok büyük."})
                    return None
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    data = json.loads(raw.decode("utf-8"))
                    if not isinstance(data, dict):
                        raise ValueError("JSON nesne olmalı")
                    return data
                except Exception:
                    self._send_json(400, {"ok": False, "error": "Geçersiz JSON gövdesi."})
                    return None

            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                if parsed.path in ("/", "/index.html"):
                    qs = parse_qs(parsed.query)
                    tok = (qs.get("token") or [""])[0]
                    if not tok or not hmac.compare_digest(tok, panel.token):
                        self._send_html(403, "<h1>403 Forbidden</h1><p>Geçersiz ElfSec oturum anahtarı.</p>")
                        return
                    html = (
                        _PANEL_HTML
                        .replace("__ELFSEC_TOKEN__", panel.token)
                        .replace("__ELFSEC_VERSION__", __version__)
                        .replace("__ELFSEC_LOGO__", logo_uri)
                    )
                    self._send_html(200, html)
                    return

                if not self._check_api_token():
                    return

                if parsed.path == "/api/status":
                    self._send_json(200, {"ok": True, **panel._build_status()})
                elif parsed.path == "/api/privacy":
                    self._send_json(200, {"ok": True, "privacy": load_privacy_settings()})
                elif parsed.path == "/api/ai/settings":
                    self._send_json(200, {"ok": True, "ai": load_ai_settings()})
                elif parsed.path == "/api/window/state":
                    self._send_json(200, {"ok": True, **panel._window_state()})
                elif parsed.path == "/api/alerts":
                    self._send_json(200, {"ok": True, "alerts": _collect_alerts(limit=100)})
                elif parsed.path == "/api/quarantine":
                    self._send_json(200, {"ok": True, "items": _collect_quarantine_items()})
                elif parsed.path == "/api/kontrol":
                    rep = run_kontrol()
                    self._send_json(200, {"ok": True, "report": rep})
                else:
                    self._send_json(404, {"ok": False, "error": "Bilinmeyen endpoint."})

            def do_POST(self) -> None:
                parsed = urlparse(self.path)
                if not self._check_api_token():
                    return
                body = self._read_json_body()
                if body is None:
                    return

                if parsed.path == "/api/privacy":
                    st = save_privacy_settings(body)
                    self._send_json(200, {"ok": True, "privacy": st})
                    return

                if parsed.path == "/api/ai/settings":
                    action = str(body.get("action") or "save").strip().lower()
                    try:
                        if action == "add_keyword":
                            st = add_custom_keyword(str(body.get("keyword") or ""))
                        elif action == "remove_keyword":
                            st = remove_custom_keyword(str(body.get("keyword") or ""))
                        else:
                            st = save_ai_settings(body)
                        self._send_json(200, {"ok": True, "ai": st})
                    except ValueError as e:
                        self._send_json(400, {"ok": False, "error": str(e)})
                    return

                if parsed.path == "/api/ai/test-llm":
                    cfg = load_ai_settings()
                    prov = str(body.get("llm_provider") or cfg.get("llm_provider") or "ollama")
                    url = str(body.get("llm_url") or cfg.get("llm_url") or "http://127.0.0.1:11434")
                    res = check_local_llm(provider=prov, url=url)
                    self._send_json(200, {"ok": True, **res})
                    return

                if parsed.path == "/api/ai/analyze":
                    text = str(body.get("text") or "")
                    if not text.strip():
                        self._send_json(400, {"ok": False, "error": "Analiz edilecek metin veya veri boş olamaz."})
                        return
                    subject = str(body.get("subject") or "")
                    sender = str(body.get("sender") or "")
                    rep = local_analyze(subject, text, [], sender)
                    ai_res = rep.get("ai_analysis") or analyze_with_local_ai(text, subject=subject, sender=sender)
                    ai_cfg = load_ai_settings()
                    if bool(body.get("notify", False)) and ai_cfg.get("notify_on_ai_alert", True):
                        if rep.get("risk_level") in ("HIGH", "CRITICAL"):
                            notify_clipboard_alarm(rep)
                    self._send_json(200, {"ok": True, "report": rep, "ai_analysis": ai_res})
                    return

                if parsed.path == "/api/alerts/clear":
                    cnt = clear_alert_logs()
                    self._send_json(200, {"ok": True, "cleared": cnt})
                    return

                if parsed.path == "/api/window/minimize":
                    wc = panel.window_controller
                    st = wc.minimize() if wc is not None else {"native": False, "maximized": False, "pinned": False}
                    self._send_json(200, {"ok": True, **st})
                    return

                if parsed.path == "/api/window/toggle-maximize":
                    wc = panel.window_controller
                    st = wc.toggle_maximize() if wc is not None else {"native": False, "maximized": False, "pinned": False}
                    self._send_json(200, {"ok": True, **st})
                    return

                if parsed.path == "/api/window/pin":
                    wc = panel.window_controller
                    st = wc.toggle_pin() if wc is not None else {"native": False, "maximized": False, "pinned": False}
                    self._send_json(200, {"ok": True, **st})
                    return

                if parsed.path == "/api/window/drag-start":
                    wc = panel.window_controller
                    st = wc.begin_drag() if wc is not None else {"started": False, "native": False, "maximized": False, "pinned": False}
                    self._send_json(200, {"ok": True, **st})
                    return

                if parsed.path == "/api/window/resize-start":
                    wc = panel.window_controller
                    edge = str(body.get("edge") or "se")
                    st = wc.begin_resize(edge) if (wc is not None and hasattr(wc, "begin_resize")) else {"started": False, "native": False, "maximized": False, "pinned": False}
                    self._send_json(200, {"ok": True, **st})
                    return

                if parsed.path == "/api/window/move":
                    wc = panel.window_controller
                    dx = int(body.get("dx", 0) or 0)
                    dy = int(body.get("dy", 0) or 0)
                    st = wc.move_by(dx, dy) if wc is not None else {"native": False, "maximized": False, "pinned": False}
                    self._send_json(200, {"ok": True, **st})
                    return

                if parsed.path == "/api/window/close":
                    wc = panel.window_controller
                    self._send_json(200, {"ok": True, "closed": True})
                    def _deferred_close() -> None:
                        threading.Event().wait(0.05)
                        if wc is not None:
                            try:
                                wc.close()
                            except Exception:
                                pass
                        panel.stop_event.set()
                    threading.Thread(target=_deferred_close, daemon=True).start()
                    return

                if parsed.path == "/api/scan/text":
                    text = str(body.get("text") or "")
                    if not text.strip():
                        self._send_json(400, {"ok": False, "error": "Taranacak metin veya URL boş olamaz."})
                        return
                    rep = analyze_clipboard_text(text)
                    self._send_json(200, {"ok": True, "report": rep})
                    return

                if parsed.path == "/api/scan/path":
                    target_str = str(body.get("path") or "").strip().strip('"')
                    if not target_str:
                        self._send_json(400, {"ok": False, "error": "Dosya veya klasör yolu boş olamaz."})
                        return
                    target = Path(target_str)
                    if not target.exists():
                        self._send_json(404, {"ok": False, "error": f"Yol bulunamadı: {target}"})
                        return
                    if target.is_file():
                        reports = [scan_file_security(target)]
                    else:
                        reports = scan_path(target, recursive=True, max_files=200)

                    ai_cfg = load_ai_settings()
                    allow_auto = bool(body.get("auto_protect", False))
                    q_lvl = str(ai_cfg.get("auto_quarantine_level", "OFF")).upper()
                    lvl_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
                    if allow_auto and ai_cfg.get("enabled", True) and ai_cfg.get("auto_protect", False) and q_lvl != "OFF":
                        for rep in reports:
                            fpath = rep.get("file")
                            if not fpath:
                                continue
                            if lvl_order.get(str(rep.get("risk_level", "LOW")).upper(), 0) >= lvl_order.get(q_lvl, 99):
                                try:
                                    qrec = quarantine_file(Path(fpath), report=rep)
                                    rep["quarantined_to"] = qrec["quarantine_path"]
                                    rep["auto_protected"] = True
                                    if ai_cfg.get("notify_on_ai_alert", True) and bool(body.get("notify", False)):
                                        notify_file_alarm(rep)
                                except Exception:
                                    pass

                    self._send_json(200, {"ok": True, "reports": reports})
                    return

                if parsed.path == "/api/scan/downloads":
                    dirs = default_watch_dirs(all_users=False)
                    st = FileWatchState(default_user_config_path().parent / ".ui_watch_seen.json")
                    ai_cfg = load_ai_settings()
                    scanned, alerts = scan_watch_dirs_once(
                        dirs,
                        st,
                        alert_on="MEDIUM",
                        notify=bool(ai_cfg.get("notify_on_ai_alert", True)) and bool(body.get("notify", False)),
                        auto_protect=bool(ai_cfg.get("auto_protect", False)),
                    )
                    auto_count = sum(1 for a in alerts if a.get("auto_protected"))
                    self._send_json(200, {
                        "ok": True,
                        "scanned_count": len(scanned),
                        "auto_protected_count": auto_count,
                        "alerts": alerts,
                    })
                    return

                if parsed.path == "/api/scan/clipboard":
                    rep = ClipboardGuard(enabled=True).check_once(force=True)
                    if not rep:
                        self._send_json(200, {
                            "ok": True,
                            "empty": True,
                            "report": {"risk_score": 0, "risk_level": "LOW", "summary": "Pano boş veya metin içermiyor.", "reasons": []},
                        })
                    else:
                        self._send_json(200, {"ok": True, "empty": False, "report": rep})
                    return

                if parsed.path == "/api/pick-file":
                    picked = _pick_native_file()
                    self._send_json(200, {"ok": True, "path": picked})
                    return

                if parsed.path == "/api/game-mode":
                    action = str(body.get("action") or "detect").strip().lower()
                    try:
                        if action == "set_mode":
                            st = panel.controller.set_mode(str(body.get("mode") or "auto"))
                        elif action == "add_game":
                            st = panel.controller.add_custom_game(str(body.get("exe") or ""))
                        elif action == "remove_game":
                            st = panel.controller.remove_custom_game(str(body.get("exe") or ""))
                        elif action == "detect":
                            st = panel.controller.evaluate()
                        else:
                            self._send_json(400, {"ok": False, "error": f"Bilinmeyen oyun modu işlemi: {action}"})
                            return
                        self._send_json(200, {"ok": True, "game_mode": st})
                    except ValueError as e:
                        self._send_json(400, {"ok": False, "error": str(e)})
                    return

                if parsed.path == "/api/quarantine/action":
                    action = str(body.get("action") or "").strip().lower()
                    target_str = str(body.get("path") or "").strip()
                    if not target_str:
                        self._send_json(400, {"ok": False, "error": "Dosya yolu gerekli."})
                        return
                    target = Path(target_str)
                    if action == "quarantine":
                        if not target.exists() or not target.is_file():
                            self._send_json(404, {"ok": False, "error": f"Dosya bulunamadı: {target}"})
                            return
                        rep = scan_file_security(target)
                        rec = quarantine_file(target, report=rep)
                        self._send_json(200, {"ok": True, "record": rec})
                        return
                    if action in ("restore", "delete"):
                        if not _is_inside_quarantine_dir(target):
                            self._send_json(403, {"ok": False, "error": "Yalnızca ElfSec karantina kasası içindeki .quarantined dosyalarına işlem yapılabilir."})
                            return
                        if not target.exists() or not target.is_file():
                            self._send_json(404, {"ok": False, "error": "Karantina dosyası bulunamadı."})
                            return
                        if action == "delete":
                            target.unlink()
                            self._send_json(200, {"ok": True, "deleted": str(target)})
                            return
                        rec = lookup_quarantine_record(target) or {}
                        orig_path_str = str(rec.get("original_path") or "").strip()
                        if orig_path_str:
                            cand_dest = Path(orig_path_str)
                            if cand_dest.exists():
                                cand_dest = cand_dest.with_name(f"{cand_dest.stem}_restored{cand_dest.suffix}")
                            dest_target = cand_dest
                        else:
                            orig_name = target.name
                            parts = orig_name.split("_", 2)
                            clean_name = parts[2] if len(parts) == 3 else orig_name
                            if clean_name.lower().endswith(".quarantined"):
                                clean_name = clean_name[: -len(".quarantined")]
                            restore_dir = Path.home() / "Downloads" / "ElfSec_Restored"
                            dest_target = restore_dir / (clean_name or "restored_file")

                        dest = restore_quarantined_file(target, dest_target)
                        digest = str(rec.get("sha256") or "") or sha256_file(dest)
                        if digest:
                            try:
                                add_trusted_hash(digest)
                            except Exception:
                                pass
                        try:
                            ap_state_file = default_user_config_path().parent / ".autopilot_watch_seen.json"
                            ws = FileWatchState(ap_state_file)
                            ws.mark(dest)
                            ws.save()
                        except Exception:
                            pass
                        self._send_json(200, {"ok": True, "restored_to": str(dest), "trusted": bool(digest)})
                        return
                    self._send_json(400, {"ok": False, "error": f"Geçersiz karantina işlemi: {action}"})
                    return

                if parsed.path == "/api/browser/register":
                    ext_id = str(body.get("extension_id") or "").strip()
                    user_only = bool(body.get("user_only", True))
                    integrate_system = bool(body.get("integrate_system", False))
                    run_self_test = bool(body.get("run_self_test", True))
                    ids = [ext_id] if ext_id else None
                    res = register_browser_hosts(
                        user_only=user_only,
                        extension_ids=ids,
                        integrate_system=integrate_system,
                        preserve_existing=True,
                        run_self_test=run_self_test,
                    )
                    code = 200 if res.get("ok") else 400
                    self._send_json(code, res)
                    return

                if parsed.path == "/api/browser/test":
                    details = browser_bridge_details()
                    wp = details.get("wrapper_path") or ""
                    if not wp:
                        self._send_json(200, {"ok": True, "self_test": {"ok": False, "error": "Kayıtlı Native Host wrapper henüz oluşturulmamış."}, "bridge": details})
                        return
                    st = test_native_host_wrapper(Path(wp))
                    self._send_json(200, {"ok": True, "self_test": st, "bridge": details})
                    return

                if parsed.path == "/api/shutdown":
                    panel.stop_event.set()
                    self._send_json(200, {"ok": True})
                    return

                self._send_json(404, {"ok": False, "error": "Bilinmeyen endpoint."})

        self._server = _ReusableThreadingHTTPServer(("127.0.0.1", self._port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        if self.autopilot:
            def _autopilot_worker() -> None:
                watch_state = FileWatchState(default_user_config_path().parent / ".autopilot_watch_seen.json")
                user_alert_log = str(default_user_config_path().parent / "guard_alerts.jsonl")
                dirs = default_watch_dirs(all_users=False, include_mail_apps=True)
                while not self.stop_event.is_set():
                    try:
                        ai_cfg = load_ai_settings()
                        if ai_cfg.get("autopilot", True) and not _is_agent_already_running():
                            mask_logs = bool(load_privacy_settings().get("kvkk_mask_logs", True))
                            scanned, alerts = scan_watch_dirs_once(
                                dirs,
                                watch_state,
                                alert_on="HIGH",
                                alert_log=user_alert_log,
                                notify=bool(ai_cfg.get("notify_on_ai_alert", True)),
                                redact=mask_logs,
                                auto_protect=bool(ai_cfg.get("auto_protect", False)),
                            )
                            prev = read_autopilot_state()
                            auto_q = sum(1 for a in alerts if a.get("auto_protected"))
                            write_autopilot_state({
                                "last_scan_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                                "watched_dirs_count": len(dirs),
                                "last_scanned_count": len(scanned),
                                "total_scanned": int(prev.get("total_scanned") or 0) + len(scanned),
                                "total_auto_quarantined": int(prev.get("total_auto_quarantined") or 0) + auto_q,
                            })
                    except Exception:
                        pass
                    gm_now = self.controller.evaluate() if self.controller else {}
                    self.stop_event.wait(120.0 if gm_now.get("active") else 12.0)

            threading.Thread(target=_autopilot_worker, daemon=True).start()
        return self.url

    def stop(self) -> None:
        self.stop_event.set()
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None


def run_desktop_panel(
    port: int = 0,
    open_browser: bool = True,
    controller: GameModeController | None = None,
) -> int:
    """Masaüstü Güvenlik Paneli sunucusunu başlatır; yerel pencere veya yedek tarayıcı açar."""
    enable_auto = bool(
        open_browser
        and os.environ.get("ELFSEC_NO_AUTOPILOT") != "1"
        and not os.environ.get("PYTEST_CURRENT_TEST")
    )
    srv = DesktopPanelServer(port=port, controller=controller, autopilot=enable_auto)
    url = srv.start()
    try:
        if open_browser:
            launched_native = False
            try:
                from app.window_host import launch_native_window

                launched_native = launch_native_window(srv)
            except Exception:
                launched_native = False

            if launched_native:
                return 0
            open_app_window(url)
        else:
            print(f"ElfSec Masaüstü Paneli: {url}")

        while not srv.stop_event.is_set():
            srv.stop_event.wait(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        srv.stop()
    return 0


_PANEL_HTML = r"""<!DOCTYPE html>
<html lang="tr" data-theme="dark">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ElfSec Güvenlik Merkezi</title>
  <link rel="icon" type="image/png" href="__ELFSEC_LOGO__" />
  <style>
    :root {
      --bg: #0b0c0e;
      --bg-sidebar: #0f1013;
      --surface: #14161a;
      --surface-solid: #14161a;
      --surface-2: #1a1d23;
      --surface-hover: #21252d;
      --frame-border: rgba(255, 255, 255, 0.09);
      --text: #f3f4f6;
      --text-2: #b4bac6;
      --muted: #7a8291;
      --border: rgba(255, 255, 255, 0.075);
      --border-strong: rgba(255, 255, 255, 0.14);
      --brand: #10b981;
      --brand-hover: #059669;
      --brand-soft: rgba(16, 185, 129, 0.12);
      --ok: #34d399;
      --ok-soft: rgba(16, 185, 129, 0.12);
      --warn: #f59e0b;
      --warn-soft: rgba(245, 158, 11, 0.12);
      --bad: #ef4444;
      --bad-soft: rgba(239, 68, 68, 0.12);
      --game: #8b5cf6;
      --game-soft: rgba(139, 92, 246, 0.13);
      --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.28);
      --shadow-md: 0 10px 28px rgba(0, 0, 0, 0.42);
      --mono: ui-monospace, "Cascadia Code", Consolas, monospace;
    }
    :root[data-theme="light"] {
      --bg: #f7f8fa;
      --bg-sidebar: #f1f3f6;
      --surface: #ffffff;
      --surface-solid: #ffffff;
      --surface-2: #f4f5f7;
      --surface-hover: #eceef2;
      --frame-border: rgba(15, 23, 42, 0.12);
      --text: #111318;
      --text-2: #424956;
      --muted: #6b7280;
      --border: rgba(15, 23, 42, 0.08);
      --border-strong: rgba(15, 23, 42, 0.16);
      --brand: #059669;
      --brand-hover: #047857;
      --brand-soft: rgba(5, 150, 105, 0.09);
      --ok: #059669;
      --ok-soft: rgba(5, 150, 105, 0.09);
      --warn: #b45309;
      --warn-soft: rgba(217, 119, 6, 0.10);
      --bad: #dc2626;
      --bad-soft: rgba(220, 38, 38, 0.09);
      --game: #6d28d9;
      --game-soft: rgba(109, 40, 217, 0.10);
      --shadow-sm: 0 1px 2px rgba(15, 23, 42, 0.04);
      --shadow-md: 0 8px 24px rgba(15, 23, 42, 0.08);
    }

    *, *::before, *::after { box-sizing: border-box; }
    html, body { height: 100vh; margin: 0; overflow: hidden; }
    body {
      font-family: "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      font-size: 13px;
      line-height: 1.45;
      -webkit-font-smoothing: antialiased;
      user-select: none;
    }
    input, textarea, pre, .mono, table { user-select: text; }
    ::-webkit-scrollbar { width: 7px; height: 7px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 999px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--muted); }

    .ico { width: 15px; height: 15px; flex: 0 0 auto; display: inline-block; }

    /* ==================== PENCERE KABUĞU ==================== */
    .app-frame {
      position: relative;
      height: 100vh;
      display: flex;
      flex-direction: column;
      border: 1px solid var(--frame-border);
      background: var(--bg);
    }
    .app-frame.is-maximized { border-width: 0; }
    .app-frame.is-maximized .win-resize-edge { display: none; }

    .win-resize-edge {
      position: fixed;
      z-index: 1200;
      user-select: none;
    }
    .win-resize-edge.n  { top: 0; left: 8px; right: 8px; height: 5px; cursor: ns-resize; }
    .win-resize-edge.s  { bottom: 0; left: 8px; right: 8px; height: 5px; cursor: ns-resize; }
    .win-resize-edge.w  { left: 0; top: 8px; bottom: 8px; width: 5px; cursor: ew-resize; }
    .win-resize-edge.e  { right: 0; top: 8px; bottom: 8px; width: 5px; cursor: ew-resize; }
    .win-resize-edge.nw { top: 0; left: 0; width: 9px; height: 9px; cursor: nwse-resize; z-index: 1201; }
    .win-resize-edge.ne { top: 0; right: 0; width: 9px; height: 9px; cursor: nesw-resize; z-index: 1201; }
    .win-resize-edge.sw { bottom: 0; left: 0; width: 9px; height: 9px; cursor: nesw-resize; z-index: 1201; }
    .win-resize-edge.se { bottom: 0; right: 0; width: 9px; height: 9px; cursor: nwse-resize; z-index: 1201; }

    .titlebar {
      height: 38px;
      flex: 0 0 38px;
      background: var(--bg-sidebar);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-left: 14px;
    }
    .titlebar-drag {
      flex: 1;
      height: 100%;
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
      cursor: default;
      app-region: drag;
      -webkit-app-region: drag;
    }
    [data-win-drag="1"] { cursor: default; }
    .titlebar-controls, .titlebar button {
      app-region: no-drag;
      -webkit-app-region: no-drag;
    }
    .tb-logo {
      width: 18px;
      height: 18px;
      display: grid;
      place-items: center;
      flex: 0 0 auto;
    }
    .tb-logo img { display: block; border-radius: 4px; width: 18px; height: 18px; }
    .tb-title {
      font-size: 12.5px;
      font-weight: 600;
      letter-spacing: -0.01em;
      color: var(--text);
      white-space: nowrap;
    }
    .tb-slash { font-size: 12px; color: var(--border-strong); }
    .tb-ver {
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 500;
      color: var(--muted);
      white-space: nowrap;
    }

    .titlebar-controls {
      height: 100%;
      display: flex;
      align-items: center;
      flex: 0 0 auto;
    }
    .tb-icon-btn {
      width: 34px;
      height: 38px;
      border: 0;
      background: transparent;
      color: var(--muted);
      display: grid;
      place-items: center;
      cursor: pointer;
      transition: background 0.12s ease, color 0.12s ease;
    }
    .tb-icon-btn:hover { background: var(--surface-hover); color: var(--text); }
    .tb-icon-btn.is-pinned { color: var(--brand); }
    .tb-sep { width: 1px; height: 14px; background: var(--border-strong); margin: 0 2px; }
    .win-btn {
      width: 44px;
      height: 38px;
      border: 0;
      background: transparent;
      color: var(--text-2);
      display: grid;
      place-items: center;
      cursor: pointer;
      transition: background 0.12s ease, color 0.12s ease;
    }
    .win-btn:hover { background: var(--surface-hover); color: var(--text); }
    .win-btn.close:hover { background: #c42b1c; color: #ffffff; }
    .win-native-only.is-hidden { display: none; }

    /* ==================== GÖVDE & KENAR ÇUBUĞU ==================== */
    .app-body {
      flex: 1;
      min-height: 0;
      display: flex;
    }
    .sidebar {
      width: 192px;
      flex: 0 0 192px;
      background: var(--bg-sidebar);
      border-right: 1px solid var(--border);
      padding: 14px 10px 12px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .nav-section-label {
      padding: 0 10px 2px;
      font-size: 10px;
      font-weight: 600;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
    }
    .nav { display: flex; flex-direction: column; gap: 2px; flex: 1; }
    .nav-btn {
      position: relative;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding: 7px 10px;
      border: 1px solid transparent;
      border-radius: 7px;
      background: transparent;
      color: var(--text-2);
      font-family: inherit;
      font-size: 12.5px;
      font-weight: 500;
      cursor: pointer;
      text-align: left;
      transition: background 0.12s ease, color 0.12s ease, border-color 0.12s ease;
    }
    .nav-btn-left { display: inline-flex; align-items: center; gap: 9px; min-width: 0; }
    .nav-btn-left span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .nav-btn:hover { background: var(--surface-hover); color: var(--text); }
    .nav-btn.active {
      background: var(--surface-2);
      border-color: var(--border);
      color: var(--text);
      font-weight: 600;
    }
    .nav-btn.active .ico { color: var(--brand); }
    .nav-btn.active::before {
      content: "";
      position: absolute;
      left: 0;
      top: 7px;
      bottom: 7px;
      width: 2px;
      border-radius: 2px;
      background: var(--brand);
    }
    .nav-badge {
      padding: 1px 6px;
      border-radius: 999px;
      font-size: 10.5px;
      font-family: var(--mono);
      font-variant-numeric: tabular-nums;
      background: var(--surface);
      border: 1px solid var(--border);
      color: var(--muted);
    }

    .side-posture {
      padding: 10px;
      border-radius: 8px;
      background: var(--surface);
      border: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      gap: 6px;
      font-size: 11.5px;
    }
    .side-posture-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }
    .pulse-wrap { display: inline-flex; align-items: center; gap: 7px; font-weight: 600; color: var(--text); }
    .pulse-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--ok);
      flex: 0 0 auto;
    }
    .pulse-dot.game { background: var(--game); }
    .pulse-dot.warn { background: var(--warn); }
    .side-foot {
      padding: 2px 6px 0;
      font-size: 10.5px;
      color: var(--muted);
      font-family: var(--mono);
      display: flex;
      justify-content: space-between;
    }

    /* ==================== ANA ALAN ==================== */
    .main {
      flex: 1;
      min-width: 0;
      overflow-y: auto;
      padding: 18px 22px 20px;
      background: var(--bg);
    }
    .main-inner { max-width: 1080px; margin: 0 auto; }
    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }
    .topbar h1 {
      margin: 0;
      font-size: 18.5px;
      font-weight: 600;
      letter-spacing: -0.02em;
      line-height: 1.25;
    }
    .topbar-sub { font-size: 12px; color: var(--muted); margin-top: 2px; }
    .topbar-actions { display: flex; align-items: center; gap: 7px; flex-wrap: wrap; }
    body[data-active-tab="overview"] .topbar-ov-hide { display: none; }

    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 9px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--muted);
      white-space: nowrap;
      font-variant-numeric: tabular-nums;
    }
    .pill::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; flex: 0 0 auto; }
    .pill.ok { background: var(--ok-soft); color: var(--ok); border-color: rgba(16, 185, 129, 0.24); }
    .pill.warn { background: var(--warn-soft); color: var(--warn); border-color: rgba(245, 158, 11, 0.24); }
    .pill.bad { background: var(--bad-soft); color: var(--bad); border-color: rgba(239, 68, 68, 0.24); }
    .pill.game { background: var(--game-soft); color: var(--game); border-color: rgba(139, 92, 246, 0.28); }

    .section { display: none; flex-direction: column; gap: 12px; }
    .section.active { display: flex; }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px 16px;
      box-shadow: var(--shadow-sm);
    }
    .card-title { margin: 0; font-size: 13.5px; font-weight: 600; letter-spacing: -0.01em; color: var(--text); }
    .card-sub { margin: 2px 0 0; font-size: 12px; color: var(--muted); }

    /* ==================== GENEL BAKIŞ BENTO DÜZENİ ==================== */
    .ov-hero {
      background: var(--surface);
      border: 1px solid var(--border);
      border-top: 2px solid var(--brand);
      border-radius: 10px;
      overflow: hidden;
      box-shadow: var(--shadow-sm);
    }
    .ov-hero.is-ok {
      border-top-color: var(--ok);
      background: linear-gradient(90deg, rgba(16, 185, 129, 0.05) 0%, var(--surface) 44%);
    }
    .ov-hero.is-warn {
      border-top-color: var(--warn);
      background: linear-gradient(90deg, rgba(245, 158, 11, 0.06) 0%, var(--surface) 44%);
    }
    .ov-hero.is-bad {
      border-top-color: var(--bad);
      background: linear-gradient(90deg, rgba(239, 68, 68, 0.06) 0%, var(--surface) 44%);
    }
    .ov-hero-main {
      padding: 13px 16px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 14px;
      align-items: center;
    }
    .hero-left { display: flex; align-items: center; gap: 14px; min-width: 0; }
    .score-ring-box {
      position: relative;
      width: 60px;
      height: 60px;
      flex: 0 0 60px;
      display: grid;
      place-items: center;
    }
    .score-ring-val {
      position: absolute;
      text-align: center;
      line-height: 1;
    }
    .score-ring-val strong {
      font-size: 17px;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
      letter-spacing: -0.02em;
      display: block;
    }
    .score-ring-val span {
      font-size: 8px;
      font-weight: 600;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      margin-top: 2px;
      display: block;
    }
    .ov-eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 10.5px;
      font-weight: 600;
      letter-spacing: 0.07em;
      text-transform: uppercase;
      color: var(--ok);
      margin-bottom: 2px;
    }
    .ov-eyebrow-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
    .ov-hero.is-warn .ov-eyebrow { color: var(--warn); }
    .ov-hero.is-bad .ov-eyebrow { color: var(--bad); }
    .ov-hero h2 {
      margin: 0 0 2px;
      font-size: 16px;
      font-weight: 600;
      letter-spacing: -0.02em;
      color: var(--text);
    }
    .ov-hero p {
      margin: 0;
      font-size: 11.5px;
      color: var(--muted);
      line-height: 1.4;
    }
    .ov-hero-actions {
      display: flex;
      flex-direction: column;
      gap: 6px;
      min-width: 174px;
    }
    .ov-autopilot-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding: 5px 10px;
      border-radius: 7px;
      background: var(--bg);
      border: 1px solid var(--border);
      font-size: 11.5px;
      font-weight: 600;
      color: var(--text);
    }
    .ov-hero-actions .btn-primary { width: 100%; height: 30px; font-size: 11.5px; }
    .ov-hero-subactions {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px;
    }
    .ov-hero-subactions .btn { width: 100%; height: 27px; padding: 0 8px; font-size: 11.5px; }

    /* Hero Alt Telemetri Şeridi */
    .ov-telemetry {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      border-top: 1px solid var(--border);
      background: var(--bg);
    }
    .ov-tel-cell {
      padding: 8px 13px;
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      gap: 1px;
      min-width: 0;
    }
    .ov-tel-cell:last-child { border-right: 0; }
    .kpi-label { font-size: 10.5px; color: var(--muted); font-weight: 500; }
    .kpi-val {
      font-size: 14px;
      font-weight: 600;
      letter-spacing: -0.015em;
      font-variant-numeric: tabular-nums;
      color: var(--text);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .kpi-val.is-alert { color: var(--warn); }
    .kpi-val.is-bad { color: var(--bad); }
    .kpi-sub {
      font-size: 10.5px;
      color: var(--muted);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      font-variant-numeric: tabular-nums;
    }

    /* 2x2 Koruma Katmanları + Fluent Anahtar + Tam Genişlik Olay Akışı */
    .ov-section-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding: 2px 2px 0;
    }
    .ov-section-title {
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--muted);
    }
    .ov-layers-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }
    .ov-layer-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 11px 13px;
      box-shadow: var(--shadow-sm);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 8px;
      cursor: pointer;
      min-width: 0;
      transition: background 0.12s ease, border-color 0.12s ease;
    }
    .ov-layer-card:hover {
      background: var(--surface-2);
      border-color: var(--border-strong);
    }
    .ov-layer-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      width: 100%;
    }
    .ov-layer-title-wrap {
      display: flex;
      align-items: center;
      gap: 9px;
      min-width: 0;
    }
    .ov-layer-foot {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding-top: 6px;
      border-top: 1px solid var(--border);
    }
    .ov-layer-link {
      font-size: 11px;
      font-weight: 500;
      color: var(--muted);
      transition: color 0.12s ease;
    }
    .ov-layer-card:hover .ov-layer-link { color: var(--brand); }
    .sw-toggle {
      position: relative;
      display: inline-block;
      width: 34px;
      height: 18px;
      flex: 0 0 34px;
      cursor: pointer;
    }
    .sw-toggle input {
      position: absolute;
      opacity: 0;
      width: 0;
      height: 0;
    }
    .sw-track {
      position: absolute;
      inset: 0;
      border-radius: 999px;
      background: var(--surface-hover);
      border: 1px solid var(--border-strong);
      transition: background 0.15s ease, border-color 0.15s ease;
    }
    .sw-track::before {
      content: "";
      position: absolute;
      width: 12px;
      height: 12px;
      left: 2px;
      top: 2px;
      border-radius: 50%;
      background: var(--text-2);
      transition: transform 0.15s ease, background 0.15s ease;
    }
    .sw-toggle input:checked + .sw-track {
      background: var(--brand);
      border-color: transparent;
    }
    .sw-toggle input:checked + .sw-track::before {
      transform: translateX(16px);
      background: #ffffff;
    }
    .ov-mod-ico {
      width: 28px;
      height: 28px;
      border-radius: 7px;
      background: var(--surface-2);
      border: 1px solid var(--border);
      color: var(--text-2);
      display: grid;
      place-items: center;
      flex: 0 0 28px;
    }
    .ov-layer-card:hover .ov-mod-ico { color: var(--brand); border-color: var(--border-strong); }
    .mod-name { font-size: 12.5px; font-weight: 600; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .mod-desc { font-size: 11px; color: var(--muted); line-height: 1.38; }

    .ov-panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      box-shadow: var(--shadow-sm);
      display: flex;
      flex-direction: column;
      overflow: hidden;
      min-width: 0;
    }
    .ov-panel-head {
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }
    .ov-panel-count {
      font-size: 11px;
      font-family: var(--mono);
      font-variant-numeric: tabular-nums;
      color: var(--muted);
    }
    .ov-feed-body { display: flex; flex-direction: column; }
    .ov-clean-state {
      padding: 12px 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .ov-clean-left { display: flex; align-items: center; gap: 11px; min-width: 0; }
    .ov-clean-ico {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      background: var(--ok-soft);
      border: 1px solid rgba(16, 185, 129, 0.24);
      color: var(--ok);
      display: grid;
      place-items: center;
      flex: 0 0 32px;
    }
    .ov-clean-title { font-size: 12.5px; font-weight: 600; color: var(--text); }
    .ov-clean-sub { font-size: 11px; color: var(--muted); line-height: 1.35; margin-top: 1px; }
    .ov-event-list { display: flex; flex-direction: column; }
    .ov-event-item {
      width: 100%;
      border: 0;
      border-bottom: 1px solid var(--border);
      background: transparent;
      color: inherit;
      font-family: inherit;
      text-align: left;
      padding: 8px 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      cursor: pointer;
      transition: background 0.12s ease;
    }
    .ov-event-item:last-child { border-bottom: 0; }
    .ov-event-item:hover { background: var(--surface-2); }
    .ov-event-left { display: flex; align-items: center; gap: 10px; min-width: 0; flex: 1; }
    .ov-event-text { min-width: 0; flex: 1; }
    .ov-event-dot { width: 7px; height: 7px; border-radius: 50%; flex: 0 0 7px; background: var(--ok); }
    .ov-event-dot.warn { background: var(--warn); }
    .ov-event-dot.bad { background: var(--bad); }
    .ov-event-title {
      font-size: 12px;
      font-weight: 500;
      color: var(--text);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .ov-event-meta {
      font-size: 10.5px;
      color: var(--muted);
      margin-top: 1px;
      font-variant-numeric: tabular-nums;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .ov-event-score {
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 600;
      color: var(--text-2);
      font-variant-numeric: tabular-nums;
      flex: 0 0 auto;
    }

    .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }

    @media (max-width: 720px) {
      .ov-hero-main { grid-template-columns: 1fr; }
      .ov-hero-actions { width: 100%; }
      .ov-telemetry { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .ov-tel-cell:nth-child(2) { border-right: 0; }
      .ov-tel-cell:nth-child(1), .ov-tel-cell:nth-child(2) { border-bottom: 1px solid var(--border); }
      .ov-layers-grid { grid-template-columns: 1fr; }
    }

    /* Butonlar & Formlar */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      height: 32px;
      padding: 0 12px;
      border-radius: 7px;
      border: 1px solid var(--border-strong);
      background: var(--surface-2);
      color: var(--text);
      font-family: inherit;
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      white-space: nowrap;
      transition: background 0.12s ease, border-color 0.12s ease, color 0.12s ease;
    }
    .btn:hover:not(:disabled) { background: var(--surface-hover); }
    .btn:disabled { opacity: 0.55; cursor: wait; }
    .btn-primary {
      background: var(--brand);
      border-color: transparent;
      color: #ffffff;
      font-weight: 600;
    }
    .btn-primary:hover:not(:disabled) { background: var(--brand-hover); }
    .btn-danger { background: var(--bad-soft); border-color: rgba(239, 68, 68, 0.28); color: var(--bad); }
    .btn-danger:hover:not(:disabled) { background: rgba(239, 68, 68, 0.20); }
    .btn-sm { height: 27px; padding: 0 10px; font-size: 11.5px; border-radius: 6px; }
    .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }

    input[type="text"], select, textarea {
      width: 100%;
      background: var(--bg);
      border: 1px solid var(--border-strong);
      border-radius: 7px;
      padding: 7px 10px;
      color: var(--text);
      font-size: 12.5px;
      font-family: inherit;
      transition: border-color 0.12s ease, box-shadow 0.12s ease;
    }
    textarea { min-height: 96px; resize: vertical; font-family: var(--mono); font-size: 12px; }
    input:focus, select:focus, textarea:focus {
      outline: none;
      border-color: var(--brand);
      box-shadow: 0 0 0 2px var(--brand-soft);
    }
    .ai-badge-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
    .ai-tag {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 2px 8px;
      border-radius: 5px;
      font-size: 11px;
      font-family: var(--mono);
      background: var(--surface-2);
      border: 1px solid var(--border);
      color: var(--text-2);
    }

    .seg {
      display: inline-flex;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 2px;
      gap: 2px;
    }
    .seg button {
      border: 0;
      background: transparent;
      color: var(--muted);
      padding: 5px 11px;
      border-radius: 6px;
      font-family: inherit;
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.12s ease, color 0.12s ease;
    }
    .seg button:hover { color: var(--text); }
    .seg button.active { background: var(--surface-2); color: var(--text); font-weight: 600; }
    .seg-sm button { padding: 4px 9px; font-size: 11px; }

    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: middle; }
    tbody tr:last-child td { border-bottom: none; }
    th {
      font-size: 10.5px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
      font-weight: 600;
    }
    tbody tr:hover { background: var(--surface-2); }
    .mono { font-family: var(--mono); font-size: 11px; word-break: break-all; font-variant-numeric: tabular-nums; }

    .chip-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 4px 9px;
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 6px;
      font-size: 11.5px;
      font-family: var(--mono);
    }
    .chip button { border: 0; background: transparent; color: var(--muted); cursor: pointer; font-weight: 700; padding: 0 2px; }
    .chip button:hover { color: var(--bad); }

    .result-box {
      margin-top: 10px;
      padding: 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--bg);
      display: none;
    }
    .result-box.show { display: block; }
    .ring-wrap { display: flex; align-items: center; gap: 12px; }

    .path-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 8px 10px;
      border-radius: 7px;
      background: var(--bg);
      border: 1px solid var(--border);
      margin-top: 8px;
    }

    .privacy-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1px;
      background: var(--border);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    .privacy-row {
      background: var(--bg);
      padding: 11px 13px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .empty-state {
      padding: 18px 12px;
      text-align: center;
      color: var(--muted);
      font-size: 12px;
      border-radius: 8px;
      background: var(--bg);
      border: 1px solid var(--border);
    }

    /* ==================== ALT DURUM ÇUBUĞU ==================== */
    .statusbar {
      height: 26px;
      flex: 0 0 26px;
      background: var(--bg-sidebar);
      border-top: 1px solid var(--border);
      padding: 0 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 11px;
      color: var(--muted);
    }
    .sb-left, .sb-right { display: flex; align-items: center; gap: 12px; }
    .sb-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--ok); display: inline-block; margin-right: 5px; }

    .toast {
      position: fixed;
      right: 16px;
      bottom: 36px;
      padding: 8px 13px;
      border-radius: 8px;
      background: var(--surface-solid);
      border: 1px solid var(--border-strong);
      color: var(--text);
      font-size: 12px;
      font-weight: 500;
      box-shadow: var(--shadow-md);
      opacity: 0;
      transform: translateY(6px);
      pointer-events: none;
      transition: opacity 0.16s ease, transform 0.16s ease;
      z-index: 999;
    }
    .toast.show { opacity: 1; transform: translateY(0); }

    @media (max-width: 680px) {
      .app-body { flex-direction: column; }
      .sidebar {
        width: 100%;
        flex: none;
        flex-direction: row;
        overflow-x: auto;
        align-items: center;
        padding: 8px;
        border-right: 0;
        border-bottom: 1px solid var(--border);
      }
      .nav { flex-direction: row; }
      .nav-section-label, .side-posture, .side-foot { display: none; }
    }
  </style>
</head>
<body data-active-tab="overview">
  <div class="app-frame" id="appFrame">
    <div class="win-resize-edge n win-native-only" data-resize="n"></div>
    <div class="win-resize-edge s win-native-only" data-resize="s"></div>
    <div class="win-resize-edge w win-native-only" data-resize="w"></div>
    <div class="win-resize-edge e win-native-only" data-resize="e"></div>
    <div class="win-resize-edge nw win-native-only" data-resize="nw"></div>
    <div class="win-resize-edge ne win-native-only" data-resize="ne"></div>
    <div class="win-resize-edge sw win-native-only" data-resize="sw"></div>
    <div class="win-resize-edge se win-native-only" data-resize="se"></div>

    <!-- ÖZEL ÇERÇEVESİZ BAŞLIK ÇUBUĞU -->
    <header class="titlebar">
      <div class="titlebar-drag" data-win-drag="1" id="titlebarDrag" title="Taşımak için sürükleyin · Çift tıklayınca büyür">
        <div class="tb-logo"><img src="__ELFSEC_LOGO__" alt="ElfSec" width="18" height="18" /></div>
        <span class="tb-title">ElfSec</span>
        <span class="tb-slash">/</span>
        <span class="tb-ver">v__ELFSEC_VERSION__</span>
      </div>
      <div class="titlebar-controls">
        <button class="tb-icon-btn" id="btnThemeToggle" title="Tema Değiştir (Açık / Koyu)">
          <svg class="ico" id="icoTheme" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"></path></svg>
        </button>
        <button class="tb-icon-btn win-native-only" id="btnWinPin" title="Her Zaman Üstte Tut">
          <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 17v5"></path><path d="M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z"></path></svg>
        </button>
        <span class="tb-sep win-native-only" id="winSep"></span>
        <button class="win-btn win-native-only" id="btnWinMin" title="Küçült">
          <svg width="11" height="11" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.3"><path d="M2 6h8"/></svg>
        </button>
        <button class="win-btn win-native-only" id="btnWinMax" title="Ekranı Kapla">
          <svg id="icoWinMax" width="10" height="10" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.3"><rect x="1.75" y="1.75" width="8.5" height="8.5" rx="1"/></svg>
        </button>
        <button class="win-btn close" id="btnWinClose" title="Kapat">
          <svg width="10" height="10" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"><path d="M2.5 2.5l7 7M9.5 2.5l-7 7"/></svg>
        </button>
      </div>
    </header>

    <!-- ANA GÖVDE -->
    <div class="app-body">
      <aside class="sidebar">
        <div class="nav-section-label">Kontrol Merkezi</div>

        <nav class="nav">
          <button class="nav-btn active" data-tab="overview">
            <span class="nav-btn-left">
              <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.6 4.8 5.4v5.9c0 4.5 3.1 8.3 7.2 9.4 4.1-1.1 7.2-4.9 7.2-9.4V5.4L12 2.6Z"></path><path d="m8.8 11.8 2.2 2.2 4.2-4.4"></path></svg>
              <span>Genel Bakış</span>
            </span>
          </button>
          <button class="nav-btn" data-tab="gamemode">
            <span class="nav-btn-left">
              <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="6" width="20" height="12" rx="4"></rect><path d="M6 12h4M8 10v4M15 11h.01M18 13h.01"></path></svg>
              <span>Oyun Modu</span>
            </span>
          </button>
          <button class="nav-btn" data-tab="scan">
            <span class="nav-btn-left">
              <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"></circle><path d="m20 20-3.5-3.5"></path></svg>
              <span>Hızlı Tarama</span>
            </span>
          </button>
          <button class="nav-btn" data-tab="ai">
            <span class="nav-btn-left">
              <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l1.9 4.6L18.5 9.5l-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9Z"></path><path d="M5 17l.9 2.1L8 20l-2.1.9L5 23l-.9-2.1L2 20l2.1-.9Z"></path><path d="M19 14l.7 1.6 1.6.7-1.6.7L19 18.6l-.7-1.6-1.6-.7 1.6-.7Z"></path></svg>
              <span>AI Güvenlik</span>
            </span>
          </button>
          <button class="nav-btn" data-tab="alerts">
            <span class="nav-btn-left">
              <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9 2.6 17.5a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"></path><path d="M12 9v4M12 17h.01"></path></svg>
              <span>Alarmlar</span>
            </span>
            <span class="nav-badge" id="navAlertsBadge">0</span>
          </button>
          <button class="nav-btn" data-tab="system">
            <span class="nav-btn-left">
              <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="12" rx="2"></rect><path d="M8 20h8M12 16v4"></path></svg>
              <span>Sistem</span>
            </span>
          </button>
        </nav>

        <div class="side-posture">
          <div class="side-posture-row">
            <span class="pulse-wrap"><span id="sidePulse" class="pulse-dot"></span><span id="sideStateTxt">Koruma Aktif</span></span>
          </div>
          <div class="side-posture-row" style="color:var(--muted);">
            <span>Oyun Modu</span>
            <span id="sideGmTxt">Otomatik</span>
          </div>
        </div>

        <div class="side-foot">
          <span>Ctrl+1–6</span>
          <span>F5 Yenile</span>
        </div>
      </aside>

      <main class="main">
        <div class="main-inner">
          <header class="topbar">
            <div>
              <h1 id="pageTitle">Genel Bakış</h1>
              <div class="topbar-sub topbar-ov-hide" id="pageSub">Gerçek zamanlı yerel koruma, oyun optimizasyonu ve tehdit özeti</div>
            </div>
            <div class="topbar-actions">
              <span class="pill topbar-ov-hide" id="pillService">Servis kontrol ediliyor</span>
              <span class="pill topbar-ov-hide" id="pillGameMode">Oyun Modu: Otomatik</span>
              <button class="btn btn-sm" id="btnRefresh">
                <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:13px;height:13px;"><path d="M21 12a9 9 0 1 1-2.64-6.36"></path><path d="M21 3v6h-6"></path></svg>
                <span>Yenile</span>
              </button>
            </div>
          </header>

          <!-- SEKME 1: GENEL BAKIŞ -->
          <section class="section active" id="tab-overview">
            <div class="ov-hero is-ok" id="heroCard">
              <div class="ov-hero-main">
                <div class="hero-left">
                  <div class="score-ring-box" id="heroScoreRing"></div>
                  <div style="min-width:0;">
                    <div class="ov-eyebrow"><span class="ov-eyebrow-dot"></span><span id="heroEyebrow">Koruma Aktif</span></div>
                    <h2 id="heroTitle">Sisteminiz Korunuyor</h2>
                    <p id="heroSub">İndirilenler, e-posta, tarayıcı ve entegre yerel AI güvenliği cihazınızda çalışır.</p>
                  </div>
                </div>
                <div class="ov-hero-actions">
                  <div class="ov-autopilot-bar">
                    <span>Otopilot Koruma</span>
                    <label class="sw-toggle" title="Tam Otomatik Korumayı Aç/Kapat">
                      <input type="checkbox" id="swAutopilot" checked />
                      <span class="sw-track"></span>
                    </label>
                  </div>
                  <button class="btn btn-primary" id="btnQuickDownloads">
                    <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px;"><path d="M12 3v12"></path><path d="m7 10 5 5 5-5"></path><path d="M5 21h14"></path></svg>
                    <span>Şimdi Tara</span>
                  </button>
                  <div class="ov-hero-subactions">
                    <button class="btn" data-jump="ai">AI Ayarları</button>
                    <button class="btn" data-jump="system">Sistem</button>
                  </div>
                </div>
              </div>

              <div class="ov-telemetry">
                <div class="ov-tel-cell">
                  <div class="kpi-label">Koruma Motoru</div>
                  <div class="kpi-val" id="statService">-</div>
                  <div class="kpi-sub" id="statHeartbeat">Kontrol ediliyor…</div>
                </div>
                <div class="ov-tel-cell">
                  <div class="kpi-label">Oyun Modu</div>
                  <div class="kpi-val" id="statGameMode">-</div>
                  <div class="kpi-sub" id="statCpuPrio">Öncelik: NORMAL</div>
                </div>
                <div class="ov-tel-cell">
                  <div class="kpi-label">Alarmlar</div>
                  <div class="kpi-val" id="statAlerts">0</div>
                  <div class="kpi-sub">Yerel günlükler</div>
                </div>
                <div class="ov-tel-cell">
                  <div class="kpi-label">Karantina</div>
                  <div class="kpi-val" id="statQuarantine">0</div>
                  <div class="kpi-sub">İzole dosya</div>
                </div>
              </div>
            </div>

            <div class="ov-section-head">
              <span class="ov-section-title">Koruma Katmanları</span>
              <span class="ov-panel-count" id="ovLayersCount">4/4 katman aktif</span>
            </div>

            <div class="ov-layers-grid" id="modStrip">
              <div class="ov-layer-card" data-jump-card="ai">
                <div class="ov-layer-top">
                  <div class="ov-layer-title-wrap">
                    <div class="ov-mod-ico">
                      <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l1.9 4.6L18.5 9.5l-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9Z"></path></svg>
                    </div>
                    <div class="mod-name">Entegre Yerel AI</div>
                  </div>
                  <label class="sw-toggle" title="Yerel AI Güvenliğini Aç/Kapat">
                    <input type="checkbox" id="swOvAi" checked />
                    <span class="sw-track"></span>
                  </label>
                </div>
                <div class="mod-desc" id="modAiDesc">Semantik ML · Hassas Veri (DLP) · Özel Kelime</div>
                <div class="ov-layer-foot">
                  <span class="pill ok" id="modAiPill">Aktif</span>
                  <span class="ov-layer-link">AI Ayarları ›</span>
                </div>
              </div>

              <div class="ov-layer-card" data-jump-card="ai">
                <div class="ov-layer-top">
                  <div class="ov-layer-title-wrap">
                    <div class="ov-mod-ico">
                      <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.6 4.8 5.4v5.9c0 4.5 3.1 8.3 7.2 9.4 4.1-1.1 7.2-4.9 7.2-9.4V5.4L12 2.6Z"></path><path d="m8.8 11.8 2.2 2.2 4.2-4.4"></path></svg>
                    </div>
                    <div class="mod-name">EXE &amp; Dosya Kalkanı</div>
                  </div>
                  <label class="sw-toggle" title="Derin PE / EXE Kalkanını Aç/Kapat">
                    <input type="checkbox" id="swOvExe" checked />
                    <span class="sw-track"></span>
                  </label>
                </div>
                <div class="mod-desc" id="modExeDesc">Packer/entropi, API enjeksiyonu, imza &amp; MotW</div>
                <div class="ov-layer-foot">
                  <span class="pill ok" id="modExePill">Derin PE</span>
                  <span class="ov-layer-link">EXE Kuralları ›</span>
                </div>
              </div>

              <div class="ov-layer-card" data-jump-card="gamemode">
                <div class="ov-layer-top">
                  <div class="ov-layer-title-wrap">
                    <div class="ov-mod-ico">
                      <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="6" width="20" height="12" rx="4"></rect><path d="M6 12h4M8 10v4M15 11h.01M18 13h.01"></path></svg>
                    </div>
                    <div class="mod-name">Akıllı Oyun Modu</div>
                  </div>
                  <label class="sw-toggle" title="Otomatik Oyun Modunu Aç/Kapat">
                    <input type="checkbox" id="swOvGm" checked />
                    <span class="sw-track"></span>
                  </label>
                </div>
                <div class="mod-desc" id="modGmDesc">Tam ekran oyunlarda ultra-düşük CPU tüketimi</div>
                <div class="ov-layer-foot">
                  <span class="pill ok" id="modGmPill">Oto</span>
                  <span class="ov-layer-link">Oyun Listesi ›</span>
                </div>
              </div>

              <div class="ov-layer-card" data-jump-card="system">
                <div class="ov-layer-top">
                  <div class="ov-layer-title-wrap">
                    <div class="ov-mod-ico">
                      <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"></circle><path d="M3.6 9h16.8M3.6 15h16.8"></path><path d="M12 3a13.5 13.5 0 0 0 0 18 13.5 13.5 0 0 0 0-18Z"></path></svg>
                    </div>
                    <div class="mod-name">Tarayıcı Köprüsü</div>
                  </div>
                  <span class="pill" id="modBrPill">Kontrol</span>
                </div>
                <div class="mod-desc" id="modBrDesc">Chrome / Edge Native Messaging bağlantısı</div>
                <div class="ov-layer-foot">
                  <span style="font-size:10.5px; color:var(--muted);" id="modBrSub">Native Host</span>
                  <span class="ov-layer-link">Köprüyü Yönet ›</span>
                </div>
              </div>
            </div>

            <div class="ov-panel">
              <div class="ov-panel-head">
                <h3 class="card-title">Son Güvenlik Olayları</h3>
                <button class="btn btn-sm" data-jump="alerts">Tümünü Gör</button>
              </div>
              <div class="ov-feed-body" id="overviewAlerts">
                <div class="ov-clean-state"><div class="ov-clean-sub">Yükleniyor…</div></div>
              </div>
            </div>
          </section>

          <!-- SEKME 2: OYUN MODU -->
          <section class="section" id="tab-gamemode">
            <div class="card">
              <div class="row" style="justify-content: space-between; margin-bottom: 12px;">
                <div>
                  <h3 class="card-title">Akıllı Oyun Modu (Ultra-Düşük Kaynak Motoru)</h3>
                  <p class="card-sub">Tam ekran (Direct3D / Borderless) veya oyun klasöründeki bir süreç algılandığında CPU, disk ve bildirim yükünü minimuma indirir.</p>
                </div>
                <span class="pill" id="gmLiveBadge">Beklemede</span>
              </div>

              <div class="row" style="justify-content: space-between; margin-top: 12px;">
                <div class="seg" id="gmModeSeg">
                  <button data-mode="auto" class="active">Otomatik</button>
                  <button data-mode="on">Her Zaman Açık</button>
                  <button data-mode="off">Kapalı</button>
                </div>
                <button class="btn" id="btnGmDetect">Algılamayı Test Et</button>
              </div>
            </div>

            <div class="grid-2">
              <div class="card">
                <h3 class="card-title" style="margin-bottom: 10px;">Oyun Sırasında Optimizasyonlar</h3>
                <table>
                  <thead><tr><th>Bileşen</th><th>Normal</th><th>Oyun Modu</th></tr></thead>
                  <tbody>
                    <tr><td>CPU Önceliği</td><td>NORMAL</td><td><strong>IDLE (En Düşük)</strong></td></tr>
                    <tr><td>İndirilenler Taraması</td><td>10 sn</td><td><strong>120 sn</strong></td></tr>
                    <tr><td>IMAP Posta Kontrolü</td><td>10 dk</td><td><strong>Ertelenir</strong></td></tr>
                    <tr><td>Bildirimler (Toast)</td><td>Anlık</td><td><strong>Oyun sonuna bekletilir</strong></td></tr>
                  </tbody>
                </table>
              </div>

              <div class="card">
                <h3 class="card-title">Özel Oyun Listesi (.exe)</h3>
                <p class="card-sub" style="margin-bottom: 10px;">Pencereli modda oynadığınız oyunların .exe adını ekleyin.</p>
                <div class="row" style="flex-wrap: nowrap;">
                  <input type="text" id="gmGameInput" placeholder="örn: minecraft.exe veya valorant.exe" />
                  <button class="btn btn-primary" id="btnAddGame">Ekle</button>
                </div>
                <div class="chip-list" id="gmCustomList"></div>
              </div>
            </div>
          </section>

          <!-- SEKME 3: HIZLI TARAMA -->
          <section class="section" id="tab-scan">
            <div class="grid-2">
              <div class="card">
                <h3 class="card-title">AI Metin / URL / Komut Analizi</h3>
                <p class="card-sub" style="margin-bottom: 10px;">Şüpheli bağlantıyı, e-posta metnini, hassas veriyi veya PowerShell/CMD komutunu yapıştırın.</p>
                <textarea id="scanTextInput" placeholder="https://... veya powershell -w hidden -enc ..."></textarea>
                <div class="row" style="margin-top: 10px;">
                  <button class="btn btn-primary" id="btnScanText">AI ile Tara</button>
                </div>
                <div class="result-box" id="scanTextResult"></div>
              </div>

              <div class="card">
                <h3 class="card-title">Dosya veya Klasör Taraması</h3>
                <p class="card-sub" style="margin-bottom: 10px;">PE (MZ) maskeleme, çift uzantı (.pdf.exe), LOLBin betik, MotW ve .eml analizi.</p>
                <div class="row" style="flex-wrap: nowrap;">
                  <input type="text" id="scanPathInput" placeholder="C:\Users\...\Downloads\dosya.pdf" />
                  <button class="btn" id="btnPickFile">Seç…</button>
                </div>
                <div class="row" style="margin-top: 10px;">
                  <button class="btn btn-primary" id="btnScanPath">Dosya / Klasör Tara</button>
                </div>
                <div class="result-box" id="scanPathResult"></div>
              </div>
            </div>
          </section>

          <!-- SEKME 4: ALARMLAR & KARANTİNA -->
          <section class="section" id="tab-alerts">
            <div class="card">
              <div class="row" style="justify-content: space-between; margin-bottom: 10px;">
                <div class="row">
                  <h3 class="card-title">Tespit Edilen Güvenlik Alarmları</h3>
                  <span class="pill" id="alertsBadge">0 kayıt</span>
                </div>
                <div class="row">
                  <div class="seg seg-sm" id="alertFilterSeg">
                    <button data-lv="ALL" class="active">Tümü</button>
                    <button data-lv="HIGH">Kritik / Yüksek</button>
                    <button data-lv="MEDIUM">Orta</button>
                    <button data-lv="LOW">Düşük</button>
                  </div>
                  <input type="text" id="alertSearch" placeholder="Ara…" style="width:150px; height:27px; padding:0 9px; font-size:12px;" />
                  <button class="btn btn-sm btn-danger" id="btnClearAlerts">Günlükleri Temizle</button>
                </div>
              </div>
              <div id="alertsTableWrap">Yükleniyor…</div>
            </div>

            <div class="card">
              <div class="row" style="justify-content: space-between; margin-bottom: 10px;">
                <h3 class="card-title">Karantina Kasası (.quarantined)</h3>
                <span class="pill" id="quarantineBadge">0 dosya</span>
              </div>
              <div id="quarantineTableWrap">Yükleniyor…</div>
            </div>
          </section>

          <!-- SEKME 5: SİSTEM & TARAYICI -->
          <section class="section" id="tab-system">
            <div class="card">
              <div class="row" style="justify-content: space-between; margin-bottom: 10px;">
                <div>
                  <h3 class="card-title">KVKK &amp; Gizlilik Denetimi</h3>
                  <p class="card-sub">Tüm AI ve güvenlik analizleri cihazınızda kalır; günlüklerde kişisel veriler maskelenir.</p>
                </div>
                <button class="btn btn-sm btn-danger" id="btnClearAlertsSys">Tüm Günlükleri Temizle</button>
              </div>
              <div class="privacy-grid">
                <div class="privacy-row">
                  <div>
                    <div class="mod-name">Sıfır Bulut / Yerel AI Kalkanı</div>
                    <div class="mod-desc">Dış/bulut API engellidir; yalnızca 127.0.0.1 loopback izinlidir.</div>
                  </div>
                  <div class="row" style="flex-wrap: nowrap;">
                    <span class="pill ok">Yalnızca 127.0.0.1</span>
                    <button class="btn btn-sm" data-jump="ai">AI Ayarları</button>
                  </div>
                </div>
                <div class="privacy-row">
                  <div>
                    <div class="mod-name">Kişisel Veri Maskeleme</div>
                    <div class="mod-desc">E-posta, TC, IBAN ve kart verileri maskelenir.</div>
                  </div>
                  <div class="row" style="flex-wrap: nowrap;">
                    <span class="pill ok" id="pillMaskPrivacy">Açık</span>
                    <button class="btn btn-sm" id="btnToggleMaskPrivacy">Kapat</button>
                  </div>
                </div>
              </div>
            </div>

            <div class="grid-2">
              <div class="card">
                <h3 class="card-title" style="margin-bottom: 10px;">Windows Eklenti Bileşenleri</h3>
                <div id="sysBadges">Yükleniyor…</div>
              </div>

              <div class="card">
                <h3 class="card-title">Tarayıcı Native Host Köprüsü</h3>
                <p class="card-sub" style="margin-bottom: 10px;">Tarayıcı uzantısı varsayılan olarak tarayıcı içinde çalışır. İsterseniz buradan isteğe bağlı Native Host manifestini kaydedebilirsiniz (Windows servisi ve otostart yalnızca ElfSecSetup veya <code>elfsec plugin install</code> ile kurulur).</p>
                <div id="browserBadges" style="margin-bottom: 8px;"></div>
                <div id="browserPairedIds" style="margin-bottom: 8px; font-size: 11px; color: var(--muted);"></div>
                <div class="row" style="flex-wrap: nowrap;">
                  <input type="text" id="extIdInput" placeholder="32 karakterlik Uzantı ID (boşsa otomatik algılanır)" />
                  <button class="btn btn-primary" id="btnPairBrowser">Şimdi Eşle</button>
                  <button class="btn" id="btnTestBrowserBridge">Test Et</button>
                </div>
                <div id="browserBridgeResult" style="margin-top: 8px; font-size: 11.5px; color: var(--muted);"></div>
              </div>
            </div>

            <div class="card">
              <div class="row" style="justify-content: space-between; margin-bottom: 10px;">
                <h3 class="card-title">Öz-Denetim (ElfSec KONTROL)</h3>
                <button class="btn btn-sm btn-primary" id="btnRunKontrol">Denetimi Çalıştır</button>
              </div>
              <div id="kontrolResult" style="font-size:12px; color:var(--muted);">Denetimi başlatmak için yukarıdaki butona tıklayın.</div>
            </div>
          </section>

          <!-- SEKME 6: AI GÜVENLİK -->
          <section class="section" id="tab-ai">
            <div class="card">
              <div class="row" style="justify-content: space-between; margin-bottom: 10px;">
                <div>
                  <h3 class="card-title">Yerel AI Güvenlik Motoru &amp; Aktif Koruma</h3>
                  <p class="card-sub">%100 çevrimdışı semantik niyet analizi, hassas veri (DLP) ve özel kelime koruması — verileriniz dışarı çıkmaz.</p>
                </div>
                <div class="row">
                  <span class="pill ok" id="aiStatePill">Aktif</span>
                  <button class="btn btn-sm" id="btnAiToggle">Kapat</button>
                </div>
              </div>

              <div class="grid-2" style="margin-top: 10px;">
                <div>
                  <div class="kpi-label" style="margin-bottom: 5px;">Motor Modu</div>
                  <div class="seg" id="aiModeSeg">
                    <button data-aimode="local_ml" class="active">Yerleşik AI</button>
                    <button data-aimode="local_llm">Yerel LLM</button>
                  </div>
                </div>
                <div>
                  <div class="kpi-label" style="margin-bottom: 5px;">Hassasiyet</div>
                  <div class="seg" id="aiSensSeg">
                    <button data-aisens="low">Düşük</button>
                    <button data-aisens="balanced" class="active">Dengeli</button>
                    <button data-aisens="strict">Sıkı</button>
                  </div>
                </div>
              </div>

              <div class="row" style="justify-content: space-between; margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border);">
                <div>
                  <div class="kpi-label" style="margin-bottom: 5px;">Tehdit Tespitinde Otomatik Koruma</div>
                  <div class="seg seg-sm" id="aiAutoQSeg">
                    <button data-qlevel="CRITICAL">Kritik: Oto-Karantina</button>
                    <button data-qlevel="HIGH">Yüksek+: Oto-Karantina</button>
                    <button data-qlevel="OFF" class="active">Yalnızca Bildir</button>
                  </div>
                </div>
                <div class="row">
                  <span class="pill ok" id="pillAiNotify">Toast Açık</span>
                  <button class="btn btn-sm" id="btnToggleAiNotify">Bildirimi Kapat</button>
                </div>
              </div>

              <div class="grid-2" style="margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border);">
                <div>
                  <div class="kpi-label" style="margin-bottom: 5px;">Masaüstü Bildirim Eşiği (Anti-Spam)</div>
                  <div class="seg seg-sm" id="aiNotifyLvlSeg">
                    <button data-nlvl="CRITICAL" class="active">Yalnızca Kritik</button>
                    <button data-nlvl="HIGH">Yüksek + Kritik</button>
                    <button data-nlvl="OFF">Sessiz</button>
                  </div>
                </div>
                <div>
                  <div class="kpi-label" style="margin-bottom: 5px;">Aynı Uyarı Bekleme Süresi</div>
                  <div class="seg seg-sm" id="aiCooldownSeg">
                    <button data-cd="60">1 dk</button>
                    <button data-cd="300" class="active">5 dk</button>
                    <button data-cd="900">15 dk</button>
                  </div>
                </div>
              </div>
            </div>

            <div class="grid-2">
              <div class="card">
                <h3 class="card-title" style="margin-bottom: 10px;">AI Algılama Modülleri</h3>
                <div class="privacy-grid">
                  <div class="privacy-row">
                    <div>
                      <div class="mod-name">Sosyal Mühendislik &amp; Oltalama</div>
                      <div class="mod-desc">Aciliyet, yetki taklidi, sahte fatura/icra bağlamı</div>
                    </div>
                    <button class="btn btn-sm" id="btnToggleAiSocial">Açık</button>
                  </div>
                  <div class="privacy-row">
                    <div>
                      <div class="mod-name">Hassas Veri Koruması (DLP)</div>
                      <div class="mod-desc">API anahtarı, IBAN, TCKN, kart, seed phrase</div>
                    </div>
                    <button class="btn btn-sm" id="btnToggleAiSensitive">Açık</button>
                  </div>
                  <div class="privacy-row">
                    <div>
                      <div class="mod-name">Betik &amp; ClickFix Niyet Analizi</div>
                      <div class="mod-desc">Obfuscation, gizli PowerShell, exfil niyeti</div>
                    </div>
                    <button class="btn btn-sm" id="btnToggleAiScript">Açık</button>
                  </div>
                </div>
              </div>

              <div class="card">
                <h3 class="card-title">Özel Güvenlik Kelimeleri &amp; Veriler</h3>
                <p class="card-sub" style="margin-bottom: 10px;">AI'ın özellikle yakalayıp uyarmasını/korumasını istediğiniz kelimeleri veya gizli kodları ekleyin.</p>
                <div class="row" style="flex-wrap: nowrap;">
                  <input type="text" id="aiKeywordInput" placeholder="örn: proje-gizli, şirket-iban, parola-kasa" />
                  <button class="btn btn-primary" id="btnAddAiKeyword">Ekle</button>
                </div>
                <div class="chip-list" id="aiKeywordList"></div>
              </div>
            </div>

            <div class="card">
              <div class="row" style="justify-content: space-between; margin-bottom: 10px;">
                <div>
                  <h3 class="card-title">Çalıştırılabilir Dosya (.EXE / PE) Güvenlik Kalkanı</h3>
                  <p class="card-sub">Virüslü, packer'lı (UPX/VMProtect), süreç enjeksiyonlu veya internetten inen imzasız .exe dosyalarını çalıştırmadan yakalar.</p>
                </div>
              </div>
              <div class="privacy-grid">
                <div class="privacy-row">
                  <div>
                    <div class="mod-name">Derin PE / EXE Statik Analizi</div>
                    <div class="mod-desc">Entropi, packer bölümü, Win32 enjeksiyon/keylogger API ve dijital imza kontrolü</div>
                  </div>
                  <button class="btn btn-sm" id="btnToggleExeDeep">Açık</button>
                </div>
                <div class="privacy-row">
                  <div>
                    <div class="mod-name">İmzasız İnternet EXE Engelleme (Sıkı)</div>
                    <div class="mod-desc">İnternetten (ZoneId=3) inen imzasız .exe dosyalarını CRITICAL sayıp oto-karantinaya alır</div>
                  </div>
                  <button class="btn btn-sm" id="btnToggleExeUnsigned">Kapalı</button>
                </div>
                <div class="privacy-row">
                  <div>
                    <div class="mod-name">Windows Defender Motoru (MpCmdRun)</div>
                    <div class="mod-desc">Yerel Defender imza veritabanı ile .exe dosyalarında çevrimdışı ek tarama</div>
                  </div>
                  <button class="btn btn-sm" id="btnToggleExeDefender">Kapalı</button>
                </div>
              </div>
            </div>

            <div class="card">
              <div class="row" style="justify-content: space-between; margin-bottom: 10px;">
                <div>
                  <h3 class="card-title">İsteğe Bağlı Yerel LLM (Yalnızca 127.0.0.1)</h3>
                  <p class="card-sub">Bilgisayarınızda çalışan Ollama veya LM Studio varsa ek semantik doğrulama için bağlanır (dış adresler engellenir).</p>
                </div>
                <button class="btn btn-sm" id="btnTestLocalLlm">Yerel LLM Algıla</button>
              </div>
              <div class="grid-2">
                <div>
                  <div class="kpi-label" style="margin-bottom: 4px;">Sağlayıcı</div>
                  <select id="aiLlmProvider">
                    <option value="ollama">Ollama (127.0.0.1:11434)</option>
                    <option value="lmstudio">LM Studio (127.0.0.1:1234)</option>
                  </select>
                </div>
                <div>
                  <div class="kpi-label" style="margin-bottom: 4px;">Yerel Adres (Loopback)</div>
                  <input type="text" id="aiLlmUrl" placeholder="http://127.0.0.1:11434" />
                </div>
              </div>
              <div class="row" style="margin-top: 8px; flex-wrap: nowrap;">
                <input type="text" id="aiLlmModel" placeholder="Model adı (örn: qwen2.5:3b veya llama3.2)" />
                <button class="btn btn-primary" id="btnSaveLlmCfg">Kaydet</button>
              </div>
              <div id="aiLlmStatus" style="margin-top: 8px; font-size: 11.5px; color: var(--muted);"></div>
            </div>

            <div class="card">
              <h3 class="card-title">Canlı AI Güvenlik Testi</h3>
              <p class="card-sub" style="margin-bottom: 10px;">Şüpheli bir e-posta, komut, hassas veri veya özel kelime girip AI kararını görün.</p>
              <textarea id="aiTestInput" placeholder="Örn: Acil fatura ödemesi için IBAN'a gönderin veya gizli kelimeniz..."></textarea>
              <div class="row" style="margin-top: 10px;">
                <button class="btn btn-primary" id="btnAiAnalyze">AI ile Analiz Et</button>
              </div>
              <div class="result-box" id="aiTestResult"></div>
            </div>
          </section>
        </div>
      </main>
    </div>

    <!-- ALT DURUM ÇUBUĞU -->
    <footer class="statusbar">
      <div class="sb-left">
        <span><span class="sb-dot"></span>Yerel Motor · 127.0.0.1</span>
        <span id="sbWindowMode">Pencere Modu: Kontrol ediliyor</span>
      </div>
      <div class="sb-right">
        <span id="sbLastSync">Canlı · 5 sn</span>
        <span>byeco</span>
      </div>
    </footer>
  </div>

  <div class="toast" id="toast"></div>

  <script>
    const TOKEN = "__ELFSEC_TOKEN__";
    const TAB_META = {
      overview: { title: "Genel Bakış", sub: "Gerçek zamanlı yerel koruma, oyun optimizasyonu ve tehdit özeti" },
      gamemode: { title: "Akıllı Oyun Modu", sub: "Tam ekran ve özel oyunlarda ultra-düşük CPU/disk tüketimi" },
      scan: { title: "Hızlı Tarama", sub: "URL, metin ve zararlı komutların yerel AI güvenlik analizi" },
      ai: { title: "Yerel AI Güvenlik", sub: "Çevrimdışı semantik tehdit, hassas veri ve özel kelime koruması" },
      alerts: { title: "Alarmlar & Karantina", sub: "Tespit edilen tehdit kayıtları ve izole edilen .quarantined kasası" },
      system: { title: "Sistem & Tarayıcı", sub: "Windows servisi, sağ-tık eklentisi ve Native Messaging köprüsü" }
    };

    let cachedAlerts = [];
    let alertLevelFilter = "ALL";

    function esc(s) {
      return String(s == null ? "" : s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }

    function fmtBytes(n) {
      const v = Number(n) || 0;
      if (v < 1024) return v + " B";
      if (v < 1024 * 1024) return (v / 1024).toFixed(1) + " KB";
      return (v / (1024 * 1024)).toFixed(2) + " MB";
    }

    function showToast(msg) {
      const el = document.getElementById("toast");
      el.textContent = msg;
      el.classList.add("show");
      clearTimeout(el._t);
      el._t = setTimeout(() => el.classList.remove("show"), 3200);
    }

    async function api(path, method = "GET", body = null) {
      const opts = { method, headers: { "X-ElfSec-Token": TOKEN } };
      if (body !== null) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(body);
      }
      const res = await fetch(path, opts);
      return await res.json();
    }

    function riskPill(level) {
      const lv = String(level || "LOW").toUpperCase();
      const cls = lv === "CRITICAL" || lv === "HIGH" ? "bad" : (lv === "MEDIUM" ? "warn" : "ok");
      return `<span class="pill ${cls}">${esc(lv)}</span>`;
    }

    function renderScoreRing(score, level) {
      const s = Math.max(0, Math.min(100, Number(score) || 0));
      const lv = String(level || "LOW").toUpperCase();
      const color = (lv === "CRITICAL" || lv === "HIGH") ? "var(--bad)" : (lv === "MEDIUM" ? "var(--warn)" : "var(--ok)");
      const r = 18;
      const c = 2 * Math.PI * r;
      const off = c - (s / 100) * c;
      return `<svg width="48" height="48" viewBox="0 0 48 48" style="flex:0 0 auto;">
        <circle cx="24" cy="24" r="${r}" fill="none" stroke="var(--border)" stroke-width="4"></circle>
        <circle cx="24" cy="24" r="${r}" fill="none" stroke="${color}" stroke-width="4"
          stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"
          stroke-linecap="round" transform="rotate(-90 24 24)"></circle>
        <text x="24" y="28" text-anchor="middle" fill="var(--text)" font-size="12" font-weight="700">${s}</text>
      </svg>`;
    }

    function renderHeroScore(score, st) {
      const s = Math.max(0, Math.min(100, Number(score) || 0));
      const color = s >= 80 ? "var(--ok)" : (s >= 55 ? "var(--warn)" : "var(--bad)");
      const r = 25;
      const c = 2 * Math.PI * r;
      const off = c - (s / 100) * c;
      document.getElementById("heroScoreRing").innerHTML = `
        <svg width="60" height="60" viewBox="0 0 60 60">
          <circle cx="30" cy="30" r="${r}" fill="none" stroke="var(--border)" stroke-width="4.5"></circle>
          <circle cx="30" cy="30" r="${r}" fill="none" stroke="${color}" stroke-width="4.5"
            stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"
            stroke-linecap="round" transform="rotate(-90 30 30)"></circle>
        </svg>
        <div class="score-ring-val"><strong>${s}</strong><span>Puan</span></div>`;

      const heroCard = document.getElementById("heroCard");
      const heroEyebrow = document.getElementById("heroEyebrow");
      const heroTitle = document.getElementById("heroTitle");
      const heroSub = document.getElementById("heroSub");
      if (!heroCard || !heroEyebrow || !heroTitle || !heroSub) return;

      const stateCls = s >= 80 ? "is-ok" : (s >= 55 ? "is-warn" : "is-bad");
      heroCard.className = "ov-hero " + stateCls;

      const info = st || {};
      const alertsCount = Number(info.alerts_count || 0);
      const activeLayers = computeActiveLayers(info);
      const ap = info.autopilot || {};
      const aiCfg = info.ai || {};
      const apOn = (ap.enabled !== false) && (aiCfg.autopilot !== false);
      if (s >= 80 && apOn) {
        heroEyebrow.textContent = "Otopilot Aktif";
        heroTitle.textContent = "Tam Otomatik Koruma Açık";
      } else if (s >= 80) {
        heroEyebrow.textContent = "Koruma Aktif";
        heroTitle.textContent = "Sisteminiz Korunuyor";
      } else if (s >= 55) {
        heroEyebrow.textContent = "Kısmi Koruma";
        heroTitle.textContent = "Temel Koruma Etkin";
      } else {
        heroEyebrow.textContent = "Dikkat Gerekiyor";
        heroTitle.textContent = "Ek Koruma Öneriliyor";
      }
      const scanTime = ap.last_scan_at ? ("Son tarama: " + String(ap.last_scan_at).slice(-8)) : "otomatik izleme hazır";
      const alertSummary = alertsCount > 0 ? `${alertsCount} yerel olay` : "tehdit yok";
      heroSub.textContent = `${activeLayers}/4 katman · ${scanTime} · ${alertSummary}`;
    }

    function computeActiveLayers(st) {
      let count = 0;
      const ai = st.ai || {};
      if (ai.enabled !== false) count += 1;
      if (ai.exe_deep_scan !== false) count += 1;
      const gm = st.game_mode || {};
      if ((gm.mode || "auto") !== "off") count += 1;
      const br = st.browser || {};
      if (Object.values(br).some(Boolean)) count += 1;
      return count;
    }

    function computePostureScore(st) {
      let score = 35;
      const ai = st.ai || {};
      const ap = st.autopilot || {};
      if (ai.enabled !== false) score += 20;
      if (ai.exe_deep_scan !== false) score += 15;
      if ((ap.enabled !== false) && (ai.autopilot !== false)) score += 15;
      const br = st.browser || {};
      if (Object.values(br).some(Boolean)) score += 10;
      const svc = st.service || {};
      if (svc.running) score += 10;
      else if (svc.installed || ap.agent_running) score += 5;
      return Math.min(100, score);
    }

    function switchTab(tab) {
      if (!TAB_META[tab]) return;
      document.body.setAttribute("data-active-tab", tab);
      document.querySelectorAll(".nav-btn").forEach(b => b.classList.toggle("active", b.dataset.tab === tab));
      document.querySelectorAll(".section").forEach(s => s.classList.toggle("active", s.id === "tab-" + tab));
      document.getElementById("pageTitle").textContent = TAB_META[tab].title;
      document.getElementById("pageSub").textContent = TAB_META[tab].sub;
    }

    document.querySelectorAll(".nav-btn").forEach(b => b.addEventListener("click", () => switchTab(b.dataset.tab)));
    document.querySelectorAll("[data-jump]").forEach(b => b.addEventListener("click", () => switchTab(b.dataset.jump)));
    document.querySelectorAll("[data-jump-card]").forEach(card => {
      card.addEventListener("click", e => {
        if (e.target.closest(".sw-toggle, input, button, a")) return;
        switchTab(card.dataset.jumpCard);
      });
    });

    /* ==================== TEMA & PENCERE KONTROLLERİ ==================== */
    function applyTheme(t) {
      document.documentElement.setAttribute("data-theme", t);
      localStorage.setItem("elfsec_ui_theme", t);
      const ico = document.getElementById("icoTheme");
      if (t === "light") {
        ico.innerHTML = '<circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"></path>';
      } else {
        ico.innerHTML = '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"></path>';
      }
    }
    applyTheme(localStorage.getItem("elfsec_ui_theme") || "dark");
    document.getElementById("btnThemeToggle").addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
      applyTheme(next);
    });

    function applyWindowState(ws) {
      const isNative = !!(ws && ws.native);
      document.querySelectorAll(".win-native-only").forEach(el => el.classList.toggle("is-hidden", !isNative));
      document.getElementById("sbWindowMode").textContent = isNative ? "Yerel Pencere" : "Tarayıcı Modu";
      document.getElementById("appFrame").classList.toggle("is-maximized", !!(ws && ws.maximized));
      const pinBtn = document.getElementById("btnWinPin");
      pinBtn.classList.toggle("is-pinned", !!(ws && ws.pinned));
      const icoMax = document.getElementById("icoWinMax");
      if (ws && ws.maximized) {
        icoMax.innerHTML = '<rect x="3" y="1.5" width="7.5" height="7.5" rx="1"/><path d="M1.5 4v6.5h6.5"/>';
        document.getElementById("btnWinMax").title = "Önceki Boyuta Döndür";
      } else {
        icoMax.innerHTML = '<rect x="1.75" y="1.75" width="8.5" height="8.5" rx="1"/>';
        document.getElementById("btnWinMax").title = "Ekranı Kapla";
      }
    }

    async function syncWindowState() {
      try {
        const ws = await api("/api/window/state");
        if (ws.ok) applyWindowState(ws);
      } catch (e) {}
    }

    document.getElementById("btnWinMin").addEventListener("click", async () => {
      const r = await api("/api/window/minimize", "POST", {});
      if (r.ok) applyWindowState(r);
    });
    document.getElementById("btnWinMax").addEventListener("click", async () => {
      const r = await api("/api/window/toggle-maximize", "POST", {});
      if (r.ok) applyWindowState(r);
    });
    document.getElementById("titlebarDrag").addEventListener("dblclick", async () => {
      const r = await api("/api/window/toggle-maximize", "POST", {});
      if (r.ok) applyWindowState(r);
    });

    (function setupWindowDragAndResize() {
      let dragging = false;
      let fallbackMoving = false;
      let startX = 0;
      let startY = 0;
      let lastX = 0;
      let lastY = 0;
      let moveInFlight = false;

      async function nativeStartDrag() {
        try {
          if (window.pywebview && window.pywebview.api && typeof window.pywebview.api.start_drag === "function") {
            const r = await window.pywebview.api.start_drag();
            if (r) applyWindowState(r);
            return r;
          }
        } catch (err) {}
        return await api("/api/window/drag-start", "POST", {});
      }

      async function nativeStartResize(edge) {
        try {
          if (window.pywebview && window.pywebview.api && typeof window.pywebview.api.start_resize === "function") {
            const r = await window.pywebview.api.start_resize(edge);
            if (r) applyWindowState(r);
            return r;
          }
        } catch (err) {}
        return await api("/api/window/resize-start", "POST", { edge });
      }

      document.querySelectorAll(".win-resize-edge[data-resize]").forEach(edgeEl => {
        edgeEl.addEventListener("mousedown", e => {
          if (e.button !== 0) return;
          e.preventDefault();
          e.stopPropagation();
          nativeStartResize(edgeEl.dataset.resize);
        });
      });

      document.querySelectorAll('[data-win-drag="1"]').forEach(el => {
        el.addEventListener("mousedown", e => {
          if (e.button !== 0 || e.detail > 1) return;
          if (e.target.closest("button, a, input, textarea, select, label")) return;
          dragging = true;
          fallbackMoving = false;
          startX = e.screenX;
          startY = e.screenY;
          lastX = e.screenX;
          lastY = e.screenY;
        });
      });

      window.addEventListener("mousemove", async e => {
        if (!dragging) return;
        if (fallbackMoving) {
          const dx = e.screenX - lastX;
          const dy = e.screenY - lastY;
          if ((dx || dy) && !moveInFlight) {
            lastX = e.screenX;
            lastY = e.screenY;
            moveInFlight = true;
            try { await api("/api/window/move", "POST", { dx, dy }); }
            finally { moveInFlight = false; }
          }
          return;
        }
        if (Math.abs(e.screenX - startX) < 2 && Math.abs(e.screenY - startY) < 2) return;
        dragging = false;
        try {
          const r = await nativeStartDrag();
          if (r) {
            applyWindowState(r);
            if (!r.started && r.native) {
              dragging = true;
              fallbackMoving = true;
              lastX = e.screenX;
              lastY = e.screenY;
            }
          }
        } catch (err) {}
      });

      window.addEventListener("mouseup", () => {
        dragging = false;
        fallbackMoving = false;
      });
    })();
    document.getElementById("btnWinPin").addEventListener("click", async () => {
      const r = await api("/api/window/pin", "POST", {});
      if (r.ok) {
        applyWindowState(r);
        showToast(r.pinned ? "Pencere üstte sabitlendi." : "Üstte sabitleme kaldırıldı.");
      }
    });
    document.getElementById("btnWinClose").addEventListener("click", async () => {
      try { await api("/api/window/close", "POST", {}); } catch (e) {}
      window.close();
    });

    /* ==================== VERİ RENDER ==================== */
    function renderGameMode(gm) {
      const mode = gm.mode || "auto";
      const active = !!gm.active;
      const proc = gm.process || "";
      const pill = document.getElementById("pillGameMode");
      const badge = document.getElementById("gmLiveBadge");
      const sideGm = document.getElementById("sideGmTxt");
      const modPill = document.getElementById("modGmPill");
      const modDesc = document.getElementById("modGmDesc");

      const swGm = document.getElementById("swOvGm");
      if (swGm) swGm.checked = (mode !== "off");

      if (active) {
        pill.className = "pill game";
        pill.textContent = "Oyun Modu: AKTİF" + (proc ? " (" + proc + ")" : "");
        badge.className = "pill game";
        badge.textContent = "DÜŞÜK GÜÇ AKTİF" + (proc ? " · " + proc : "");
        sideGm.textContent = proc || "Aktif";
        modPill.className = "pill game";
        modPill.textContent = "Aktif";
        modDesc.textContent = (proc ? proc + " · " : "") + "Düşük CPU / disk önceliği devrede";
      } else if (mode === "off") {
        pill.className = "pill";
        pill.textContent = "Oyun Modu: Kapalı";
        badge.className = "pill";
        badge.textContent = "Kapalı (Tam Koruma)";
        sideGm.textContent = "Kapalı";
        modPill.className = "pill";
        modPill.textContent = "Kapalı";
        modDesc.textContent = "Tam güvenlik tarama aralığı sabit";
      } else {
        pill.className = "pill ok";
        pill.textContent = "Oyun Modu: Otomatik";
        badge.className = "pill ok";
        badge.textContent = "Otomatik İzleme Hazır";
        sideGm.textContent = "Otomatik";
        modPill.className = "pill ok";
        modPill.textContent = "Oto";
        modDesc.textContent = "Tam ekran algılama · Öncelik: " + (gm.cpu_priority || "NORMAL");
      }

      document.getElementById("statGameMode").textContent = active ? "AKTİF" : (mode === "off" ? "Kapalı" : "Otomatik");
      document.getElementById("statCpuPrio").textContent = "Öncelik: " + (gm.cpu_priority || "NORMAL");

      document.querySelectorAll("#gmModeSeg button").forEach(b => {
        b.classList.toggle("active", b.dataset.mode === mode);
      });

      const listEl = document.getElementById("gmCustomList");
      const games = gm.custom_games || [];
      if (!games.length) {
        listEl.innerHTML = '<span style="font-size:12px; color:var(--muted);">Henüz özel oyun eklenmedi.</span>';
      } else {
        listEl.innerHTML = games.map(g =>
          `<span class="chip">${esc(g)} <button data-del-game="${esc(g)}" title="Sil">×</button></span>`
        ).join("");
        listEl.querySelectorAll("[data-del-game]").forEach(btn => {
          btn.addEventListener("click", async () => {
            const r = await api("/api/game-mode", "POST", { action: "remove_game", exe: btn.dataset.delGame });
            if (r.ok) { renderGameMode(r.game_mode); showToast("Oyun listeden çıkarıldı."); }
          });
        });
      }
    }

    const SOURCE_LABELS = {
      browser_webmail: "Webmail",
      browser_download: "Tarayıcı İndirme",
      file_watcher: "İndirilenler",
      file_scan: "Dosya Tarama",
      ai_scan: "AI Analiz",
      mail: "E-posta"
    };

    function renderPrivacy(pr) {
      const p = pr || {};
      const maskOn = p.kvkk_mask_logs !== false;
      const pMask = document.getElementById("pillMaskPrivacy");
      const bMask = document.getElementById("btnToggleMaskPrivacy");
      if (pMask && bMask) {
        pMask.className = "pill " + (maskOn ? "ok" : "warn");
        pMask.textContent = maskOn ? "Açık" : "Kapalı";
        bMask.textContent = maskOn ? "Kapat" : "Aç";
      }
    }

    function renderOverviewFeedHtml(rows) {
      if (!rows.length) {
        return `<div class="ov-clean-state">
          <div class="ov-clean-left">
            <div class="ov-clean-ico">
              <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.6 4.8 5.4v5.9c0 4.5 3.1 8.3 7.2 9.4 4.1-1.1 7.2-4.9 7.2-9.4V5.4L12 2.6Z"></path><path d="m8.8 11.8 2.2 2.2 4.2-4.4"></path></svg>
            </div>
            <div>
              <div class="ov-clean-title">Tehdit tespit edilmedi</div>
              <div class="ov-clean-sub">Yerel günlükler temiz · Yeni .exe ve dosya indirmeleri otomatik taranır.</div>
            </div>
          </div>
          <button type="button" class="btn btn-sm" data-jump-scan="1">Dosya Tara</button>
        </div>`;
      }
      return `<div class="ov-event-list">` + rows.map(r => {
        const lv = String(r.risk_level || "LOW").toUpperCase();
        const dotCls = (lv === "CRITICAL" || lv === "HIGH") ? "bad" : (lv === "MEDIUM" ? "warn" : "");
        const srcRaw = r.source || "mail";
        const srcLbl = SOURCE_LABELS[srcRaw] || srcRaw;
        const when = r.alerted_at || r.analyzed_at || r.date || "-";
        const title = r.subject || r.file || r.preview || r.summary || "-";
        return `<button type="button" class="ov-event-item" data-jump-alert="1">
          <div class="ov-event-left">
            <span class="ov-event-dot ${dotCls}"></span>
            <div class="ov-event-text">
              <div class="ov-event-title">${esc(title)}</div>
              <div class="ov-event-meta">${esc(srcLbl)} · ${esc(when)}</div>
            </div>
          </div>
          <span class="ov-event-score">${esc(r.risk_score ?? "-")}/100</span>
        </button>`;
      }).join("") + `</div>`;
    }

    function renderAlertRowsHtml(rows) {
      if (!rows.length) return '<div class="empty-state">Kriterlere uyan güvenlik alarmı kaydı yok.</div>';
      return `<table><thead><tr><th>Zaman</th><th>Seviye</th><th>Skor</th><th>Kaynak</th><th>Detay</th></tr></thead><tbody>` +
        rows.map(r => {
          const srcRaw = r.source || "mail";
          const srcLbl = SOURCE_LABELS[srcRaw] || srcRaw;
          return `<tr>
          <td class="mono">${esc(r.alerted_at || r.analyzed_at || r.date || "-")}</td>
          <td>${riskPill(r.risk_level)}</td>
          <td style="font-variant-numeric:tabular-nums;"><strong>${esc(r.risk_score ?? "-")}/100</strong></td>
          <td>${esc(srcLbl)}</td>
          <td>${esc(r.subject || r.file || r.preview || r.summary || "-")}</td>
        </tr>`;
        }).join("") + `</tbody></table>`;
    }

    function applyAlertsFilter() {
      const q = (document.getElementById("alertSearch").value || "").trim().toLowerCase();
      const filtered = cachedAlerts.filter(r => {
        const lv = String(r.risk_level || "LOW").toUpperCase();
        if (alertLevelFilter === "HIGH" && lv !== "CRITICAL" && lv !== "HIGH") return false;
        if (alertLevelFilter === "MEDIUM" && lv !== "MEDIUM") return false;
        if (alertLevelFilter === "LOW" && lv !== "LOW") return false;
        if (!q) return true;
        const hay = [r.subject, r.file, r.preview, r.summary, r.source].map(x => String(x || "")).join(" ").toLowerCase();
        return hay.includes(q);
      });
      document.getElementById("alertsBadge").textContent = filtered.length + " / " + cachedAlerts.length + " kayıt";
      document.getElementById("alertsTableWrap").innerHTML = renderAlertRowsHtml(filtered);
    }

    async function refreshAll() {
      const [st, al, qr] = await Promise.all([
        api("/api/status"),
        api("/api/alerts"),
        api("/api/quarantine")
      ]);
      if (st.ok) {
        const svc = st.service || {};
        const pSvc = document.getElementById("pillService");
        const pulse = document.getElementById("sidePulse");
        const sideState = document.getElementById("sideStateTxt");
        const gmActive = !!(st.game_mode && st.game_mode.active);

        if (svc.running) {
          pSvc.className = "pill ok";
          pSvc.textContent = "Servis: ÇALIŞIYOR";
          sideState.textContent = gmActive ? "Oyun Modu" : "Koruma Aktif";
          pulse.className = "pulse-dot" + (gmActive ? " game" : "");
        } else if (svc.installed) {
          pSvc.className = "pill warn";
          pSvc.textContent = "Servis: " + (svc.state || "DURMUŞ");
          sideState.textContent = "Servis Durmuş";
          pulse.className = "pulse-dot warn";
        } else {
          pSvc.className = "pill warn";
          pSvc.textContent = "Tekil Mod";
          sideState.textContent = gmActive ? "Oyun Modu" : "Panel Hazır";
          pulse.className = "pulse-dot" + (gmActive ? " game" : " warn");
        }

        renderHeroScore(computePostureScore(st), st);
        const layersEl = document.getElementById("ovLayersCount");
        if (layersEl) layersEl.textContent = computeActiveLayers(st) + "/4 katman aktif";

        const ap = st.autopilot || {};
        const apOn = (ap.enabled !== false) && ((st.ai || {}).autopilot !== false);
        const swAp = document.getElementById("swAutopilot");
        if (swAp) swAp.checked = apOn;

        document.getElementById("statService").textContent = svc.running
          ? "Servis + Oto"
          : (apOn ? "Otomatik" : "Manuel");
        document.getElementById("statHeartbeat").textContent = svc.running
          ? ("Son: " + (svc.heartbeat ? String(svc.heartbeat).slice(-8) : "aktif"))
          : (apOn ? (ap.last_scan_at ? ("Son tarama: " + String(ap.last_scan_at).slice(-8)) : "Arka plan aktif") : "Otopilot kapalı");

        const alertsCount = Number(st.alerts_count || 0);
        const quarCount = Number(st.quarantine_count || 0);
        const elAlerts = document.getElementById("statAlerts");
        elAlerts.textContent = String(alertsCount);
        elAlerts.className = "kpi-val" + (alertsCount > 0 ? " is-alert" : "");

        const elQuar = document.getElementById("statQuarantine");
        elQuar.textContent = String(quarCount);
        elQuar.className = "kpi-val" + (quarCount > 0 ? " is-bad" : "");

        document.getElementById("navAlertsBadge").textContent = String(alertsCount + quarCount);
        renderGameMode(st.game_mode || {});
        renderPrivacy(st.privacy || {});
        renderAiSettings(st.ai || {});

        const br = st.browser || {};
        const brNames = Object.entries(br).filter(([, v]) => Boolean(v)).map(([k]) => k.toUpperCase());
        const brCount = brNames.length;
        const brPill = document.getElementById("modBrPill");
        brPill.className = "pill " + (brCount ? "ok" : "warn");
        brPill.textContent = brCount ? `${brCount} Bağlı` : "Eşlenmedi";
        document.getElementById("modBrDesc").textContent = brCount
          ? `${brNames.join(" · ")} uzantı koruması aktif`
          : "Sistem sekmesinden tarayıcı eşleyin";
        const brSub = document.getElementById("modBrSub");
        if (brSub) brSub.textContent = brCount ? "Native Host Hazır" : "Bağlantı Bekliyor";

        document.getElementById("sysBadges").innerHTML = `
          <div class="row" style="margin-bottom:8px;">
            <span class="pill ${st.context_menu_files ? 'ok' : 'warn'}">Sağ-Tık Dosya: ${st.context_menu_files ? 'Hazır' : 'Eksik'}</span>
            <span class="pill ${st.context_menu_dirs ? 'ok' : 'warn'}">Sağ-Tık Klasör: ${st.context_menu_dirs ? 'Hazır' : 'Eksik'}</span>
            <span class="pill ${st.agent_autostart ? 'ok' : 'warn'}">Otomatik Başlatma: ${st.agent_autostart ? 'Açık' : 'Kapalı'}</span>
            <span class="pill ${st.protocol_registered ? 'ok' : 'warn'}">elfsec:// Protokolü: ${st.protocol_registered ? 'Kayıtlı' : 'Eksik'}</span>
          </div>
          <div class="path-row">
            <div><div style="font-size:10.5px; color:var(--muted);">Veri Dizini</div><div class="mono">${esc(st.machine_data_dir)}</div></div>
            <button class="btn btn-sm" data-copy="${esc(st.machine_data_dir)}">Kopyala</button>
          </div>
          <div class="path-row">
            <div><div style="font-size:10.5px; color:var(--muted);">Yapılandırma Dosyası</div><div class="mono">${esc(st.config_file)}</div></div>
            <button class="btn btn-sm" data-copy="${esc(st.config_file)}">Kopyala</button>
          </div>
        `;
        document.querySelectorAll("[data-copy]").forEach(btn => {
          btn.addEventListener("click", async () => {
            try { await navigator.clipboard.writeText(btn.dataset.copy); showToast("Yol panoya kopyalandı."); }
            catch (e) { showToast("Kopyalanamadı."); }
          });
        });

        document.getElementById("browserBadges").innerHTML = ["chrome", "edge", "brave", "firefox"].map(b =>
          `<span class="pill ${br[b] ? 'ok' : ''}" style="margin-right:6px; margin-bottom:6px;">${b.toUpperCase()}: ${br[b] ? 'Bağlı' : 'Bağlı Değil'}</span>`
        ).join("");
        const bb = st.browser_bridge || {};
        const paired = bb.extension_ids || [];
        const pairedEl = document.getElementById("browserPairedIds");
        if (pairedEl) {
          pairedEl.innerHTML = paired.length
            ? `Eşlenen uzantı kimlikleri: <span class="mono">${paired.map(esc).join(", ")}</span>`
            : "Henüz kayıtlı uzantı manifesti yok; otomatik keşif için eşleyin.";
        }
      }

      if (al.ok) {
        cachedAlerts = al.alerts || [];
        const ovAlerts = document.getElementById("overviewAlerts");
        ovAlerts.innerHTML = renderOverviewFeedHtml(cachedAlerts.slice(0, 3));
        ovAlerts.querySelectorAll("[data-jump-alert]").forEach(btn => {
          btn.addEventListener("click", () => switchTab("alerts"));
        });
        ovAlerts.querySelectorAll("[data-jump-scan]").forEach(btn => {
          btn.addEventListener("click", () => switchTab("scan"));
        });
        applyAlertsFilter();
      }

      if (qr.ok) {
        const items = qr.items || [];
        document.getElementById("quarantineBadge").textContent = items.length + " dosya";
        if (!items.length) {
          document.getElementById("quarantineTableWrap").innerHTML = '<div class="empty-state">Karantina kasası temiz.</div>';
        } else {
          document.getElementById("quarantineTableWrap").innerHTML =
            `<table><thead><tr><th>Dosya</th><th>Boyut</th><th>Tarih</th><th>İşlem</th></tr></thead><tbody>` +
            items.map(it => `<tr>
              <td>
                <div><strong>${esc(it.name)}</strong></div>
                ${it.original_path ? `<div class="mono" style="color:var(--muted);">Orijinal: ${esc(it.original_path)}</div>` : `<div class="mono" style="color:var(--muted);">${esc(it.path)}</div>`}
              </td>
              <td>${fmtBytes(it.size)}</td>
              <td class="mono">${esc(it.modified_at)}</td>
              <td class="row">
                <button class="btn btn-sm" data-qact="restore" data-qpath="${esc(it.path)}">Geri Yükle</button>
                <button class="btn btn-sm btn-danger" data-qact="delete" data-qpath="${esc(it.path)}">Kalıcı Sil</button>
              </td>
            </tr>`).join("") + `</tbody></table>`;
          document.querySelectorAll("[data-qact]").forEach(btn => {
            btn.addEventListener("click", async () => {
              const r = await api("/api/quarantine/action", "POST", { action: btn.dataset.qact, path: btn.dataset.qpath });
              if (r.ok) {
                const msg = r.restored_to ? ("Orijinal konumuna geri yüklendi: " + r.restored_to) : "Karantina işlemi tamamlandı.";
                showToast(msg);
                refreshAll();
              }
              else showToast("Hata: " + (r.error || "işlem başarısız"));
            });
          });
        }
      }
      document.getElementById("sbLastSync").textContent = "Güncel · " + new Date().toLocaleTimeString("tr-TR");
    }

    document.getElementById("btnRefresh").addEventListener("click", () => { refreshAll(); showToast("Yenilendi"); });

    async function clearAllAlertLogs() {
      const r = await api("/api/alerts/clear", "POST", {});
      if (r.ok) { showToast("Alarm günlükleri temizlendi."); refreshAll(); }
    }
    document.getElementById("btnClearAlerts").addEventListener("click", clearAllAlertLogs);
    document.getElementById("btnClearAlertsSys").addEventListener("click", clearAllAlertLogs);

    document.getElementById("btnToggleMaskPrivacy").addEventListener("click", async () => {
      const cur = document.getElementById("pillMaskPrivacy").textContent === "Açık";
      const r = await api("/api/privacy", "POST", { kvkk_mask_logs: !cur });
      if (r.ok) {
        renderPrivacy(r.privacy);
        showToast(!cur ? "Günlüklerde KVKK veri maskeleme açıldı." : "Günlük maskeleme kapatıldı.");
      }
    });

    document.querySelectorAll("#alertFilterSeg button").forEach(btn => {
      btn.addEventListener("click", () => {
        alertLevelFilter = btn.dataset.lv;
        document.querySelectorAll("#alertFilterSeg button").forEach(b => b.classList.toggle("active", b === btn));
        applyAlertsFilter();
      });
    });
    document.getElementById("alertSearch").addEventListener("input", applyAlertsFilter);

    document.querySelectorAll("#gmModeSeg button").forEach(btn => {
      btn.addEventListener("click", async () => {
        const r = await api("/api/game-mode", "POST", { action: "set_mode", mode: btn.dataset.mode });
        if (r.ok) { renderGameMode(r.game_mode); showToast("Oyun modu güncellendi."); }
      });
    });
    document.getElementById("btnGmDetect").addEventListener("click", async () => {
      const r = await api("/api/game-mode", "POST", { action: "detect" });
      if (r.ok) { renderGameMode(r.game_mode); showToast(r.game_mode.active ? "Oyun algılandı!" : "Ön planda oyun yok."); }
    });
    async function addCustomGame() {
      const inp = document.getElementById("gmGameInput");
      const exe = inp.value.trim();
      if (!exe) return;
      const r = await api("/api/game-mode", "POST", { action: "add_game", exe });
      if (r.ok) { inp.value = ""; renderGameMode(r.game_mode); showToast("Oyun eklendi."); }
      else showToast(r.error || "Eklenemedi");
    }
    document.getElementById("btnAddGame").addEventListener("click", addCustomGame);
    document.getElementById("gmGameInput").addEventListener("keydown", e => { if (e.key === "Enter") addCustomGame(); });

    document.getElementById("btnQuickDownloads").addEventListener("click", async () => {
      showToast("İndirilenler taranıyor…");
      const r = await api("/api/scan/downloads", "POST", { notify: true });
      if (r.ok) {
        const n = (r.alerts || []).length;
        const aq = Number(r.auto_protected_count || 0);
        const extra = aq > 0 ? `, ${aq} otomatik karantina` : "";
        showToast(`${r.scanned_count} yeni dosya tarandı, ${n} tehdit bulundu${extra}.`);
        refreshAll();
      }
    });

    function buildAiTagsHtml(ai) {
      if (!ai || !ai.enabled) return "";
      const tags = [];
      if (ai.category && ai.category !== "benign") {
        tags.push(`<span class="ai-tag">AI: ${esc(ai.category_tr || ai.category)} (%${Math.round((ai.confidence || 0) * 100)})</span>`);
      }
      (ai.keyword_hits || []).forEach(kw => {
        tags.push(`<span class="ai-tag">Kelime: ${esc(kw)}</span>`);
      });
      (ai.sensitive_hits || []).forEach(sh => {
        tags.push(`<span class="ai-tag">DLP: ${esc(sh.label)} (${esc(sh.masked_sample)})</span>`);
      });
      return tags.length ? `<div class="ai-badge-row">${tags.join("")}</div>` : "";
    }

    function buildPeTagsHtml(pe) {
      if (!pe) return "";
      const tags = [];
      if (pe.valid_pe) {
        tags.push(`<span class="ai-tag">${pe.has_authenticode ? "PE: İmzalı" : "PE: İmzasız"}</span>`);
        if (pe.max_entropy) {
          tags.push(`<span class="ai-tag">Entropi: ${esc(Number(pe.max_entropy).toFixed(2))}</span>`);
        }
      }
      (pe.packers || []).forEach(pk => {
        tags.push(`<span class="ai-tag">Packer: ${esc(pk)}</span>`);
      });
      (pe.api_families || []).forEach(fam => {
        tags.push(`<span class="ai-tag">API: ${esc(fam.label || fam.family)}</span>`);
      });
      (pe.keyword_hits || []).forEach(kw => {
        tags.push(`<span class="ai-tag">PE Kelime: ${esc(kw)}</span>`);
      });
      if (pe.defender && pe.defender.checked) {
        tags.push(`<span class="ai-tag">${pe.defender.infected ? "Defender: " + esc(pe.defender.threat_name || "Tehdit") : "Defender: Temiz"}</span>`);
      }
      return tags.length ? `<div class="ai-badge-row">${tags.join("")}</div>` : "";
    }

    function renderAiSettings(ai) {
      const cfg = ai || {};
      const enabled = cfg.enabled !== false;
      const statePill = document.getElementById("aiStatePill");
      const toggleBtn = document.getElementById("btnAiToggle");
      const modAiPill = document.getElementById("modAiPill");
      const modAiDesc = document.getElementById("modAiDesc");
      if (statePill && toggleBtn) {
        statePill.className = "pill " + (enabled ? "ok" : "");
        statePill.textContent = enabled ? "Aktif" : "Kapalı";
        toggleBtn.textContent = enabled ? "Kapat" : "Aç";
      }
      const swAi = document.getElementById("swOvAi");
      if (swAi) swAi.checked = enabled;
      const kws = cfg.custom_keywords || [];
      if (modAiPill && modAiDesc) {
        modAiPill.className = "pill " + (enabled ? "ok" : "");
        modAiPill.textContent = enabled ? "Aktif" : "Kapalı";
        modAiDesc.textContent = enabled
          ? `${cfg.mode === "local_llm" ? "Yerel LLM" : "Yerleşik ML"} · DLP · ${kws.length} özel kelime`
          : "Yerel AI koruma devre dışı";
      }

      const mode = cfg.mode || "local_ml";
      document.querySelectorAll("#aiModeSeg button").forEach(b => b.classList.toggle("active", b.dataset.aimode === mode));
      const sens = cfg.sensitivity || "balanced";
      document.querySelectorAll("#aiSensSeg button").forEach(b => b.classList.toggle("active", b.dataset.aisens === sens));
      const qLevel = cfg.auto_quarantine_level || "OFF";
      document.querySelectorAll("#aiAutoQSeg button").forEach(b => b.classList.toggle("active", b.dataset.qlevel === qLevel));

      const nLvl = String(cfg.notify_min_level || "CRITICAL").toUpperCase();
      document.querySelectorAll("#aiNotifyLvlSeg button").forEach(b => b.classList.toggle("active", b.dataset.nlvl === nLvl));
      const cdSec = String(cfg.notify_cooldown_sec || 300);
      document.querySelectorAll("#aiCooldownSeg button").forEach(b => b.classList.toggle("active", b.dataset.cd === cdSec));

      const pNotif = document.getElementById("pillAiNotify");
      const bNotif = document.getElementById("btnToggleAiNotify");
      const nOn = (cfg.notify_on_ai_alert !== false) && (nLvl !== "OFF");
      if (pNotif && bNotif) {
        pNotif.className = "pill " + (nOn ? "ok" : "");
        pNotif.textContent = nOn ? "Toast Açık" : "Toast Kapalı";
        bNotif.textContent = nOn ? "Bildirimi Kapat" : "Bildirimi Aç";
      }

      const setModBtn = (id, on) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = on ? "Açık" : "Kapalı";
        el.className = "btn btn-sm" + (on ? " btn-primary" : "");
      };
      setModBtn("btnToggleAiSocial", cfg.detect_social_engineering !== false);
      setModBtn("btnToggleAiSensitive", cfg.detect_sensitive_data !== false);
      setModBtn("btnToggleAiScript", cfg.detect_script_intent !== false);
      setModBtn("btnToggleExeDeep", cfg.exe_deep_scan !== false);
      setModBtn("btnToggleExeUnsigned", !!cfg.exe_block_unsigned_downloads);
      setModBtn("btnToggleExeDefender", !!cfg.exe_defender_scan);

      const modExePill = document.getElementById("modExePill");
      const modExeDesc = document.getElementById("modExeDesc");
      const swExe = document.getElementById("swOvExe");
      const deepOn = cfg.exe_deep_scan !== false;
      if (swExe) swExe.checked = deepOn;
      if (modExePill && modExeDesc) {
        const strictOn = !!cfg.exe_block_unsigned_downloads;
        const defOn = !!cfg.exe_defender_scan;
        modExePill.className = "pill " + (deepOn ? "ok" : "warn");
        modExePill.textContent = !deepOn ? "Temel" : (strictOn ? "Sıkı Mod" : "Derin PE");
        if (!deepOn) {
          modExeDesc.textContent = "Yalnızca uzantı ve MotW kontrolü";
        } else {
          const extras = ["Entropi/API", "İmza/MotW"];
          if (strictOn) extras.push("İmzasız Blok");
          if (defOn) extras.push("Defender");
          modExeDesc.textContent = extras.join(" · ");
        }
      }

      const kwWrap = document.getElementById("aiKeywordList");
      if (kwWrap) {
        if (!kws.length) {
          kwWrap.innerHTML = '<span style="font-size:12px; color:var(--muted);">Henüz özel güvenlik kelimesi eklenmedi.</span>';
        } else {
          kwWrap.innerHTML = kws.map(k =>
            `<span class="chip">${esc(k)} <button data-del-aikw="${esc(k)}" title="Sil">×</button></span>`
          ).join("");
          kwWrap.querySelectorAll("[data-del-aikw]").forEach(btn => {
            btn.addEventListener("click", async () => {
              const r = await api("/api/ai/settings", "POST", { action: "remove_keyword", keyword: btn.dataset.delAikw });
              if (r.ok) { renderAiSettings(r.ai); showToast("Özel kelime silindi."); }
            });
          });
        }
      }

      const provEl = document.getElementById("aiLlmProvider");
      const urlEl = document.getElementById("aiLlmUrl");
      const modEl = document.getElementById("aiLlmModel");
      if (provEl && document.activeElement !== provEl) provEl.value = cfg.llm_provider || "ollama";
      if (urlEl && document.activeElement !== urlEl) urlEl.value = cfg.llm_url || "http://127.0.0.1:11434";
      if (modEl && document.activeElement !== modEl) modEl.value = cfg.llm_model || "";
    }

    async function saveAiPatch(patch, toastMsg) {
      const r = await api("/api/ai/settings", "POST", patch);
      if (r.ok) {
        renderAiSettings(r.ai);
        if (toastMsg) showToast(toastMsg);
      } else {
        showToast(r.error || "Ayar kaydedilemedi");
      }
    }

    function showTextReport(rep) {
      const box = document.getElementById("scanTextResult");
      box.classList.add("show");
      const reasons = (rep.reasons || []).map(x => `<li>${esc(x)}</li>`).join("");
      box.innerHTML = `<div class="ring-wrap">
          ${renderScoreRing(rep.risk_score, rep.risk_level)}
          <div>
            <div class="row">${riskPill(rep.risk_level)}<strong>Skor: ${esc(rep.risk_score)}/100</strong></div>
            <div style="margin-top:5px; font-size:12.5px;">${esc(rep.summary)}</div>
          </div>
        </div>
        ${buildAiTagsHtml(rep.ai_analysis)}
        ${reasons ? `<ul style="margin:8px 0 0 18px; font-size:12px; color:var(--text-2);">${reasons}</ul>` : ""}`;
    }

    document.getElementById("btnScanText").addEventListener("click", async () => {
      const txt = document.getElementById("scanTextInput").value;
      const r = await api("/api/scan/text", "POST", { text: txt });
      if (r.ok) showTextReport(r.report);
      else showToast(r.error || "Tarama hatası");
    });

    document.getElementById("btnPickFile").addEventListener("click", async () => {
      const r = await api("/api/pick-file", "POST", {});
      if (r.ok && r.path) document.getElementById("scanPathInput").value = r.path;
    });

    async function runPathScan() {
      const p = document.getElementById("scanPathInput").value.trim();
      const r = await api("/api/scan/path", "POST", { path: p });
      const box = document.getElementById("scanPathResult");
      box.classList.add("show");
      if (!r.ok) {
        box.innerHTML = `<span class="pill bad">Hata</span> ${esc(r.error)}`;
        return;
      }
      const rows = r.reports || [];
      box.innerHTML = rows.map(rep => {
        const canQ = rep.risk_score >= 25 && rep.file && !rep.auto_protected;
        return `<div style="padding:9px 0; border-bottom:1px solid var(--border);" class="ring-wrap">
          ${renderScoreRing(rep.risk_score, rep.risk_level)}
          <div style="flex:1; min-width:0;">
            <div class="row" style="justify-content:space-between;">
              <strong>${esc(rep.filename || rep.file)}</strong>
              <div class="row">${riskPill(rep.risk_level)}
                ${rep.auto_protected ? '<span class="pill bad">Oto-Karantina</span>' : ""}
                ${canQ ? `<button class="btn btn-sm btn-danger" data-qfile="${esc(rep.file)}">Karantinaya Al</button>` : ""}
              </div>
            </div>
            ${buildAiTagsHtml(rep.ai_analysis)}
            ${buildPeTagsHtml(rep.pe_analysis)}
            <div style="font-size:11.5px; color:var(--muted); margin-top:4px;">${(rep.reasons || []).map(esc).join(" · ")}</div>
          </div>
        </div>`;
      }).join("");
      box.querySelectorAll("[data-qfile]").forEach(btn => {
        btn.addEventListener("click", async () => {
          const qr = await api("/api/quarantine/action", "POST", { action: "quarantine", path: btn.dataset.qfile });
          if (qr.ok) { showToast("Dosya karantinaya alındı."); refreshAll(); }
          else showToast(qr.error || "Karantina başarısız");
        });
      });
    }
    document.getElementById("btnScanPath").addEventListener("click", runPathScan);
    document.getElementById("scanPathInput").addEventListener("keydown", e => { if (e.key === "Enter") runPathScan(); });

    document.getElementById("btnPairBrowser").addEventListener("click", async () => {
      const extId = document.getElementById("extIdInput").value.trim();
      const resEl = document.getElementById("browserBridgeResult");
      if (resEl) resEl.textContent = "Tarayıcı köprüsü ve Windows sistem kayıtları işleniyor…";
      const r = await api("/api/browser/register", "POST", {
        extension_id: extId,
        user_only: true,
        integrate_system: false,
        run_self_test: true
      });
      if (r.ok) {
        const ids = (r.extension_ids || []).length;
        const stOk = !!(r.self_test && r.self_test.ok);
        if (resEl) {
          resEl.innerHTML = `<span class="pill ok">Sisteme İşlendi</span> `
            + `<span class="pill ${stOk ? 'ok' : 'warn'}">Ping: ${stOk ? 'Yanıt Alındı' : esc((r.self_test && r.self_test.error) || 'Beklemede')}</span> `
            + `<span style="margin-left:4px;">${ids} uzantı kimliği + ${esc(r.registry_entries || 0)} sistem kaydı yazıldı.</span>`;
        }
        showToast("Tarayıcı köprüsü ve Windows sistemi tamamen eşlendi!");
        refreshAll();
      } else {
        if (resEl) resEl.textContent = "Hata: " + (r.error || "eşlenemedi");
        showToast("Hata: " + (r.error || "eşlenemedi"));
      }
    });

    document.getElementById("btnTestBrowserBridge").addEventListener("click", async () => {
      const resEl = document.getElementById("browserBridgeResult");
      if (resEl) resEl.textContent = "Canlı stdio ping testi yapılıyor…";
      const r = await api("/api/browser/test", "POST", {});
      const st = (r && r.self_test) || {};
      if (r.ok && st.ok) {
        const resp = st.response || {};
        if (resEl) {
          resEl.innerHTML = `<span class="pill ok">Köprü Aktif</span> v${esc(resp.version || "?")} · AI: ${resp.ai_enabled ? "Açık" : "Kapalı"} · EXE: ${resp.exe_deep_scan ? "Derin PE" : "Temel"}`;
        }
        showToast("Tarayıcı köprüsü testi başarılı!");
      } else {
        if (resEl) resEl.textContent = "Test başarısız: " + (st.error || r.error || "yanıt yok");
        showToast("Köprü yanıt vermedi.");
      }
    });

    document.getElementById("btnRunKontrol").addEventListener("click", async () => {
      const el = document.getElementById("kontrolResult");
      el.textContent = "Denetim çalıştırılıyor…";
      const r = await api("/api/kontrol");
      if (!r.ok) { el.textContent = "Denetim başarısız."; return; }
      const rep = r.report;
      const fails = (rep.bulgular || []).filter(b => b.durum === "FAIL" || b.durum === "WARN");
      el.innerHTML = `<div class="row" style="margin-bottom:8px;">
        <span class="pill ${rep.fail ? 'bad' : 'ok'}">Sonuç: ${esc(rep.worst)}</span>
        <span class="pill">Toplam: ${esc(rep.toplam)}</span>
        <span class="pill ${rep.fail ? 'bad' : 'ok'}">FAIL: ${esc(rep.fail)}</span>
        <span class="pill ${rep.warn ? 'warn' : 'ok'}">WARN: ${esc(rep.warn)}</span>
      </div>` + (fails.length ? fails.map(f => `<div class="mono" style="margin-top:4px;">${esc(f.id)}: ${esc(f.baslik)} — ${esc(f.detay)}</div>`).join("") : "<div>Tüm güvenlik kontrolleri başarılı.</div>");
    });

    document.getElementById("btnAiToggle").addEventListener("click", () => {
      const cur = document.getElementById("aiStatePill").textContent === "Aktif";
      saveAiPatch({ enabled: !cur }, !cur ? "Yerel AI güvenlik motoru açıldı." : "Yerel AI güvenlik motoru kapatıldı.");
    });
    document.querySelectorAll("#aiModeSeg button").forEach(btn => {
      btn.addEventListener("click", () => saveAiPatch({ mode: btn.dataset.aimode }, "AI motor modu güncellendi."));
    });
    document.querySelectorAll("#aiSensSeg button").forEach(btn => {
      btn.addEventListener("click", () => saveAiPatch({ sensitivity: btn.dataset.aisens }, "AI hassasiyeti güncellendi."));
    });
    document.querySelectorAll("#aiAutoQSeg button").forEach(btn => {
      btn.addEventListener("click", () => saveAiPatch({
        auto_protect: btn.dataset.qlevel !== "OFF",
        auto_quarantine_level: btn.dataset.qlevel
      }, "Otomatik koruma eşiği güncellendi."));
    });
    document.getElementById("btnToggleAiNotify").addEventListener("click", () => {
      const cur = document.getElementById("pillAiNotify").textContent === "Toast Açık";
      saveAiPatch({ notify_on_ai_alert: !cur }, !cur ? "AI bildirimleri açıldı." : "AI bildirimleri kapatıldı.");
    });
    document.querySelectorAll("#aiNotifyLvlSeg button").forEach(btn => {
      btn.addEventListener("click", () => saveAiPatch({ notify_min_level: btn.dataset.nlvl }, "Bildirim eşiği güncellendi."));
    });
    document.querySelectorAll("#aiCooldownSeg button").forEach(btn => {
      btn.addEventListener("click", () => saveAiPatch({ notify_cooldown_sec: Number(btn.dataset.cd) }, "Bildirim bekleme süresi güncellendi."));
    });
    document.getElementById("btnToggleAiSocial").addEventListener("click", () => {
      const cur = document.getElementById("btnToggleAiSocial").textContent === "Açık";
      saveAiPatch({ detect_social_engineering: !cur }, "Sosyal mühendislik modülü güncellendi.");
    });
    document.getElementById("btnToggleAiSensitive").addEventListener("click", () => {
      const cur = document.getElementById("btnToggleAiSensitive").textContent === "Açık";
      saveAiPatch({ detect_sensitive_data: !cur }, "Hassas veri (DLP) modülü güncellendi.");
    });
    document.getElementById("btnToggleAiScript").addEventListener("click", () => {
      const cur = document.getElementById("btnToggleAiScript").textContent === "Açık";
      saveAiPatch({ detect_script_intent: !cur }, "Betik niyet modülü güncellendi.");
    });
    document.getElementById("btnToggleExeDeep").addEventListener("click", () => {
      const cur = document.getElementById("btnToggleExeDeep").textContent === "Açık";
      saveAiPatch({ exe_deep_scan: !cur }, "Derin PE/EXE statik analizi güncellendi.");
    });
    document.getElementById("btnToggleExeUnsigned").addEventListener("click", () => {
      const cur = document.getElementById("btnToggleExeUnsigned").textContent === "Açık";
      saveAiPatch({ exe_block_unsigned_downloads: !cur }, !cur ? "Sıkı imzasız EXE engelleme açıldı." : "Sıkı imzasız EXE engelleme kapatıldı.");
    });
    document.getElementById("btnToggleExeDefender").addEventListener("click", () => {
      const cur = document.getElementById("btnToggleExeDefender").textContent === "Açık";
      saveAiPatch({ exe_defender_scan: !cur }, !cur ? "Windows Defender EXE doğrulaması açıldı." : "Windows Defender EXE doğrulaması kapatıldı.");
    });

    document.getElementById("swAutopilot").addEventListener("change", async e => {
      await saveAiPatch({ autopilot: e.target.checked }, e.target.checked ? "Tam Otomatik Otopilot açıldı." : "Otopilot duraklatıldı (manuel mod).");
      refreshAll();
    });
    document.getElementById("swOvAi").addEventListener("change", async e => {
      await saveAiPatch({ enabled: e.target.checked }, e.target.checked ? "Entegre Yerel AI açıldı." : "Entegre Yerel AI kapatıldı.");
      refreshAll();
    });
    document.getElementById("swOvExe").addEventListener("change", async e => {
      await saveAiPatch({ exe_deep_scan: e.target.checked }, e.target.checked ? "Derin PE / EXE Kalkanı açıldı." : "EXE Kalkanı temel moda alındı.");
      refreshAll();
    });
    document.getElementById("swOvGm").addEventListener("change", async e => {
      const nextMode = e.target.checked ? "auto" : "off";
      const r = await api("/api/game-mode", "POST", { action: "set_mode", mode: nextMode });
      if (r.ok) {
        showToast(e.target.checked ? "Otomatik Oyun Modu açıldı." : "Oyun Modu kapatıldı.");
        refreshAll();
      }
    });

    async function addAiKeywordFromInput() {
      const inp = document.getElementById("aiKeywordInput");
      const kw = inp.value.trim();
      if (!kw) return;
      const r = await api("/api/ai/settings", "POST", { action: "add_keyword", keyword: kw });
      if (r.ok) { inp.value = ""; renderAiSettings(r.ai); showToast("Özel güvenlik kelimesi eklendi."); }
      else showToast(r.error || "Eklenemedi");
    }
    document.getElementById("btnAddAiKeyword").addEventListener("click", addAiKeywordFromInput);
    document.getElementById("aiKeywordInput").addEventListener("keydown", e => { if (e.key === "Enter") addAiKeywordFromInput(); });

    document.getElementById("btnTestLocalLlm").addEventListener("click", async () => {
      const prov = document.getElementById("aiLlmProvider").value;
      const url = document.getElementById("aiLlmUrl").value.trim();
      const stEl = document.getElementById("aiLlmStatus");
      stEl.textContent = "Yerel loopback LLM kontrol ediliyor…";
      const r = await api("/api/ai/test-llm", "POST", { llm_provider: prov, llm_url: url });
      if (r.available) {
        const models = (r.models || []).slice(0, 5).join(", ") || "model listesi boş";
        stEl.textContent = `Bağlı (${r.provider}): ${models}`;
        if (!document.getElementById("aiLlmModel").value.trim() && (r.models || []).length) {
          document.getElementById("aiLlmModel").value = r.models[0];
        }
      } else {
        stEl.textContent = r.error || "Yerel LLM bulunamadı (yerleşik AI çalışmaya devam eder).";
      }
    });
    document.getElementById("btnSaveLlmCfg").addEventListener("click", () => {
      saveAiPatch({
        llm_provider: document.getElementById("aiLlmProvider").value,
        llm_url: document.getElementById("aiLlmUrl").value.trim(),
        llm_model: document.getElementById("aiLlmModel").value.trim()
      }, "Yerel LLM ayarları kaydedildi.");
    });

    document.getElementById("btnAiAnalyze").addEventListener("click", async () => {
      const txt = document.getElementById("aiTestInput").value;
      const box = document.getElementById("aiTestResult");
      const r = await api("/api/ai/analyze", "POST", { text: txt, notify: true });
      if (!r.ok) { showToast(r.error || "Analiz hatası"); return; }
      const rep = r.report || {};
      const ai = r.ai_analysis || {};
      box.classList.add("show");
      const protMap = {
        auto_quarantine: "Otomatik Karantina",
        notify_warn: "Anlık Bildirim / Uyarı",
        allow: "Temiz / İzin Ver"
      };
      const reasons = (rep.reasons || []).map(x => `<li>${esc(x)}</li>`).join("");
      box.innerHTML = `<div class="ring-wrap">
          ${renderScoreRing(rep.risk_score, rep.risk_level)}
          <div style="flex:1; min-width:0;">
            <div class="row">
              ${riskPill(rep.risk_level)}
              <strong>${esc(ai.category_tr || "Analiz")}</strong>
              <span class="pill">Güven: %${Math.round((ai.confidence || 0) * 100)}</span>
              <span class="pill">${esc(protMap[ai.recommended_protection] || "İzin Ver")}</span>
            </div>
            <div style="margin-top:5px; font-size:12.5px;">${esc(ai.verdict_tr || rep.summary)}</div>
          </div>
        </div>
        ${buildAiTagsHtml(ai)}
        ${reasons ? `<ul style="margin:8px 0 0 18px; font-size:12px; color:var(--text-2);">${reasons}</ul>` : ""}`;
    });

    document.addEventListener("keydown", e => {
      if (e.ctrlKey && !e.shiftKey && !e.altKey) {
        const idx = ["1", "2", "3", "4", "5", "6"].indexOf(e.key);
        if (idx >= 0) {
          e.preventDefault();
          switchTab(["overview", "gamemode", "scan", "ai", "alerts", "system"][idx]);
        }
      } else if (e.key === "F5") {
        e.preventDefault();
        refreshAll();
        showToast("Yenilendi");
      }
    });

    syncWindowState();
    refreshAll();
    setInterval(refreshAll, 5000);
  </script>
</body>
</html>
"""
