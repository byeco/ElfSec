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
from app.privacy import clear_alert_logs, load_privacy_settings, save_privacy_settings
from app.services.file_scanner import (
    default_quarantine_dir,
    quarantine_file,
    restore_quarantined_file,
    scan_file_security,
    scan_path,
)
from app.settings_store import current_settings, default_user_config_path, machine_data_dir
from app.watchers.clipboard_guard import ClipboardGuard, analyze_clipboard_text
from app.watchers.file_watcher import FileWatchState, default_watch_dirs, scan_watch_dirs_once
from app.win_plugin import plugin_status, register_browser_hosts

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
        Path("guard_alerts.jsonl"),
        default_user_config_path().parent / "clipboard_alerts.jsonl",
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
                items.append({
                    "name": fp.name,
                    "path": str(fp),
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
    ):
        self.token = token or secrets.token_hex(24)
        self.controller = controller or GameModeController()
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
        return {
            "version": __version__,
            "env": s.env,
            "imap_configured": bool(s.imap_configured),
            "service": pst.get("service", {}),
            "browser": pst.get("browser", {}),
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
                    self._send_json(200, {"ok": True, "reports": reports})
                    return

                if parsed.path == "/api/scan/downloads":
                    dirs = default_watch_dirs(all_users=False)
                    st = FileWatchState(default_user_config_path().parent / ".ui_watch_seen.json")
                    scanned, alerts = scan_watch_dirs_once(dirs, st, alert_on="MEDIUM", notify=False)
                    self._send_json(200, {
                        "ok": True,
                        "scanned_count": len(scanned),
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
                        orig_name = target.name
                        parts = orig_name.split("_", 2)
                        clean_name = parts[2] if len(parts) == 3 else orig_name
                        if clean_name.lower().endswith(".quarantined"):
                            clean_name = clean_name[: -len(".quarantined")]
                        restore_dir = Path.home() / "Downloads" / "ElfSec_Restored"
                        dest = restore_quarantined_file(target, restore_dir / (clean_name or "restored_file"))
                        self._send_json(200, {"ok": True, "restored_to": str(dest)})
                        return
                    self._send_json(400, {"ok": False, "error": f"Geçersiz karantina işlemi: {action}"})
                    return

                if parsed.path == "/api/browser/register":
                    ext_id = str(body.get("extension_id") or "").strip()
                    user_only = bool(body.get("user_only", True))
                    ids = [ext_id] if ext_id else None
                    res = register_browser_hosts(user_only=user_only, extension_ids=ids)
                    code = 200 if res.get("ok") else 400
                    self._send_json(code, res)
                    return

                if parsed.path == "/api/shutdown":
                    self._send_json(200, {"ok": True})
                    panel.stop_event.set()
                    return

                self._send_json(404, {"ok": False, "error": "Bilinmeyen endpoint."})

        self._server = _ReusableThreadingHTTPServer(("127.0.0.1", self._port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
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
    srv = DesktopPanelServer(port=port, controller=controller)
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
      --bg: #070b14;
      --bg-chrome: transparent;
      --bg-subtle: #0d1526;
      --surface: rgba(16, 25, 44, 0.76);
      --surface-solid: #10192c;
      --surface-2: rgba(255, 255, 255, 0.032);
      --surface-hover: rgba(255, 255, 255, 0.065);
      --frame-border: rgba(148, 163, 184, 0.11);
      --text: #eef4ff;
      --text-2: #cbd5e1;
      --muted: #8497b4;
      --border: rgba(148, 163, 184, 0.075);
      --border-strong: rgba(148, 163, 184, 0.15);
      --brand: #34d399;
      --brand-strong: #10b981;
      --brand-deep: #059669;
      --brand-glow: rgba(16, 185, 129, 0.24);
      --brand-soft: rgba(16, 185, 129, 0.13);
      --ok: #34d399;
      --ok-soft: rgba(16, 185, 129, 0.14);
      --warn: #fbbf24;
      --warn-soft: rgba(245, 158, 11, 0.15);
      --bad: #f87171;
      --bad-soft: rgba(239, 68, 68, 0.16);
      --game: #a78bfa;
      --game-soft: rgba(139, 92, 246, 0.16);
      --inset-hi: inset 0 1px 0 rgba(255, 255, 255, 0.045);
      --shadow-md: 0 12px 32px rgba(2, 6, 23, 0.34);
      --mono: ui-monospace, "Cascadia Code", Consolas, monospace;
    }
    :root[data-theme="light"] {
      --bg: #f1f5f9;
      --bg-chrome: transparent;
      --bg-subtle: #e6ecf4;
      --surface: rgba(255, 255, 255, 0.90);
      --surface-solid: #ffffff;
      --surface-2: rgba(15, 23, 42, 0.036);
      --surface-hover: rgba(15, 23, 42, 0.065);
      --frame-border: rgba(15, 23, 42, 0.12);
      --text: #0f172a;
      --text-2: #334155;
      --muted: #5a6a82;
      --border: rgba(15, 23, 42, 0.075);
      --border-strong: rgba(15, 23, 42, 0.15);
      --brand: #059669;
      --brand-strong: #047857;
      --brand-deep: #065f46;
      --brand-glow: rgba(5, 150, 105, 0.16);
      --brand-soft: rgba(5, 150, 105, 0.10);
      --ok: #059669;
      --ok-soft: rgba(5, 150, 105, 0.10);
      --warn: #b45309;
      --warn-soft: rgba(217, 119, 6, 0.12);
      --bad: #dc2626;
      --bad-soft: rgba(220, 38, 38, 0.11);
      --game: #6d28d9;
      --game-soft: rgba(109, 40, 217, 0.10);
      --inset-hi: inset 0 1px 0 rgba(255, 255, 255, 0.9);
      --shadow-md: 0 8px 24px rgba(15, 23, 42, 0.06);
    }
    *, *::before, *::after { box-sizing: border-box; }
    html, body { height: 100vh; margin: 0; overflow: hidden; }
    body {
      font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      -webkit-font-smoothing: antialiased;
      user-select: none;
    }
    input, textarea, pre, .mono, table { user-select: text; }
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 999px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--muted); }

    .ico { width: 16px; height: 16px; flex: 0 0 auto; display: inline-block; }

    /* ==================== ÖZEL PENCERE KABUĞU ==================== */
    .app-frame {
      height: 100vh;
      display: flex;
      flex-direction: column;
      border: 1px solid var(--frame-border);
      background:
        radial-gradient(920px 420px at 18% -6%, rgba(52, 211, 153, 0.10), transparent 62%),
        radial-gradient(720px 360px at 94% 8%, rgba(16, 185, 129, 0.07), transparent 58%),
        var(--bg);
    }
    .app-frame.is-maximized { border-width: 0; }

    .titlebar {
      height: 36px;
      flex: 0 0 36px;
      background: transparent;
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
      gap: 9px;
      min-width: 0;
      cursor: grab;
    }
    [data-win-drag="1"] { cursor: grab; }
    [data-win-drag="1"]:active { cursor: grabbing; }
    .tb-grip {
      color: var(--muted);
      opacity: 0.45;
      display: inline-flex;
      align-items: center;
      margin-right: 1px;
      transition: opacity 0.14s ease;
    }
    .titlebar-drag:hover .tb-grip { opacity: 0.9; }
    .tb-logo {
      width: 22px;
      height: 22px;
      border-radius: 7px;
      display: grid;
      place-items: center;
      background: var(--brand-soft);
      flex: 0 0 auto;
    }
    .tb-logo img { display: block; border-radius: 4px; }
    .tb-title { font-size: 12.5px; font-weight: 800; letter-spacing: -0.01em; color: var(--text); white-space: nowrap; }
    .tb-sub { font-size: 11.5px; color: var(--muted); white-space: nowrap; }
    .tb-ver {
      padding: 2px 7px;
      border-radius: 6px;
      background: var(--surface-2);
      font-family: var(--mono);
      font-size: 10px;
      font-weight: 700;
      color: var(--brand);
    }
    .tb-status {
      margin-left: 6px;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 2px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 600;
      background: var(--surface-2);
      color: var(--text-2);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .pulse-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--ok);
      box-shadow: 0 0 0 3px var(--brand-soft);
      flex: 0 0 auto;
      animation: pulseGlow 2.4s ease-in-out infinite;
    }
    @keyframes pulseGlow {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.72; transform: scale(0.9); }
    }
    .pulse-dot.game { background: var(--game); box-shadow: 0 0 0 3px var(--game-soft); }
    .pulse-dot.warn { background: var(--warn); box-shadow: 0 0 0 3px var(--warn-soft); }

    .titlebar-controls {
      height: 100%;
      display: flex;
      align-items: center;
      flex: 0 0 auto;
    }
    .tb-icon-btn {
      width: 34px;
      height: 36px;
      border: 0;
      background: transparent;
      color: var(--muted);
      display: grid;
      place-items: center;
      cursor: pointer;
      border-radius: 7px;
      transition: background 0.14s ease, color 0.14s ease;
    }
    .tb-icon-btn:hover { background: var(--surface-hover); color: var(--text); }
    .tb-icon-btn.is-pinned { color: var(--brand); background: var(--brand-soft); }
    .tb-sep { width: 1px; height: 14px; background: var(--border-strong); margin: 0 4px; opacity: 0.55; }
    .win-btn {
      width: 40px;
      height: 36px;
      border: 0;
      background: transparent;
      color: var(--text-2);
      display: grid;
      place-items: center;
      cursor: pointer;
      transition: background 0.12s ease, color 0.12s ease;
    }
    .win-btn:hover { background: var(--surface-hover); color: var(--text); }
    .win-btn.close:hover { background: #e11d48; color: #ffffff; }
    .win-native-only.is-hidden { display: none; }

    /* ==================== BÜTÜNLEŞİK GÖVDE & KENAR ÇUBUĞU ==================== */
    .app-body {
      flex: 1;
      min-height: 0;
      display: flex;
      padding: 4px 14px 4px 12px;
      gap: 14px;
    }
    .sidebar {
      width: 196px;
      flex: 0 0 196px;
      background: transparent;
      padding: 6px 2px 10px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .brand-card {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 4px 6px 6px;
    }
    .brand-logo {
      width: 34px;
      height: 34px;
      border-radius: 10px;
      background: linear-gradient(145deg, var(--brand-soft), var(--surface-2));
      display: grid;
      place-items: center;
      box-shadow: 0 4px 14px var(--brand-glow);
      flex: 0 0 auto;
    }
    .brand-logo img { display: block; border-radius: 6px; width: 22px; height: 22px; }
    .brand-title { font-size: 15px; font-weight: 800; letter-spacing: -0.02em; }
    .brand-meta { font-size: 10.5px; color: var(--muted); margin-top: 1px; }

    .side-posture {
      padding: 10px 12px;
      border-radius: 12px;
      background: var(--surface-2);
      display: flex;
      flex-direction: column;
      gap: 6px;
      font-size: 11.5px;
    }
    .side-posture-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
    .pulse-wrap { display: inline-flex; align-items: center; gap: 7px; font-weight: 700; }

    .nav { display: flex; flex-direction: column; gap: 4px; flex: 1; }
    .nav-btn {
      position: relative;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding: 9px 11px;
      border: 0;
      border-radius: 11px;
      background: transparent;
      color: var(--text-2);
      font-size: 12.5px;
      font-weight: 600;
      cursor: pointer;
      text-align: left;
      transition: background 0.14s ease, color 0.14s ease, transform 0.12s ease;
    }
    .nav-btn-left { display: inline-flex; align-items: center; gap: 10px; }
    .nav-btn:hover { background: var(--surface-hover); color: var(--text); }
    .nav-btn.active {
      background: var(--brand-soft);
      color: var(--brand);
      font-weight: 700;
      box-shadow: inset 0 1px 0 rgba(52, 211, 153, 0.16);
    }
    .nav-btn.active::before {
      content: "";
      position: absolute;
      left: 3px;
      top: 9px;
      bottom: 9px;
      width: 3px;
      border-radius: 999px;
      background: var(--brand);
    }
    .nav-badge {
      padding: 1px 7px;
      border-radius: 999px;
      font-size: 10.5px;
      font-family: var(--mono);
      background: var(--surface-2);
      color: var(--muted);
    }
    .side-foot {
      padding: 6px 8px 0;
      display: flex;
      flex-direction: column;
      gap: 6px;
      font-size: 11px;
      color: var(--muted);
      opacity: 0.78;
    }
    .kbd-hint {
      display: flex;
      justify-content: space-between;
      font-size: 10px;
      color: var(--muted);
      font-family: var(--mono);
    }

    /* ==================== ANA ALAN ==================== */
    .main {
      flex: 1;
      min-width: 0;
      overflow-y: auto;
      padding: 6px 4px 12px;
    }
    .main-inner { max-width: 1120px; margin: 0 auto; }
    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      margin-bottom: 12px;
      flex-wrap: wrap;
    }
    .topbar h1 { margin: 0; font-size: 18px; font-weight: 800; letter-spacing: -0.025em; }
    .topbar-sub { font-size: 11.5px; color: var(--muted); margin-top: 1px; }
    .topbar-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 11.5px;
      font-weight: 700;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--muted);
      white-space: nowrap;
    }
    .pill::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
    .pill.ok { background: var(--ok-soft); color: var(--ok); border-color: rgba(16,185,129,0.28); }
    .pill.warn { background: var(--warn-soft); color: var(--warn); border-color: rgba(245,158,11,0.28); }
    .pill.bad { background: var(--bad-soft); color: var(--bad); border-color: rgba(239,68,68,0.28); }
    .pill.game { background: var(--game-soft); color: var(--game); border-color: rgba(139,92,246,0.34); }

    .section { display: none; flex-direction: column; gap: 12px; }
    .section.active { display: flex; animation: fadeIn 0.16s ease; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 15px;
      padding: 15px 17px;
      box-shadow: var(--inset-hi), var(--shadow-md);
    }
    .hero {
      background: linear-gradient(135deg, rgba(16,185,129,0.16), rgba(16,25,44,0.88) 64%);
      border-color: rgba(52,211,153,0.20);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    :root[data-theme="light"] .hero { background: linear-gradient(135deg, #ecfdf5, #ffffff 68%); }
    .hero-left { display: flex; align-items: center; gap: 13px; min-width: 240px; flex: 1; }
    .score-ring-box {
      position: relative;
      width: 62px;
      height: 62px;
      flex: 0 0 62px;
      display: grid;
      place-items: center;
    }
    .score-ring-val {
      position: absolute;
      text-align: center;
      line-height: 1;
    }
    .score-ring-val strong { font-size: 16px; font-weight: 800; font-variant-numeric: tabular-nums; display: block; }
    .score-ring-val span { font-size: 8.5px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
    .hero h2 { margin: 0 0 3px; font-size: 16px; font-weight: 800; letter-spacing: -0.02em; }
    .hero p { margin: 0 0 7px; font-size: 12px; color: var(--muted); line-height: 1.4; }
    .hero-chips { display: flex; gap: 6px; flex-wrap: wrap; }
    .chip-tag {
      font-size: 10.5px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 999px;
      background: var(--brand-soft);
      color: var(--brand);
      border: 1px solid rgba(16,185,129,0.24);
    }

    .grid-4 { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
    .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }
    .stat-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 11px 12px;
      box-shadow: var(--inset-hi);
      transition: transform 0.14s ease, border-color 0.14s ease;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .stat-card:hover { transform: translateY(-1px); border-color: var(--border-strong); }
    .stat-top { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
    .stat-label { font-size: 11px; color: var(--muted); font-weight: 600; }
    .stat-ico {
      width: 24px;
      height: 24px;
      border-radius: 7px;
      display: grid;
      place-items: center;
      background: var(--brand-soft);
      color: var(--brand);
    }
    .stat-ico.game { background: var(--game-soft); color: var(--game); }
    .stat-ico.warn { background: var(--warn-soft); color: var(--warn); }
    .stat-ico.bad { background: var(--bad-soft); color: var(--bad); }
    .stat-val { font-size: 18px; font-weight: 800; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
    .stat-sub { font-size: 11px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

    .mod-strip { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; }
    @media (min-width: 1120px) {
      .mod-strip { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    }
    @media (max-width: 780px) {
      .grid-4 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    .mod-item {
      padding: 11px 13px;
      border-radius: 12px;
      background: var(--surface-2);
      border: 1px solid transparent;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      transition: background 0.14s ease, border-color 0.14s ease;
    }
    .mod-item:hover { background: var(--surface-hover); border-color: var(--border); }
    .mod-name { font-size: 12.5px; font-weight: 700; }
    .mod-desc { font-size: 11px; color: var(--muted); margin-top: 1px; }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 7px;
      padding: 8px 14px;
      border-radius: 10px;
      border: 1px solid var(--border-strong);
      background: var(--surface-2);
      color: var(--text);
      font-size: 12.5px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.14s ease;
    }
    .btn:hover:not(:disabled) { background: var(--surface-hover); transform: translateY(-1px); }
    .btn:disabled { opacity: 0.55; cursor: wait; }
    .btn-primary {
      background: linear-gradient(135deg, var(--brand-strong), var(--brand-deep));
      border-color: transparent;
      color: #ffffff;
      box-shadow: 0 4px 14px var(--brand-glow);
    }
    .btn-primary:hover:not(:disabled) { filter: brightness(1.08); }
    .btn-danger { background: var(--bad-soft); border-color: rgba(239,68,68,0.35); color: var(--bad); }
    .btn-sm { padding: 6px 11px; font-size: 11.5px; border-radius: 8px; }
    .row { display: flex; gap: 9px; align-items: center; flex-wrap: wrap; }

    input[type="text"], textarea {
      width: 100%;
      background: var(--surface-2);
      border: 1px solid var(--border-strong);
      border-radius: 10px;
      padding: 9px 12px;
      color: var(--text);
      font-size: 13px;
      font-family: inherit;
    }
    textarea { min-height: 98px; resize: vertical; font-family: var(--mono); font-size: 12px; }
    input:focus, textarea:focus { outline: none; border-color: var(--brand); box-shadow: 0 0 0 3px var(--brand-soft); }

    .seg {
      display: inline-flex;
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 11px;
      padding: 3px;
      gap: 4px;
    }
    .seg button {
      border: 0;
      background: transparent;
      color: var(--muted);
      padding: 7px 13px;
      border-radius: 8px;
      font-size: 12.5px;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.14s ease;
    }
    .seg button.active { background: var(--brand-strong); color: #fff; }
    .seg-sm button { padding: 5px 10px; font-size: 11.5px; }

    table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
    th, td { padding: 9px 10px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: middle; }
    tbody tr:last-child td { border-bottom: none; }
    th { font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); font-weight: 700; }
    tbody tr:hover { background: var(--surface-hover); }
    .mono { font-family: var(--mono); font-size: 11.5px; word-break: break-all; }

    .chip-list { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 5px 10px;
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 8px;
      font-size: 12px;
      font-family: var(--mono);
    }
    .chip button { border: 0; background: transparent; color: var(--bad); cursor: pointer; font-weight: 800; padding: 0 2px; }

    .result-box {
      margin-top: 12px;
      padding: 14px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: var(--surface-2);
      display: none;
    }
    .result-box.show { display: block; }
    .ring-wrap { display: flex; align-items: center; gap: 14px; }

    .path-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 8px 10px;
      border-radius: 9px;
      background: var(--surface-2);
      border: 1px solid var(--border);
      margin-top: 8px;
    }

    .empty-state {
      padding: 20px;
      text-align: center;
      color: var(--muted);
      font-size: 12.5px;
      border: 1px dashed var(--border-strong);
      border-radius: 12px;
      background: var(--surface-2);
    }

    /* ==================== ALT DURUM ÇUBUĞU ==================== */
    .statusbar {
      height: 24px;
      flex: 0 0 24px;
      background: transparent;
      padding: 0 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 10.5px;
      color: var(--muted);
      opacity: 0.78;
    }
    .sb-left, .sb-right { display: flex; align-items: center; gap: 12px; }
    .sb-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--ok); display: inline-block; }

    .toast {
      position: fixed;
      right: 18px;
      bottom: 34px;
      padding: 9px 14px;
      border-radius: 10px;
      background: var(--surface-solid);
      border: 1px solid rgba(52, 211, 153, 0.35);
      color: var(--text);
      font-size: 12px;
      font-weight: 600;
      box-shadow: 0 12px 30px rgba(0, 0, 0, 0.4);
      opacity: 0;
      transform: translateY(8px);
      pointer-events: none;
      transition: all 0.18s ease;
      z-index: 999;
    }
    .toast.show { opacity: 1; transform: translateY(0); }

    @media (max-width: 680px) {
      .app-body { flex-direction: column; }
      .sidebar { width: 100%; flex: none; flex-direction: row; overflow-x: auto; align-items: center; padding: 8px; }
      .nav { flex-direction: row; }
      .brand-card, .side-posture, .side-foot { display: none; }
    }
  </style>
</head>
<body>
  <div class="app-frame" id="appFrame">
    <!-- ÖZEL ÇERÇEVESİZ BAŞLIK ÇUBUĞU -->
    <header class="titlebar">
      <div class="titlebar-drag" data-win-drag="1" id="titlebarDrag" title="Taşımak için sürükleyin · Çift tıklayınca büyür">
        <span class="tb-grip" aria-hidden="true">
          <svg width="10" height="14" viewBox="0 0 10 14" fill="currentColor"><circle cx="2.5" cy="2.5" r="1.2"/><circle cx="7.5" cy="2.5" r="1.2"/><circle cx="2.5" cy="7" r="1.2"/><circle cx="7.5" cy="7" r="1.2"/><circle cx="2.5" cy="11.5" r="1.2"/><circle cx="7.5" cy="11.5" r="1.2"/></svg>
        </span>
        <div class="tb-logo"><img src="__ELFSEC_LOGO__" alt="ElfSec" width="16" height="16" /></div>
        <span class="tb-title">ElfSec</span>
        <span class="tb-sub">Güvenlik Merkezi</span>
        <span class="tb-ver">v__ELFSEC_VERSION__</span>
        <span class="tb-status">
          <span class="pulse-dot" id="tbPulse"></span>
          <span id="tbStatusTxt">Yerel Motor Hazır</span>
        </span>
      </div>
      <div class="titlebar-controls">
        <button class="tb-icon-btn" id="btnThemeToggle" title="Tema Değiştir (Açık / Koyu)">
          <svg class="ico" id="icoTheme" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"></path></svg>
        </button>
        <button class="tb-icon-btn win-native-only" id="btnWinPin" title="Her Zaman Üstte Tut">
          <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 17v5"></path><path d="M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z"></path></svg>
        </button>
        <span class="tb-sep win-native-only" id="winSep"></span>
        <button class="win-btn win-native-only" id="btnWinMin" title="Küçült">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M2 6h8"/></svg>
        </button>
        <button class="win-btn win-native-only" id="btnWinMax" title="Ekranı Kapla">
          <svg id="icoWinMax" width="11" height="11" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.35"><rect x="1.75" y="1.75" width="8.5" height="8.5" rx="1.2"/></svg>
        </button>
        <button class="win-btn close" id="btnWinClose" title="Kapat">
          <svg width="11" height="11" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M2.5 2.5l7 7M9.5 2.5l-7 7"/></svg>
        </button>
      </div>
    </header>

    <!-- ANA GÖVDE -->
    <div class="app-body">
      <aside class="sidebar">
        <div class="brand-card" data-win-drag="1" title="Pencereyi taşımak için sürükleyin">
          <div class="brand-logo"><img src="__ELFSEC_LOGO__" alt="ElfSec" width="28" height="28" /></div>
          <div>
            <div class="brand-title">ElfSec</div>
            <div class="brand-meta">Yerel Güvenlik Kalkanı</div>
          </div>
        </div>

        <div class="side-posture">
          <div class="side-posture-row">
            <span class="pulse-wrap"><span id="sidePulse" class="pulse-dot"></span><span id="sideStateTxt">Koruma Aktif</span></span>
            <span style="font-family:var(--mono); font-size:10.5px; color:var(--brand); font-weight:700;">YEREL</span>
          </div>
          <div class="side-posture-row" style="color:var(--muted); font-size:11.5px;">
            <span>Oyun Modu</span>
            <span id="sideGmTxt">Otomatik</span>
          </div>
        </div>

        <nav class="nav">
          <button class="nav-btn active" data-tab="overview">
            <span class="nav-btn-left">
              <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.6 4.8 5.4v5.9c0 4.5 3.1 8.3 7.2 9.4 4.1-1.1 7.2-4.9 7.2-9.4V5.4L12 2.6Z"></path><path d="m8.8 11.8 2.2 2.2 4.2-4.4"></path></svg>
              <span>Genel Bakış</span>
            </span>
          </button>
          <button class="nav-btn" data-tab="gamemode">
            <span class="nav-btn-left">
              <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="6" width="20" height="12" rx="4"></rect><path d="M6 12h4M8 10v4M15 11h.01M18 13h.01"></path></svg>
              <span>Oyun Modu</span>
            </span>
          </button>
          <button class="nav-btn" data-tab="scan">
            <span class="nav-btn-left">
              <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"></circle><path d="m20 20-3.5-3.5"></path></svg>
              <span>Hızlı Tarama</span>
            </span>
          </button>
          <button class="nav-btn" data-tab="alerts">
            <span class="nav-btn-left">
              <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9 2.6 17.5a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"></path><path d="M12 9v4M12 17h.01"></path></svg>
              <span>Alarmlar &amp; Karantina</span>
            </span>
            <span class="nav-badge" id="navAlertsBadge">0</span>
          </button>
          <button class="nav-btn" data-tab="system">
            <span class="nav-btn-left">
              <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="12" rx="2"></rect><path d="M8 20h8M12 16v4"></path></svg>
              <span>Sistem &amp; Tarayıcı</span>
            </span>
          </button>
        </nav>

        <div class="side-foot">
          <div class="kbd-hint"><span>Sekme Geçişi</span><span>Ctrl+1..5</span></div>
          <div class="kbd-hint"><span>Yenile</span><span>F5</span></div>
        </div>
      </aside>

      <main class="main">
        <div class="main-inner">
          <header class="topbar">
            <div>
              <h1 id="pageTitle">Genel Bakış</h1>
              <div class="topbar-sub" id="pageSub">Gerçek zamanlı yerel koruma, oyun optimizasyonu ve tehdit özeti</div>
            </div>
            <div class="topbar-actions">
              <span class="pill" id="pillService">Servis kontrol ediliyor</span>
              <span class="pill" id="pillGameMode">Oyun Modu: Otomatik</span>
              <button class="btn btn-sm" id="btnRefresh">Yenile</button>
            </div>
          </header>

          <!-- SEKME 1: GENEL BAKIŞ -->
          <section class="section active" id="tab-overview">
            <div class="card hero">
              <div class="hero-left">
                <div class="score-ring-box" id="heroScoreRing"></div>
                <div>
                  <h2 id="heroTitle">ElfSec Yerel Koruma Hazır</h2>
                  <p id="heroSub">İndirilenler klasörü, pano (ClickFix) ve e-posta güvenliği cihazınızda yerel olarak izlenir.</p>
                  <div class="hero-chips">
                    <span class="chip-tag">Sıfır Bulut · %100 Yerel</span>
                    <span class="chip-tag">Açık Kaynak · GPL-3.0</span>
                  </div>
                </div>
              </div>
              <div class="row">
                <button class="btn btn-primary" id="btnQuickDownloads">İndirilenleri Tara</button>
                <button class="btn" id="btnQuickClipboard">Panoyu Tara</button>
                <button class="btn" data-jump="system">Öz-Denetim</button>
              </div>
            </div>

            <div class="grid-4">
              <div class="stat-card">
                <div class="stat-top">
                  <div class="stat-label">Windows Servisi</div>
                  <div class="stat-ico"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2.6 4.8 5.4v5.9c0 4.5 3.1 8.3 7.2 9.4 4.1-1.1 7.2-4.9 7.2-9.4V5.4L12 2.6Z"/></svg></div>
                </div>
                <div class="stat-val" id="statService">-</div>
                <div class="stat-sub" id="statHeartbeat">Son kontrol: -</div>
              </div>
              <div class="stat-card">
                <div class="stat-top">
                  <div class="stat-label">Oyun Modu &amp; CPU</div>
                  <div class="stat-ico game"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="6" width="20" height="12" rx="4"/><path d="M6 12h4M8 10v4"/></svg></div>
                </div>
                <div class="stat-val" id="statGameMode">-</div>
                <div class="stat-sub" id="statCpuPrio">Öncelik: NORMAL</div>
              </div>
              <div class="stat-card">
                <div class="stat-top">
                  <div class="stat-label">Toplam Alarm</div>
                  <div class="stat-ico warn"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.3 3.9 2.6 17.5a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/></svg></div>
                </div>
                <div class="stat-val" id="statAlerts">0</div>
                <div class="stat-sub">Yerel günlük kayıtları</div>
              </div>
              <div class="stat-card">
                <div class="stat-top">
                  <div class="stat-label">Karantina Kasası</div>
                  <div class="stat-ico bad"><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg></div>
                </div>
                <div class="stat-val" id="statQuarantine">0</div>
                <div class="stat-sub">İzole edilen dosya</div>
              </div>
            </div>

            <div class="mod-strip" id="modStrip">
              <div class="mod-item"><div><div class="mod-name">İndirilenler Kalkanı</div><div class="mod-desc">PE, çift uzantı &amp; MotW</div></div><span class="pill ok">Hazır</span></div>
              <div class="mod-item"><div><div class="mod-name">Pano / ClickFix</div><div class="mod-desc" id="modClipDesc">KVKK: Arka plan kapalı</div></div><span class="pill" id="modClipPill">Kapalı</span></div>
              <div class="mod-item"><div><div class="mod-name">Akıllı Oyun Modu</div><div class="mod-desc" id="modGmDesc">Otomatik algılama</div></div><span class="pill ok" id="modGmPill">Oto</span></div>
              <div class="mod-item"><div><div class="mod-name">Tarayıcı Köprüsü</div><div class="mod-desc" id="modBrDesc">Native Messaging</div></div><span class="pill" id="modBrPill">Kontrol</span></div>
            </div>

            <div class="card">
              <div class="row" style="justify-content: space-between; margin-bottom: 10px;">
                <strong>Son Güvenlik Olayları</strong>
                <button class="btn btn-sm" data-jump="alerts">Tümünü Gör</button>
              </div>
              <div id="overviewAlerts">Yükleniyor…</div>
            </div>
          </section>

          <!-- SEKME 2: OYUN MODU -->
          <section class="section" id="tab-gamemode">
            <div class="card">
              <div class="row" style="justify-content: space-between; margin-bottom: 12px;">
                <div>
                  <h3 style="margin:0 0 4px;">Akıllı Oyun Modu (Ultra-Düşük Kaynak Motoru)</h3>
                  <p style="margin:0; font-size:12.5px; color:var(--muted);">Tam ekran (Direct3D / Borderless) veya oyun klasöründeki bir süreç algılandığında CPU, disk ve bildirim yükünü minimuma indirir.</p>
                </div>
                <span class="pill" id="gmLiveBadge">Beklemede</span>
              </div>

              <div class="row" style="justify-content: space-between; margin-top: 14px;">
                <div class="seg" id="gmModeSeg">
                  <button data-mode="auto" class="active">Otomatik</button>
                  <button data-mode="on">Her Zaman Açık</button>
                  <button data-mode="off">Kapalı</button>
                </div>
                <button class="btn" id="btnGmDetect">Şimdi Algılamayı Test Et</button>
              </div>
            </div>

            <div class="grid-2">
              <div class="card">
                <h3 style="margin:0 0 10px; font-size:15px;">Oyun Sırasında Yapılan Optimizasyonlar</h3>
                <table>
                  <thead><tr><th>Bileşen</th><th>Normal</th><th>Oyun Modu</th></tr></thead>
                  <tbody>
                    <tr><td>CPU Önceliği</td><td>NORMAL</td><td><strong>IDLE (En Düşük)</strong></td></tr>
                    <tr><td>İndirilenler Taraması</td><td>10 sn</td><td><strong>120 sn</strong></td></tr>
                    <tr><td>Pano (ClickFix) Taraması</td><td>1.5 sn</td><td><strong>15 sn</strong></td></tr>
                    <tr><td>IMAP Posta Kontrolü</td><td>10 dk</td><td><strong>Ertelenir</strong></td></tr>
                    <tr><td>Bildirimler (Toast)</td><td>Anlık</td><td><strong>Oyun sonuna bekletilir</strong></td></tr>
                  </tbody>
                </table>
              </div>

              <div class="card">
                <h3 style="margin:0 0 6px; font-size:15px;">Özel Oyun Listesi (.exe)</h3>
                <p style="margin:0 0 10px; font-size:12px; color:var(--muted);">Pencereli modda oynadığınız veya otomatik listeye eklemek istediğiniz oyunların .exe adını ekleyin.</p>
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
                <h3 style="margin:0 0 6px; font-size:15px;">URL / Metin / ClickFix Taraması</h3>
                <p style="margin:0 0 10px; font-size:12px; color:var(--muted);">Şüpheli bağlantıyı, e-posta metnini veya PowerShell/CMD komutunu yapıştırın.</p>
                <textarea id="scanTextInput" placeholder="https://... veya powershell -w hidden -enc ..."></textarea>
                <div class="row" style="margin-top: 10px;">
                  <button class="btn btn-primary" id="btnScanText">Metni Tara</button>
                  <button class="btn" id="btnScanClipFill">Panodan Çek &amp; Tara</button>
                </div>
                <div class="result-box" id="scanTextResult"></div>
              </div>

              <div class="card">
                <h3 style="margin:0 0 6px; font-size:15px;">Dosya veya Klasör Taraması</h3>
                <p style="margin:0 0 10px; font-size:12px; color:var(--muted);">PE (MZ) maskeleme, çift uzantı (.pdf.exe), LOLBin betik, MotW ve .eml analizi.</p>
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
                  <strong>Tespit Edilen Güvenlik Alarmları</strong>
                  <span class="pill" id="alertsBadge">0 kayıt</span>
                </div>
                <div class="row">
                  <div class="seg seg-sm" id="alertFilterSeg">
                    <button data-lv="ALL" class="active">Tümü</button>
                    <button data-lv="HIGH">Kritik / Yüksek</button>
                    <button data-lv="MEDIUM">Orta</button>
                    <button data-lv="LOW">Düşük</button>
                  </div>
                  <input type="text" id="alertSearch" placeholder="Ara…" style="width:160px; padding:5px 10px; font-size:12px;" />
                  <button class="btn btn-sm btn-danger" id="btnClearAlerts">Günlükleri Temizle</button>
                </div>
              </div>
              <div id="alertsTableWrap">Yükleniyor…</div>
            </div>

            <div class="card">
              <div class="row" style="justify-content: space-between; margin-bottom: 10px;">
                <strong>Karantina Kasası (.quarantined)</strong>
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
                  <h3 style="margin:0 0 3px; font-size:15px;">KVKK &amp; Gizlilik Denetimi</h3>
                  <p style="margin:0; font-size:12px; color:var(--muted);">Pano izleme varsayılan kapalıdır; açıldığında yalnızca ClickFix komutları ve URL'ler RAM'de taranır.</p>
                </div>
                <button class="btn btn-sm btn-danger" id="btnClearAlertsSys">Tüm Günlükleri Temizle</button>
              </div>
              <div class="grid-2">
                <div class="mod-item">
                  <div>
                    <div class="mod-name">Arka Plan Pano İzleme (İsteğe Bağlı)</div>
                    <div class="mod-desc">Normal metin/şifre/IBAN taranmaz; yalnızca ClickFix/URL denetlenir.</div>
                  </div>
                  <div class="row">
                    <span class="pill" id="pillClipPrivacy">Kapalı</span>
                    <button class="btn btn-sm" id="btnToggleClipPrivacy">Aç</button>
                  </div>
                </div>
                <div class="mod-item">
                  <div>
                    <div class="mod-name">Günlüklerde Kişisel Veri Maskeleme</div>
                    <div class="mod-desc">E-posta, TC, IBAN, kart ve ham pano içeriği günlüklerden çıkarılır.</div>
                  </div>
                  <div class="row">
                    <span class="pill ok" id="pillMaskPrivacy">Açık</span>
                    <button class="btn btn-sm" id="btnToggleMaskPrivacy">Kapat</button>
                  </div>
                </div>
              </div>
            </div>

            <div class="grid-2">
              <div class="card">
                <h3 style="margin:0 0 10px; font-size:15px;">Windows Eklenti Bileşenleri</h3>
                <div id="sysBadges">Yükleniyor…</div>
              </div>

              <div class="card">
                <h3 style="margin:0 0 6px; font-size:15px;">Tarayıcı Native Host Köprüsü</h3>
                <p style="margin:0 0 10px; font-size:12px; color:var(--muted);">Chrome Web Store / Edge uzantı kimliğinizi yerel elfsec.exe ile eşleyin.</p>
                <div id="browserBadges" style="margin-bottom: 12px;"></div>
                <div class="row" style="flex-wrap: nowrap;">
                  <input type="text" id="extIdInput" placeholder="32 karakterlik Store Uzantı ID (boşsa varsayılan)" />
                  <button class="btn btn-primary" id="btnPairBrowser">Eşle</button>
                </div>
              </div>
            </div>

            <div class="card">
              <div class="row" style="justify-content: space-between; margin-bottom: 10px;">
                <strong>Öz-Denetim (ElfSec KONTROL)</strong>
                <button class="btn btn-sm btn-primary" id="btnRunKontrol">Denetimi Çalıştır</button>
              </div>
              <div id="kontrolResult" style="font-size:12.5px; color:var(--muted);">Denetimi başlatmak için yukarıdaki butona tıklayın.</div>
            </div>
          </section>
        </div>
      </main>
    </div>

    <!-- ALT DURUM ÇUBUĞU -->
    <footer class="statusbar">
      <div class="sb-left">
        <span><span class="sb-dot"></span> %100 Yerel Motor · Sıfır Bulut · 127.0.0.1</span>
        <span id="sbWindowMode">Pencere Modu: Kontrol ediliyor</span>
      </div>
      <div class="sb-right">
        <span id="sbLastSync">Canlı · 5 sn</span>
        <span>© 2026 byeco · GPL-3.0</span>
      </div>
    </footer>
  </div>

  <div class="toast" id="toast"></div>

  <script>
    const TOKEN = "__ELFSEC_TOKEN__";
    const TAB_META = {
      overview: { title: "Genel Bakış", sub: "Gerçek zamanlı yerel koruma, oyun optimizasyonu ve tehdit özeti" },
      gamemode: { title: "Akıllı Oyun Modu", sub: "Tam ekran ve özel oyunlarda ultra-düşük CPU/disk tüketimi" },
      scan: { title: "Hızlı Tarama", sub: "ClickFix pano komutları, URL, dosya ve klasör güvenlik analizi" },
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
      const r = 21;
      const c = 2 * Math.PI * r;
      const off = c - (s / 100) * c;
      return `<svg width="56" height="56" viewBox="0 0 56 56" style="flex:0 0 auto;">
        <circle cx="28" cy="28" r="${r}" fill="none" stroke="var(--border)" stroke-width="5"></circle>
        <circle cx="28" cy="28" r="${r}" fill="none" stroke="${color}" stroke-width="5"
          stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"
          stroke-linecap="round" transform="rotate(-90 28 28)"></circle>
        <text x="28" y="32" text-anchor="middle" fill="var(--text)" font-size="13" font-weight="800">${s}</text>
      </svg>`;
    }

    function renderHeroScore(score) {
      const s = Math.max(0, Math.min(100, Number(score) || 0));
      const color = s >= 80 ? "var(--ok)" : (s >= 55 ? "var(--warn)" : "var(--bad)");
      const r = 25;
      const c = 2 * Math.PI * r;
      const off = c - (s / 100) * c;
      document.getElementById("heroScoreRing").innerHTML = `
        <svg width="62" height="62" viewBox="0 0 62 62">
          <circle cx="31" cy="31" r="${r}" fill="none" stroke="var(--border)" stroke-width="5"></circle>
          <circle cx="31" cy="31" r="${r}" fill="none" stroke="${color}" stroke-width="5"
            stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"
            stroke-linecap="round" transform="rotate(-90 31 31)"></circle>
        </svg>
        <div class="score-ring-val"><strong>${s}</strong><span>Puan</span></div>`;
    }

    function computePostureScore(st) {
      let score = 45;
      const svc = st.service || {};
      if (svc.running) score += 25;
      else if (svc.installed) score += 10;
      if (st.context_menu_files || st.context_menu_dirs) score += 10;
      if (st.protocol_registered) score += 10;
      const br = st.browser || {};
      if (Object.values(br).some(Boolean)) score += 10;
      return Math.min(100, score);
    }

    function switchTab(tab) {
      if (!TAB_META[tab]) return;
      document.querySelectorAll(".nav-btn").forEach(b => b.classList.toggle("active", b.dataset.tab === tab));
      document.querySelectorAll(".section").forEach(s => s.classList.toggle("active", s.id === "tab-" + tab));
      document.getElementById("pageTitle").textContent = TAB_META[tab].title;
      document.getElementById("pageSub").textContent = TAB_META[tab].sub;
    }

    document.querySelectorAll(".nav-btn").forEach(b => b.addEventListener("click", () => switchTab(b.dataset.tab)));
    document.querySelectorAll("[data-jump]").forEach(b => b.addEventListener("click", () => switchTab(b.dataset.jump)));

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
      document.getElementById("sbWindowMode").textContent = isNative ? "Yerel Çerçevesiz Pencere" : "Tarayıcı Uygulama Modu";
      document.getElementById("appFrame").classList.toggle("is-maximized", !!(ws && ws.maximized));
      const pinBtn = document.getElementById("btnWinPin");
      pinBtn.classList.toggle("is-pinned", !!(ws && ws.pinned));
      const icoMax = document.getElementById("icoWinMax");
      if (ws && ws.maximized) {
        icoMax.innerHTML = '<rect x="3" y="1.5" width="7.5" height="7.5" rx="1"/><path d="M1.5 4v6.5h6.5"/>';
        document.getElementById("btnWinMax").title = "Önceki Boyuta Döndür";
      } else {
        icoMax.innerHTML = '<rect x="1.75" y="1.75" width="8.5" height="8.5" rx="1.2"/>';
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

    (function setupWindowDrag() {
      let dragging = false;
      let fallbackMoving = false;
      let startX = 0;
      let startY = 0;
      let lastX = 0;
      let lastY = 0;
      let moveInFlight = false;

      document.querySelectorAll('[data-win-drag="1"]').forEach(el => {
        el.addEventListener("mousedown", e => {
          if (e.button !== 0 || e.detail > 1) return;
          if (e.target.closest("button, a, input, textarea, select")) return;
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
        if (Math.abs(e.screenX - startX) < 3 && Math.abs(e.screenY - startY) < 3) return;
        dragging = false;
        try {
          const r = await api("/api/window/drag-start", "POST", {});
          if (r && r.ok) {
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

      if (active) {
        pill.className = "pill game";
        pill.textContent = "Oyun Modu: AKTİF" + (proc ? " (" + proc + ")" : "");
        badge.className = "pill game";
        badge.textContent = "DÜŞÜK GÜÇ AKTİF" + (proc ? " · " + proc : "");
        sideGm.textContent = proc || "Aktif";
        modPill.className = "pill game";
        modPill.textContent = "Aktif";
        modDesc.textContent = proc || "Düşük kaynak modu";
      } else if (mode === "off") {
        pill.className = "pill";
        pill.textContent = "Oyun Modu: Kapalı";
        badge.className = "pill";
        badge.textContent = "Kapalı (Tam Koruma)";
        sideGm.textContent = "Kapalı";
        modPill.className = "pill";
        modPill.textContent = "Kapalı";
        modDesc.textContent = "Devre dışı";
      } else {
        pill.className = "pill ok";
        pill.textContent = "Oyun Modu: Otomatik";
        badge.className = "pill ok";
        badge.textContent = "Otomatik İzleme Hazır";
        sideGm.textContent = "Otomatik";
        modPill.className = "pill ok";
        modPill.textContent = "Oto";
        modDesc.textContent = "Tam ekran izleniyor";
      }

      document.getElementById("statGameMode").textContent = active ? "AKTİF" : (mode === "off" ? "Kapalı" : "Otomatik");
      document.getElementById("statCpuPrio").textContent = "CPU Önceliği: " + (gm.cpu_priority || "NORMAL");

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
      clipboard: "Pano",
      mail: "E-posta"
    };

    function renderPrivacy(pr) {
      const p = pr || {};
      const clipOn = !!p.clipboard_auto_watch;
      const maskOn = p.kvkk_mask_logs !== false;
      const modClipPill = document.getElementById("modClipPill");
      const modClipDesc = document.getElementById("modClipDesc");
      if (modClipPill && modClipDesc) {
        modClipPill.className = "pill " + (clipOn ? "ok" : "");
        modClipPill.textContent = clipOn ? "Aktif" : "Kapalı";
        modClipDesc.textContent = clipOn ? "Yalnızca ClickFix & URL" : "KVKK: Arka plan kapalı";
      }
      const pClip = document.getElementById("pillClipPrivacy");
      const bClip = document.getElementById("btnToggleClipPrivacy");
      if (pClip && bClip) {
        pClip.className = "pill " + (clipOn ? "ok" : "");
        pClip.textContent = clipOn ? "Açık" : "Kapalı";
        bClip.textContent = clipOn ? "Kapat" : "Aç";
      }
      const pMask = document.getElementById("pillMaskPrivacy");
      const bMask = document.getElementById("btnToggleMaskPrivacy");
      if (pMask && bMask) {
        pMask.className = "pill " + (maskOn ? "ok" : "warn");
        pMask.textContent = maskOn ? "Açık" : "Kapalı";
        bMask.textContent = maskOn ? "Kapat" : "Aç";
      }
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
          <td><strong>${esc(r.risk_score ?? "-")}/100</strong></td>
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
        const tbPulse = document.getElementById("tbPulse");
        const tbTxt = document.getElementById("tbStatusTxt");
        const sideState = document.getElementById("sideStateTxt");
        const gmActive = !!(st.game_mode && st.game_mode.active);

        if (svc.running) {
          pSvc.className = "pill ok";
          pSvc.textContent = "Servis: ÇALIŞIYOR";
          sideState.textContent = gmActive ? "Oyun Modu" : "Koruma Aktif";
          tbTxt.textContent = gmActive ? "Oyun Modu · Düşük Güç" : "Gerçek Zamanlı Koruma Aktif";
          pulse.className = "pulse-dot" + (gmActive ? " game" : "");
          tbPulse.className = pulse.className;
        } else if (svc.installed) {
          pSvc.className = "pill warn";
          pSvc.textContent = "Servis: " + (svc.state || "DURMUŞ");
          sideState.textContent = "Servis Durmuş";
          tbTxt.textContent = "Servis Durmuş · Panel Hazır";
          pulse.className = "pulse-dot warn";
          tbPulse.className = "pulse-dot warn";
        } else {
          pSvc.className = "pill warn";
          pSvc.textContent = "Tekil Mod (Servissiz)";
          sideState.textContent = gmActive ? "Oyun Modu" : "Panel Hazır";
          tbTxt.textContent = gmActive ? "Oyun Modu · Tekil" : "Yerel Motor Hazır";
          pulse.className = "pulse-dot" + (gmActive ? " game" : " warn");
          tbPulse.className = pulse.className;
        }

        renderHeroScore(computePostureScore(st));
        document.getElementById("statService").textContent = svc.state || "TEKLİ";
        document.getElementById("statHeartbeat").textContent = "Son kontrol: " + (svc.heartbeat || "yok");
        document.getElementById("statAlerts").textContent = String(st.alerts_count || 0);
        document.getElementById("statQuarantine").textContent = String(st.quarantine_count || 0);
        document.getElementById("navAlertsBadge").textContent = String((st.alerts_count || 0) + (st.quarantine_count || 0));
        renderGameMode(st.game_mode || {});
        renderPrivacy(st.privacy || {});

        const br = st.browser || {};
        const brCount = Object.values(br).filter(Boolean).length;
        const brPill = document.getElementById("modBrPill");
        brPill.className = "pill " + (brCount ? "ok" : "warn");
        brPill.textContent = brCount ? `${brCount} Bağlı` : "Eşlenmedi";
        document.getElementById("modBrDesc").textContent = brCount ? "Chrome/Edge köprüsü aktif" : "Sistem sekmesinden eşleyin";

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
      }

      if (al.ok) {
        cachedAlerts = al.alerts || [];
        document.getElementById("overviewAlerts").innerHTML = renderAlertRowsHtml(cachedAlerts.slice(0, 5));
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
              <td><div><strong>${esc(it.name)}</strong></div><div class="mono" style="color:var(--muted);">${esc(it.path)}</div></td>
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
              if (r.ok) { showToast("Karantina işlemi tamamlandı."); refreshAll(); }
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

    document.getElementById("btnToggleClipPrivacy").addEventListener("click", async () => {
      const cur = document.getElementById("pillClipPrivacy").textContent === "Açık";
      const r = await api("/api/privacy", "POST", { clipboard_auto_watch: !cur });
      if (r.ok) {
        renderPrivacy(r.privacy);
        showToast(!cur ? "Arka plan ClickFix pano koruması açıldı." : "Arka plan pano izleme kapatıldı (KVKK).");
      }
    });
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
      const r = await api("/api/scan/downloads", "POST", {});
      if (r.ok) {
        const n = (r.alerts || []).length;
        showToast(`${r.scanned_count} yeni dosya tarandı, ${n} tehdit bulundu.`);
        refreshAll();
      }
    });
    document.getElementById("btnQuickClipboard").addEventListener("click", async () => {
      const r = await api("/api/scan/clipboard", "POST", {});
      if (r.ok) {
        const rep = r.report || {};
        showToast(`Pano: ${rep.risk_level || "LOW"} (${rep.risk_score || 0}/100)`);
      }
    });

    function showTextReport(rep) {
      const box = document.getElementById("scanTextResult");
      box.classList.add("show");
      const reasons = (rep.reasons || []).map(x => `<li>${esc(x)}</li>`).join("");
      box.innerHTML = `<div class="ring-wrap">
          ${renderScoreRing(rep.risk_score, rep.risk_level)}
          <div>
            <div class="row">${riskPill(rep.risk_level)}<strong>Skor: ${esc(rep.risk_score)}/100</strong></div>
            <div style="margin-top:6px; font-size:13px;">${esc(rep.summary)}</div>
          </div>
        </div>
        ${reasons ? `<ul style="margin:10px 0 0 18px; font-size:12px;">${reasons}</ul>` : ""}`;
    }

    document.getElementById("btnScanText").addEventListener("click", async () => {
      const txt = document.getElementById("scanTextInput").value;
      const r = await api("/api/scan/text", "POST", { text: txt });
      if (r.ok) showTextReport(r.report);
      else showToast(r.error || "Tarama hatası");
    });
    document.getElementById("btnScanClipFill").addEventListener("click", async () => {
      const r = await api("/api/scan/clipboard", "POST", {});
      if (r.ok) showTextReport(r.report);
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
        const canQ = rep.risk_score >= 25 && rep.file;
        return `<div style="padding:10px 0; border-bottom:1px solid var(--border);" class="ring-wrap">
          ${renderScoreRing(rep.risk_score, rep.risk_level)}
          <div style="flex:1;">
            <div class="row" style="justify-content:space-between;">
              <strong>${esc(rep.filename || rep.file)}</strong>
              <div class="row">${riskPill(rep.risk_level)}
                ${canQ ? `<button class="btn btn-sm btn-danger" data-qfile="${esc(rep.file)}">Karantinaya Al</button>` : ""}
              </div>
            </div>
            <div style="font-size:12px; color:var(--muted); margin-top:4px;">${(rep.reasons || []).map(esc).join(" · ")}</div>
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
      const r = await api("/api/browser/register", "POST", { extension_id: extId, user_only: true });
      if (r.ok) { showToast("Tarayıcı Native Host eşlendi!"); refreshAll(); }
      else showToast("Hata: " + (r.error || "eşlenemedi"));
    });

    document.getElementById("btnRunKontrol").addEventListener("click", async () => {
      const el = document.getElementById("kontrolResult");
      el.textContent = "Denetim çalıştırılıyor…";
      const r = await api("/api/kontrol");
      if (!r.ok) { el.textContent = "Denetim başarısız."; return; }
      const rep = r.report;
      const fails = (rep.bulgular || []).filter(b => b.durum === "FAIL" || b.durum === "WARN");
      el.innerHTML = `<div class="row" style="margin-bottom:10px;">
        <span class="pill ${rep.fail ? 'bad' : 'ok'}">Sonuç: ${esc(rep.worst)}</span>
        <span class="pill">Toplam: ${esc(rep.toplam)}</span>
        <span class="pill ${rep.fail ? 'bad' : 'ok'}">FAIL: ${esc(rep.fail)}</span>
        <span class="pill ${rep.warn ? 'warn' : 'ok'}">WARN: ${esc(rep.warn)}</span>
      </div>` + (fails.length ? fails.map(f => `<div class="mono" style="margin-top:4px;">${esc(f.id)}: ${esc(f.baslik)} — ${esc(f.detay)}</div>`).join("") : "<div>Tüm güvenlik kontrolleri başarılı!</div>");
    });

    document.addEventListener("keydown", e => {
      if (e.ctrlKey && !e.shiftKey && !e.altKey) {
        const idx = ["1", "2", "3", "4", "5"].indexOf(e.key);
        if (idx >= 0) {
          e.preventDefault();
          switchTab(["overview", "gamemode", "scan", "alerts", "system"][idx]);
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
