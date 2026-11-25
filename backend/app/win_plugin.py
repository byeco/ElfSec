"""Windows Güvenlik Eklentisi Entegrasyonu: Sağ-tık menüsü, protokol, otostart ajan ve AlertBridge.

Mimari:
- Arka plan Windows Servisi (`ElfSecGuard`) SYSTEM yetkisinde çalışır, tüm
  kullanıcıların İndirilenler klasörünü + IMAP kutusunu tarar ve alarmları
  ProgramData\\ElfSec\\guard_alerts.jsonl dosyasına yazar.
- Kullanıcı oturumundaki ajan (`elfsec.exe agent --tray`) Sistem Tepsisi ikonunu,
  Pano/ClickFix korumasını ve AlertBridge (servis alarmlarını anında Windows Toast
  olarak kullanıcıya gösterme) köprüsünü çalıştırır.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from app.game_mode import GameModeController, apply_process_priority, read_shared_game_mode
from app.notify import notify_alarm, notify_clipboard_alarm, notify_file_alarm, toast
from app.privacy import load_privacy_settings, sanitize_alert_for_storage, save_privacy_settings
from app.settings_store import default_user_config_path, find_config_file, get_explicit, machine_data_dir
from app.tray import hide_console, run_tray_loop
from app.watchers.clipboard_guard import ClipboardGuard
from app.watchers.file_watcher import FileWatchState, default_watch_dirs, scan_watch_dirs_once
from app.win_service import (
    install_service,
    is_admin,
    resolve_exe_path,
    service_status,
    start_service,
    uninstall_service,
)

LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

SHELL_FILE_KEY = r"Software\Classes\*\shell\ElfSecScan"
SHELL_DIR_KEY = r"Software\Classes\Directory\shell\ElfSecScan"
EML_SHELL_KEY = r"Software\Classes\SystemFileAssociations\.eml\shell\ElfSecMailScan"
MSG_SHELL_KEY = r"Software\Classes\SystemFileAssociations\.msg\shell\ElfSecMailScan"
PROTOCOL_KEY = r"Software\Classes\elfsec"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE_NAME = "ElfSecAgent"

CHROME_NM_KEY = r"SOFTWARE\Google\Chrome\NativeMessagingHosts\com.elfsec.guard"
EDGE_NM_KEY = r"SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.elfsec.guard"
BRAVE_NM_KEY = r"SOFTWARE\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.elfsec.guard"
FIREFOX_NM_KEY = r"SOFTWARE\Mozilla\NativeMessagingHosts\com.elfsec.guard"


def build_registry_entries(exe_path: str, user_only: bool = False) -> list[dict]:
    """Windows Kayıt Defteri girdilerini saf veri olarak üretir (test edilebilir)."""
    hive = "HKCU" if user_only else "HKLM"
    exe_p = str(exe_path)
    if exe_p.lower().endswith(("python.exe", "pythonw.exe")):
        scan_cmd = f'"{exe_p}" -m app.cli scan-path "%1" --notify --pause'
        proto_cmd = f'"{exe_p}" -m app.cli "%1"'
        agent_cmd = f'"{exe_p}" -m app.cli agent --tray'
    else:
        scan_cmd = f'"{exe_p}" scan-path "%1" --notify --pause'
        proto_cmd = f'"{exe_p}" "%1"'
        agent_cmd = f'"{exe_p}" agent --tray'

    return [
        {
            "hive": hive,
            "path": SHELL_FILE_KEY,
            "values": {"": "ElfSec ile Güvenlik Taraması", "Icon": f"{exe_p},0"},
        },
        {
            "hive": hive,
            "path": f"{SHELL_FILE_KEY}\\command",
            "values": {"": scan_cmd},
        },
        {
            "hive": hive,
            "path": SHELL_DIR_KEY,
            "values": {"": "ElfSec ile Klasör Taraması", "Icon": f"{exe_p},0"},
        },
        {
            "hive": hive,
            "path": f"{SHELL_DIR_KEY}\\command",
            "values": {"": scan_cmd},
        },
        {
            "hive": hive,
            "path": EML_SHELL_KEY,
            "values": {"": "ElfSec ile E-posta Analizi", "Icon": f"{exe_p},0"},
        },
        {
            "hive": hive,
            "path": f"{EML_SHELL_KEY}\\command",
            "values": {"": scan_cmd},
        },
        {
            "hive": hive,
            "path": MSG_SHELL_KEY,
            "values": {"": "ElfSec ile E-posta Analizi", "Icon": f"{exe_p},0"},
        },
        {
            "hive": hive,
            "path": f"{MSG_SHELL_KEY}\\command",
            "values": {"": scan_cmd},
        },
        {
            "hive": hive,
            "path": PROTOCOL_KEY,
            "values": {"": "URL:ElfSec Protocol", "URL Protocol": ""},
        },
        {
            "hive": hive,
            "path": f"{PROTOCOL_KEY}\\shell\\open\\command",
            "values": {"": proto_cmd},
        },
        {
            "hive": hive,
            "path": RUN_KEY,
            "values": {RUN_VALUE_NAME: agent_cmd},
        },
    ]


def build_browser_registry_entries(
    chromium_manifest: str,
    firefox_manifest: str,
    user_only: bool = False,
) -> list[dict]:
    """Chrome, Edge, Brave ve Firefox NativeMessagingHosts kayıtlarını üretir."""
    hive = "HKCU" if user_only else "HKLM"
    return [
        {"hive": hive, "path": CHROME_NM_KEY, "values": {"": str(chromium_manifest)}},
        {"hive": hive, "path": EDGE_NM_KEY, "values": {"": str(chromium_manifest)}},
        {"hive": hive, "path": BRAVE_NM_KEY, "values": {"": str(chromium_manifest)}},
        {"hive": hive, "path": FIREFOX_NM_KEY, "values": {"": str(firefox_manifest)}},
    ]


def _winreg_root(hive: str):
    import winreg

    return winreg.HKEY_CURRENT_USER if hive == "HKCU" else winreg.HKEY_LOCAL_MACHINE


def _apply_registry_entries(entries: list[dict]) -> None:
    if os.name != "nt":
        return
    import winreg

    for ent in entries:
        root = _winreg_root(ent["hive"])
        with winreg.CreateKeyEx(root, ent["path"], 0, winreg.KEY_WRITE) as key:
            for name, val in ent["values"].items():
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(val))


def _delete_tree_safe(root, subkey: str) -> None:
    import winreg

    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            while True:
                try:
                    child = winreg.EnumKey(key, 0)
                    _delete_tree_safe(root, f"{subkey}\\{child}")
                except OSError:
                    break
        winreg.DeleteKey(root, subkey)
    except OSError:
        pass


def _reg_exists(hive: str, subkey: str, value_name: str | None = None) -> bool:
    if os.name != "nt":
        return False
    import winreg

    try:
        with winreg.OpenKey(_winreg_root(hive), subkey, 0, winreg.KEY_READ) as key:
            if value_name is not None:
                winreg.QueryValueEx(key, value_name)
            return True
    except OSError:
        return False


def _remove_registry_entries(user_only: bool = False) -> None:
    if os.name != "nt":
        return
    import winreg

    hives = ["HKCU"] if user_only else ["HKLM", "HKCU"]
    for h in hives:
        root = _winreg_root(h)
        for sub in (SHELL_FILE_KEY, SHELL_DIR_KEY, EML_SHELL_KEY, MSG_SHELL_KEY, PROTOCOL_KEY):
            _delete_tree_safe(root, sub)
        try:
            with winreg.OpenKey(root, RUN_KEY, 0, winreg.KEY_WRITE) as key:
                winreg.DeleteValue(key, RUN_VALUE_NAME)
        except OSError:
            pass


def register_browser_hosts(
    exe_path: str = "",
    user_only: bool = False,
    extension_ids: list[str] | None = None,
) -> dict:
    """Chrome, Edge, Brave ve Firefox için Native Messaging host dosyalarını ve kayıtlarını kurar."""
    if os.name != "nt":
        return {"ok": False, "error": "Tarayıcı Native Host kaydı yalnızca Windows'ta desteklenir."}
    if not user_only and not is_admin():
        return {"ok": False, "error": "HKLM tarayıcı kaydı için Yönetici izni gerekli (veya --user-only kullanın)."}

    from app.native_host import write_native_host_files

    exe = resolve_exe_path(exe_path)
    target_dir = (default_user_config_path().parent if user_only else machine_data_dir()) / "native-host"
    try:
        files = write_native_host_files(target_dir, exe, extension_ids=extension_ids)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    entries = build_browser_registry_entries(
        files["chromium_manifest"],
        files["firefox_manifest"],
        user_only=user_only,
    )
    _apply_registry_entries(entries)
    return {
        "ok": True,
        "scope": "HKCU" if user_only else "HKLM",
        "registry_entries": len(entries),
        **files,
    }


def unregister_browser_hosts(user_only: bool = False) -> dict:
    """Tarayıcı Native Messaging kayıtlarını temizler."""
    if os.name != "nt":
        return {"ok": False, "error": "Yalnızca Windows'ta desteklenir."}
    hives = ["HKCU"] if user_only else ["HKLM", "HKCU"]
    for h in hives:
        root = _winreg_root(h)
        for sub in (CHROME_NM_KEY, EDGE_NM_KEY, BRAVE_NM_KEY, FIREFOX_NM_KEY):
            _delete_tree_safe(root, sub)
    return {"ok": True, "removed": True}


def browser_status() -> dict:
    """Chrome/Edge/Brave/Firefox Native Host kayıt durumunu döndürür."""
    return {
        "chrome": _reg_exists("HKLM", CHROME_NM_KEY) or _reg_exists("HKCU", CHROME_NM_KEY),
        "edge": _reg_exists("HKLM", EDGE_NM_KEY) or _reg_exists("HKCU", EDGE_NM_KEY),
        "brave": _reg_exists("HKLM", BRAVE_NM_KEY) or _reg_exists("HKCU", BRAVE_NM_KEY),
        "firefox": _reg_exists("HKLM", FIREFOX_NM_KEY) or _reg_exists("HKCU", FIREFOX_NM_KEY),
    }


class AlertBridge:
    """Servisin yazdığı guard_alerts.jsonl dosyasını takip eder (yeni satırları Toast yapar)."""

    def __init__(self, alert_log: str | Path, seek_end: bool = True):
        self.alert_log = Path(alert_log)
        self._offset: int = 0
        if seek_end and self.alert_log.exists():
            try:
                self._offset = self.alert_log.stat().st_size
            except OSError:
                self._offset = 0

    def poll_once(self) -> list[dict]:
        """Son okuma noktasından sonra eklenmiş yeni alarm satırlarını döndür."""
        if not self.alert_log.exists():
            self._offset = 0
            return []
        try:
            size = self.alert_log.stat().st_size
            if size < self._offset:
                self._offset = 0
            if size == self._offset:
                return []
            with open(self.alert_log, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(self._offset)
                chunk = fh.read()
                self._offset = fh.tell()
        except OSError:
            return []

        alerts: list[dict] = []
        for line in chunk.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    alerts.append(obj)
            except Exception:
                continue
        return alerts


def _launch_agent_detached(exe_path: str) -> bool:
    if os.name != "nt":
        return False
    try:
        if exe_path.lower().endswith(("python.exe", "pythonw.exe")):
            cmd = [exe_path, "-m", "app.cli", "agent", "--tray"]
        else:
            cmd = [exe_path, "agent", "--tray"]
        flags = 0x08000000 | 0x00000008  # CREATE_NO_WINDOW | DETACHED_PROCESS
        subprocess.Popen(cmd, creationflags=flags, close_fds=True)
        return True
    except Exception:
        return False


def install_plugin(
    exe_path: str = "",
    user_only: bool = False,
    with_service: bool = True,
    start_now: bool = True,
    extension_ids: list[str] | None = None,
) -> dict:
    """Windows Güvenlik Eklentisini (servis + sağ-tık + tarayıcı Native Host + tepsi) tek komutla kurar."""
    if os.name != "nt":
        return {"ok": False, "error": "Windows Güvenlik Eklentisi yalnızca Windows'ta kurulabilir."}
    if not user_only and not is_admin():
        return {
            "ok": False,
            "error": "Sistem geneli eklenti + Windows Servisi için Yönetici izni (UAC) gerekli.",
        }

    exe = resolve_exe_path(exe_path)
    entries = build_registry_entries(exe, user_only=user_only)
    _apply_registry_entries(entries)
    browser_res = register_browser_hosts(exe_path=exe, user_only=user_only, extension_ids=extension_ids)

    svc_ok = True
    svc_msg = "Servis kurulumu atlandı."
    if with_service and not user_only:
        svc_ok, svc_msg = install_service(exe_path=exe)
        if svc_ok and start_now:
            st_ok, st_msg = start_service()
            svc_msg = f"{svc_msg} | {st_msg}"
            svc_ok = svc_ok and st_ok

    agent_started = False
    if start_now:
        agent_started = _launch_agent_detached(exe)

    return {
        "ok": svc_ok and bool(browser_res.get("ok", True)),
        "exe": exe,
        "scope": "HKCU" if user_only else "HKLM",
        "registry_entries": len(entries) + int(browser_res.get("registry_entries", 0)),
        "browser": browser_res,
        "service_message": svc_msg,
        "agent_started": agent_started,
    }


def uninstall_plugin(user_only: bool = False) -> dict:
    """Windows Güvenlik Eklentisi kayıtlarını, tarayıcı köprüsünü ve servisi temizler."""
    if os.name != "nt":
        return {"ok": False, "error": "Yalnızca Windows'ta desteklenir."}
    svc_ok = True
    svc_msg = ""
    if not user_only:
        svc_ok, svc_msg = uninstall_service()
    _remove_registry_entries(user_only=user_only)
    unregister_browser_hosts(user_only=user_only)
    return {"ok": svc_ok, "service_message": svc_msg, "removed_registry": True}


def plugin_status() -> dict:
    """Eklenti, servis, sağ-tık menüsü, tarayıcı köprüsü ve alarm log durumunu özetler."""
    m_dir = machine_data_dir()
    alert_log = m_dir / "guard_alerts.jsonl"
    if not alert_log.exists():
        local_log = Path("guard_alerts.jsonl")
        if local_log.exists():
            alert_log = local_log

    recent = 0
    if alert_log.exists():
        try:
            recent = len([ln for ln in alert_log.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()])
        except OSError:
            pass

    return {
        "os": os.name,
        "is_admin": is_admin(),
        "service": service_status(),
        "browser": browser_status(),
        "context_menu_files": _reg_exists("HKLM", SHELL_FILE_KEY) or _reg_exists("HKCU", SHELL_FILE_KEY),
        "context_menu_dirs": _reg_exists("HKLM", SHELL_DIR_KEY) or _reg_exists("HKCU", SHELL_DIR_KEY),
        "protocol_registered": _reg_exists("HKLM", PROTOCOL_KEY) or _reg_exists("HKCU", PROTOCOL_KEY),
        "agent_autostart": (
            _reg_exists("HKLM", RUN_KEY, RUN_VALUE_NAME)
            or _reg_exists("HKCU", RUN_KEY, RUN_VALUE_NAME)
        ),
        "config_file": str(find_config_file(get_explicit()) or "(yok — varsayılanlar)"),
        "machine_data_dir": str(m_dir),
        "alert_log": str(alert_log),
        "alert_log_exists": alert_log.exists(),
        "alerts_count": recent,
        "game_mode": read_shared_game_mode(),
    }


def _open_terminal_command(cmd_args: list[str]) -> None:
    if os.name != "nt":
        return
    exe = resolve_exe_path()
    if exe.lower().endswith(("python.exe", "pythonw.exe")):
        cmd = ["cmd.exe", "/k", exe, "-m", "app.cli", *cmd_args]
    else:
        cmd = ["cmd.exe", "/k", exe, *cmd_args]
    try:
        subprocess.Popen(cmd, creationflags=0x00000010)  # CREATE_NEW_CONSOLE
    except Exception:
        pass


def run_agent(
    tray: bool = True,
    clipboard: bool | None = None,
    alert_log: str = "",
    alert_on: str = "HIGH",
    notify: bool = True,
    once: bool = False,
) -> int:
    """Kullanıcı oturumu ajanı: Sistem Tepsisi + KVKK Uyumlu Pano Koruması + Servis Alarm Köprüsü."""
    log_path = Path(alert_log) if alert_log else (machine_data_dir() / "guard_alerts.jsonl")
    bridge = AlertBridge(log_path, seek_end=not once)
    clip_enabled = bool(load_privacy_settings().get("clipboard_auto_watch", False)) if clipboard is None else bool(clipboard)
    clip_guard = ClipboardGuard(enabled=clip_enabled, strict_kvkk=True)
    gm = GameModeController()
    gm_state: dict = gm.evaluate() if not once else {"mode": "auto", "active": False, "process": ""}
    pending_alerts: list[dict] = []
    pending_lock = threading.Lock()

    def _emit_toast(rep: dict) -> None:
        src = rep.get("source", "")
        if src == "clipboard":
            notify_clipboard_alarm(rep)
        elif src in ("file_watcher", "file_scan"):
            notify_file_alarm(rep)
        else:
            notify_alarm(rep)

    def _dispatch_alert(rep: dict) -> None:
        if not notify:
            return
        if gm_state.get("active") and str(rep.get("risk_level", "")).upper() != "CRITICAL":
            with pending_lock:
                if len(pending_alerts) < 50:
                    pending_alerts.append(rep)
            return
        _emit_toast(rep)

    if once:
        if clip_guard.enabled:
            rep = clip_guard.check_once(force=True)
            if rep and LEVEL_ORDER.get(rep.get("risk_level", "LOW"), 0) >= LEVEL_ORDER.get(alert_on.upper(), 1):
                _dispatch_alert(rep)
        for row in bridge.poll_once():
            _dispatch_alert(row)
        return 0

    if tray:
        hide_console()

    stop_event = threading.Event()
    apply_process_priority(bool(gm_state.get("active")))

    def _flush_pending() -> None:
        with pending_lock:
            queued = list(pending_alerts)
            pending_alerts.clear()
        if not queued or not notify:
            return
        if len(queued) <= 2:
            for item in queued:
                _emit_toast(item)
        else:
            toast(
                "ElfSec Oyun Sonrası Özeti",
                f"Oyun sırasında {len(queued)} güvenlik uyarısı kaydedildi. Ayrıntılar için Güvenlik Panelini açın.",
            )

    def _game_mode_loop() -> None:
        while not stop_event.is_set():
            prev_active = bool(gm_state.get("active"))
            try:
                st = gm.evaluate()
                gm_state.update(st)
                now_active = bool(st.get("active"))
                apply_process_priority(now_active)
                if prev_active and not now_active:
                    _flush_pending()
            except Exception:
                pass
            stop_event.wait(5.0)

    threading.Thread(target=_game_mode_loop, daemon=True).start()

    def _on_clip_alert(rep: dict) -> None:
        _dispatch_alert(rep)
        try:
            mask = bool(load_privacy_settings().get("kvkk_mask_logs", True))
            safe_rep = sanitize_alert_for_storage(rep, mask=mask)
            u_log = default_user_config_path().parent / "clipboard_alerts.jsonl"
            u_log.parent.mkdir(parents=True, exist_ok=True)
            with open(u_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(safe_rep, ensure_ascii=False, default=str) + "\n")
        except Exception:
            pass

    def _clip_interval() -> float:
        if clipboard is None:
            try:
                clip_guard.enabled = bool(load_privacy_settings().get("clipboard_auto_watch", False))
            except Exception:
                pass
        return 15.0 if gm_state.get("active") else 1.5

    if clipboard is not False:
        threading.Thread(
            target=clip_guard.run_loop,
            args=(stop_event, 1.5, "MEDIUM", _on_clip_alert),
            kwargs={"interval_fn": _clip_interval},
            daemon=True,
        ).start()

    def _bridge_loop() -> None:
        while not stop_event.is_set():
            for row in bridge.poll_once():
                _dispatch_alert(row)
            stop_event.wait(15.0 if gm_state.get("active") else 2.0)

    threading.Thread(target=_bridge_loop, daemon=True).start()

    def _cb_scan_clipboard() -> None:
        rep = clip_guard.check_once(force=True)
        if not rep:
            toast("ElfSec Pano Taraması", "Pano boş veya metin içermiyor.")
        elif LEVEL_ORDER.get(rep.get("risk_level", "LOW"), 0) >= LEVEL_ORDER.get("MEDIUM", 1):
            notify_clipboard_alarm(rep)
        else:
            toast("ElfSec Pano Taraması", f"Temiz (skor {rep['risk_score']}/100).")

    def _cb_scan_downloads() -> None:
        dirs = default_watch_dirs(all_users=False)
        st = FileWatchState(default_user_config_path().parent / ".agent_watch_seen.json")
        scanned, alerts = scan_watch_dirs_once(dirs, st, alert_on=alert_on, notify=True)
        if not alerts:
            toast("ElfSec İndirilenler Taraması", f"{len(scanned)} yeni dosya tarandı, tehdit yok.")

    def _cb_toggle_clip() -> None:
        now_on = clip_guard.toggle()
        try:
            save_privacy_settings({"clipboard_auto_watch": now_on})
        except Exception:
            pass
        toast(
            "ElfSec Pano Koruması (KVKK)",
            "ClickFix pano koruması AÇIK (yalnızca komut/URL)." if now_on else "Arka plan pano izleme KAPALI.",
        )

    def _cb_toggle_game_mode() -> None:
        cur = str(gm_state.get("mode", "auto"))
        nxt = {"auto": "on", "on": "off", "off": "auto"}.get(cur, "auto")
        st = gm.set_mode(nxt)
        gm_state.update(st)
        apply_process_priority(bool(st.get("active")))
        if not st.get("active"):
            _flush_pending()
        labels = {
            "auto": "Otomatik (oyun algılanınca düşük güç)",
            "on": "Açık (ultra-düşük kaynak modu)",
            "off": "Kapalı (tam koruma)",
        }
        toast("ElfSec Oyun Modu", labels.get(nxt, nxt))

    def _cb_status() -> None:
        st = plugin_status()
        svc = st.get("service", {})
        gm_info = gm_state if gm_state else st.get("game_mode", {})
        if gm_info.get("active"):
            gm_txt = f"AKTİF ({gm_info.get('process') or 'düşük güç'})"
        else:
            gm_txt = "Otomatik" if gm_info.get("mode", "auto") == "auto" else "Kapalı"
        toast(
            "ElfSec Güvenlik Durumu",
            f"Servis: {svc.get('state')} | Pano: {'AÇIK' if clip_guard.enabled else 'KAPALI'} | "
            f"Oyun Modu: {gm_txt} | Alarmlar: {st.get('alerts_count', 0)}",
        )

    panel_box: dict = {"server": None}
    panel_lock = threading.Lock()

    def _cb_dashboard() -> None:
        try:
            cmd = (
                [sys.executable, "ui"]
                if getattr(sys, "frozen", False)
                else [sys.executable, "-m", "app.cli", "ui"]
            )
            flags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
            subprocess.Popen(cmd, creationflags=flags, close_fds=True)
            return
        except Exception:
            pass
        try:
            from app.desktop_ui import DesktopPanelServer, open_app_window

            with panel_lock:
                srv = panel_box["server"]
                if srv is None:
                    srv = DesktopPanelServer(controller=gm)
                    srv.start()
                    panel_box["server"] = srv
            open_app_window(srv.url)
        except Exception:
            _open_terminal_command(["dashboard"])

    callbacks = {
        "scan_clipboard": _cb_scan_clipboard,
        "scan_downloads": _cb_scan_downloads,
        "toggle_clipboard": _cb_toggle_clip,
        "toggle_game_mode": _cb_toggle_game_mode,
        "status": _cb_status,
        "dashboard": _cb_dashboard,
    }

    try:
        if tray:
            shown = run_tray_loop(stop_event=stop_event, tooltip="ElfSec Güvenlik Eklentisi", callbacks=callbacks)
            if shown:
                stop_event.set()
                return 0

        try:
            while not stop_event.is_set():
                time.sleep(1.0)
        except KeyboardInterrupt:
            stop_event.set()
        return 0
    finally:
        apply_process_priority(False)
        with panel_lock:
            srv = panel_box["server"]
            if srv is not None:
                try:
                    srv.stop()
                except Exception:
                    pass
