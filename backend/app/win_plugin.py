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
from datetime import datetime, timezone
from pathlib import Path

from app.game_mode import GameModeController, apply_process_priority, read_shared_game_mode
from app.notify import notify_alarm, notify_file_alarm, toast
from app.services.local_ai import load_ai_settings, save_ai_settings
from app.settings_store import default_user_config_path, find_config_file, get_explicit, machine_data_dir
from app.tray import hide_console, run_tray_loop
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


def _reg_value(hive: str, subkey: str, value_name: str = "") -> str:
    if os.name != "nt":
        return ""
    import winreg

    try:
        with winreg.OpenKey(_winreg_root(hive), subkey, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, value_name)
            return str(val or "")
    except OSError:
        return ""


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
    integrate_system: bool = False,
    preserve_existing: bool = True,
    run_self_test: bool = False,
) -> dict:
    """Chrome, Edge, Brave ve Firefox için Native Messaging host dosyalarını ve sistem kayıtlarını kurar."""
    if os.name != "nt":
        return {"ok": False, "error": "Tarayıcı Native Host kaydı yalnızca Windows'ta desteklenir."}
    if not user_only and not is_admin():
        return {"ok": False, "error": "HKLM tarayıcı kaydı için Yönetici izni gerekli (veya --user-only kullanın)."}

    from app.native_host import (
        CHROMIUM_EXT_ID_RE,
        NATIVE_HOST_NAME,
        discover_installed_extension_ids,
        test_native_host_wrapper,
        write_native_host_files,
    )

    explicit_ids: list[str] = []
    for raw_id in (extension_ids or []):
        eid = str(raw_id or "").strip().lower()
        if not eid:
            continue
        if not CHROMIUM_EXT_ID_RE.match(eid):
            return {"ok": False, "error": f"Geçersiz Chromium eklenti ID'si: {raw_id}"}
        if eid not in explicit_ids:
            explicit_ids.append(eid)

    exe = resolve_exe_path(exe_path)
    target_dir = (default_user_config_path().parent if user_only else machine_data_dir()) / "native-host"

    merged_ids: list[str] = []
    if preserve_existing:
        for eid in discover_installed_extension_ids(existing_manifest=target_dir / f"{NATIVE_HOST_NAME}.json"):
            if eid not in merged_ids:
                merged_ids.append(eid)
    for eid in explicit_ids:
        if eid not in merged_ids:
            merged_ids.append(eid)

    try:
        files = write_native_host_files(target_dir, exe, extension_ids=merged_ids or None)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    entries = build_browser_registry_entries(
        files["chromium_manifest"],
        files["firefox_manifest"],
        user_only=user_only,
    )
    sys_entries = build_registry_entries(exe, user_only=user_only) if integrate_system else []
    _apply_registry_entries(entries + sys_entries)

    self_test = test_native_host_wrapper(Path(files["wrapper"])) if run_self_test else None
    return {
        "ok": True,
        "scope": "HKCU" if user_only else "HKLM",
        "exe": exe,
        "extension_ids": merged_ids,
        "system_integrated": bool(integrate_system),
        "registry_entries": len(entries) + len(sys_entries),
        "browser": browser_status(),
        "self_test": self_test,
        **files,
    }


def browser_bridge_details() -> dict:
    """Kayıtlı tarayıcı manifestini, eşlenen uzantı kimliklerini ve wrapper durumunu döndürür."""
    from app.native_host import NATIVE_HOST_NAME

    manifest_path = ""
    for hive in ("HKCU", "HKLM"):
        for key in (CHROME_NM_KEY, EDGE_NM_KEY, BRAVE_NM_KEY):
            val = _reg_value(hive, key)
            if val:
                manifest_path = val
                break
        if manifest_path:
            break

    if not manifest_path:
        for cand_dir in (default_user_config_path().parent / "native-host", machine_data_dir() / "native-host"):
            cand = cand_dir / f"{NATIVE_HOST_NAME}.json"
            if cand.exists():
                manifest_path = str(cand)
                break

    ext_ids: list[str] = []
    wrapper_path = ""
    if manifest_path and Path(manifest_path).exists():
        try:
            mf = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
            wrapper_path = str(mf.get("path") or "")
            for orig in mf.get("allowed_origins") or []:
                s = str(orig).strip()
                if s.startswith("chrome-extension://"):
                    ext_ids.append(s.split("chrome-extension://", 1)[1].rstrip("/"))
        except Exception:
            pass

    return {
        "browsers": browser_status(),
        "manifest_path": manifest_path,
        "wrapper_path": wrapper_path,
        "wrapper_exists": bool(wrapper_path and Path(wrapper_path).is_file()),
        "extension_ids": ext_ids,
    }


_AGENT_MUTEX_NAME = r"Local\ElfSecAgentSingleton"


def autopilot_state_path() -> Path:
    """Kullanıcı dizinindeki Otopilot durum dosyası yolu."""
    return default_user_config_path().parent / "autopilot_state.json"


def read_autopilot_state(path: Path | None = None) -> dict:
    p = Path(path) if path is not None else autopilot_state_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def write_autopilot_state(patch: dict, path: Path | None = None) -> dict:
    p = Path(path) if path is not None else autopilot_state_path()
    cur = read_autopilot_state(p)
    cur.update(patch or {})
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(cur, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, p)
    except OSError:
        pass
    return cur


def _acquire_agent_mutex() -> int | None:
    """Tek-örnek (single-instance) Windows Mutex edinir; zaten çalışıyorsa None döner."""
    if os.name != "nt":
        return 1
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.CreateMutexW(None, False, _AGENT_MUTEX_NAME)
        last_err = kernel32.GetLastError()
        if not handle:
            return None
        if last_err == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(handle)
            return None
        return int(handle)
    except Exception:
        return 1


def _release_agent_mutex(handle: int | None) -> None:
    if os.name != "nt" or not handle or handle == 1:
        return
    try:
        import ctypes
        from ctypes import wintypes

        ctypes.windll.kernel32.CloseHandle(wintypes.HANDLE(handle))
    except Exception:
        pass


def _is_agent_already_running() -> bool:
    """Arka planda çalışan bir ElfSec ajanının olup olmadığını denetler."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        SYNCHRONIZE = 0x00100000
        kernel32 = ctypes.windll.kernel32
        kernel32.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
        kernel32.OpenMutexW.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.OpenMutexW(SYNCHRONIZE, False, _AGENT_MUTEX_NAME)
        if handle:
            kernel32.CloseHandle(handle)
            return True
    except Exception:
        pass
    return False


def ensure_autopilot_system_ready(start_agent: bool = False, register_system: bool = False) -> dict:
    """İstek üzerine tarayıcı köprüsü, Windows sağ-tık/otostart ve arka plan ajanını hazırlar."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    if os.name != "nt":
        return write_autopilot_state({
            "bootstrapped_at": now,
            "system_integrated": False,
            "agent_running": False,
            "browser_count": 0,
        })

    if register_system:
        reg_ok = False
        br_count = 0
        try:
            res = register_browser_hosts(
                user_only=True,
                integrate_system=True,
                preserve_existing=True,
                run_self_test=False,
            )
            reg_ok = bool(res.get("ok"))
            br_map = res.get("browser") if isinstance(res.get("browser"), dict) else browser_status()
            br_count = sum(1 for v in br_map.values() if v)
        except Exception:
            reg_ok = False
    else:
        br_map = browser_status()
        br_count = sum(1 for v in br_map.values() if v)
        reg_ok = bool(
            _reg_exists("HKLM", RUN_KEY, RUN_VALUE_NAME)
            or _reg_exists("HKCU", RUN_KEY, RUN_VALUE_NAME)
        )

    agent_running = _is_agent_already_running()
    if start_agent and not agent_running:
        try:
            launched = _launch_agent_detached(resolve_exe_path())
            if launched:
                agent_running = True
        except Exception:
            pass

    return write_autopilot_state({
        "bootstrapped_at": now,
        "system_integrated": reg_ok,
        "agent_running": agent_running,
        "browser_count": br_count,
    })


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
    """Kullanıcı oturumu ajanı: Sistem Tepsisi + Yerel AI Koruması + Servis Alarm Köprüsü."""
    del clipboard  # Pano izleme kaldırıldı (imza geriye dönük uyumluluk için korunur)
    log_path = Path(alert_log) if alert_log else (machine_data_dir() / "guard_alerts.jsonl")
    bridge = AlertBridge(log_path, seek_end=not once)
    gm = GameModeController()
    gm_state: dict = gm.evaluate() if not once else {"mode": "auto", "active": False, "process": ""}
    pending_alerts: list[dict] = []
    pending_lock = threading.Lock()

    def _emit_toast(rep: dict) -> None:
        src = rep.get("source", "")
        if src in ("file_watcher", "file_scan"):
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
        for row in bridge.poll_once():
            _dispatch_alert(row)
        return 0

    mutex_handle = _acquire_agent_mutex()
    if mutex_handle is None:
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

    def _bridge_loop() -> None:
        while not stop_event.is_set():
            for row in bridge.poll_once():
                _dispatch_alert(row)
            stop_event.wait(15.0 if gm_state.get("active") else 2.0)

    threading.Thread(target=_bridge_loop, daemon=True).start()

    def _autopilot_watch_loop() -> None:
        from app.privacy import load_privacy_settings

        watch_state = FileWatchState(default_user_config_path().parent / ".autopilot_watch_seen.json")
        user_alert_log = str(default_user_config_path().parent / "guard_alerts.jsonl")
        dirs = default_watch_dirs(all_users=False, include_mail_apps=True)

        # İlk açılışta zaten var olan dosyaları sıfırdan alarm yağmuruna tutmamak için durum yüklenir;
        # daha önce hiç görülmemiş dosyalar yine incelenir.
        while not stop_event.is_set():
            try:
                ai_cfg = load_ai_settings()
                if ai_cfg.get("autopilot", True):
                    mask_logs = bool(load_privacy_settings().get("kvkk_mask_logs", True))
                    scanned, alerts = scan_watch_dirs_once(
                        dirs,
                        watch_state,
                        alert_on=alert_on,
                        alert_log=user_alert_log,
                        notify=bool(notify and ai_cfg.get("notify_on_ai_alert", True)),
                        redact=mask_logs,
                        auto_protect=True,
                    )
                    prev = read_autopilot_state()
                    auto_q = sum(1 for a in alerts if a.get("auto_protected"))
                    write_autopilot_state({
                        "last_scan_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                        "agent_running": True,
                        "watched_dirs_count": len(dirs),
                        "last_scanned_count": len(scanned),
                        "total_scanned": int(prev.get("total_scanned") or 0) + len(scanned),
                        "total_auto_quarantined": int(prev.get("total_auto_quarantined") or 0) + auto_q,
                    })
            except Exception:
                pass
            stop_event.wait(120.0 if gm_state.get("active") else 10.0)

    threading.Thread(target=_autopilot_watch_loop, daemon=True).start()

    def _cb_scan_downloads() -> None:
        dirs = default_watch_dirs(all_users=False)
        st = FileWatchState(default_user_config_path().parent / ".agent_watch_seen.json")
        scanned, alerts = scan_watch_dirs_once(dirs, st, alert_on=alert_on, notify=True, auto_protect=True)
        if not alerts:
            toast("ElfSec İndirilenler Taraması", f"{len(scanned)} yeni dosya tarandı, tehdit yok.")

    def _cb_toggle_ai() -> None:
        try:
            cur = bool(load_ai_settings().get("enabled", True))
            upd = save_ai_settings({"enabled": not cur})
            now_on = bool(upd.get("enabled", True))
        except Exception:
            now_on = True
        toast(
            "ElfSec Yerel AI Güvenlik",
            "Entegre Yerel AI koruması AÇIK." if now_on else "Entegre Yerel AI koruması KAPALI.",
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
        ai_on = bool(load_ai_settings().get("enabled", True))
        gm_info = gm_state if gm_state else st.get("game_mode", {})
        if gm_info.get("active"):
            gm_txt = f"AKTİF ({gm_info.get('process') or 'düşük güç'})"
        else:
            gm_txt = "Otomatik" if gm_info.get("mode", "auto") == "auto" else "Kapalı"
        toast(
            "ElfSec Güvenlik Durumu",
            f"Servis: {svc.get('state')} | Yerel AI: {'AÇIK' if ai_on else 'KAPALI'} | "
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
        "scan_downloads": _cb_scan_downloads,
        "toggle_ai": _cb_toggle_ai,
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
        _release_agent_mutex(mutex_handle)
        apply_process_priority(False)
        with panel_lock:
            srv = panel_box["server"]
            if srv is not None:
                try:
                    srv.stop()
                except Exception:
                    pass
