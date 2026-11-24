"""Native Windows Service (SYSTEM / Yönetici) + Birleşik Arka Plan Koruma Koşucusu.

Ek bağımlılık kurmadan (yalnızca stdlib + ctypes + sc.exe) gerçek Windows Servisi
olarak çalışır:
- Hem tüm kullanıcıların İndirilenler klasörlerini (file_watcher),
- Hem de yapılandırılmışsa IMAP posta kutusunu (mail guard) periyodik tarar.
- Sonucu ProgramData\\ElfSec\\service_status.json ve guard_alerts.jsonl dosyalarına yazar;
  kullanıcı oturumundaki tray/agent süreci bu alarmları Windows Toast olarak gösterir.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from app.settings_store import machine_data_dir
from app.watchers.file_watcher import FileWatchState, default_watch_dirs, scan_watch_dirs_once

SERVICE_NAME = "ElfSecGuard"
SERVICE_DISPLAY = "ElfSec Güvenlik Servisi"
SERVICE_DESC = "ElfSec arka plan e-posta, İndirilenler ve Windows güvenlik eklentisi servisi."


def is_admin() -> bool:
    """Mevcut süreç Yönetici (Windows) veya root (POSIX) yetkisinde mi?"""
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def resolve_exe_path(explicit: str = "") -> str:
    """Servis ve kayıt defteri kayıtları için kullanılacak elfsec.exe yolunu çözer."""
    if explicit:
        return str(Path(explicit).resolve())
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve())
    dist_exe = Path(__file__).resolve().parents[1] / "dist" / "elfsec.exe"
    if dist_exe.exists():
        return str(dist_exe.resolve())
    return str(Path(sys.executable).resolve())


def _format_bin_path(
    exe_path: str,
    config_path: str = "",
    watch_interval: int = 10,
    mail_interval: int = 10,
    action: str = "notify-only",
) -> str:
    exe_p = str(exe_path)
    if exe_p.lower().endswith(("python.exe", "pythonw.exe")):
        cmd = f'"{exe_p}" -m app.cli'
    else:
        cmd = f'"{exe_p}"'
    if config_path:
        cmd += f' --config "{config_path}"'
    cmd += (
        f" service run --watch-interval {max(2, int(watch_interval))}"
        f" --mail-interval {max(1, int(mail_interval))}"
        f" --action {action}"
    )
    return cmd


def build_sc_create_args(
    exe_path: str,
    config_path: str = "",
    watch_interval: int = 10,
    mail_interval: int = 10,
    action: str = "notify-only",
) -> list[str]:
    """sc.exe create komut argüman listesini üretir (saf fonksiyon)."""
    bin_path = _format_bin_path(exe_path, config_path, watch_interval, mail_interval, action)
    return [
        "sc.exe",
        "create",
        SERVICE_NAME,
        "binPath=",
        bin_path,
        "start=",
        "auto",
        "DisplayName=",
        SERVICE_DISPLAY,
    ]


def ensure_machine_data_dir() -> Path:
    """ProgramData\\ElfSec dizinini oluştur ve kullanıcı okuma / yönetici yazma ACL'sini kur."""
    d = machine_data_dir()
    d.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        try:
            subprocess.run(
                ["icacls", str(d), "/grant", "SYSTEM:(OI)(CI)F",
                 "Administrators:(OI)(CI)F", "Users:(OI)(CI)RX"],
                capture_output=True, timeout=10, check=False,
            )
        except Exception:
            pass
    return d


def _run_sc(args: list[str]) -> tuple[int, str]:
    r = subprocess.run(args, capture_output=True, timeout=20, check=False)
    out = (
        (r.stdout or b"").decode("utf-8", errors="replace")
        + "\n"
        + (r.stderr or b"").decode("utf-8", errors="replace")
    ).strip()
    return r.returncode, out


def install_service(
    exe_path: str = "",
    config_path: str = "",
    watch_interval: int = 10,
    mail_interval: int = 10,
    action: str = "notify-only",
) -> tuple[bool, str]:
    """Windows Servisini kurar (Yönetici yetkisi gerekir)."""
    if os.name != "nt":
        return False, "Windows Servisi yalnızca Windows üzerinde kurulabilir."
    if not is_admin():
        return False, "Yönetici izni (UAC) gerekli. PowerShell'i 'Yönetici olarak çalıştır' ile açın."

    ensure_machine_data_dir()
    exe = resolve_exe_path(exe_path)
    # Varsa durdur ve güncellemek için önce sil
    _run_sc(["sc.exe", "stop", SERVICE_NAME])
    _run_sc(["sc.exe", "delete", SERVICE_NAME])

    rc, out = _run_sc(build_sc_create_args(exe, config_path, watch_interval, mail_interval, action))
    if rc != 0:
        return False, f"Servis oluşturulamadı (rc={rc}): {out}"
    _run_sc(["sc.exe", "description", SERVICE_NAME, SERVICE_DESC])
    _run_sc(["sc.exe", "failure", SERVICE_NAME, "reset=", "86400",
             "actions=", "restart/5000/restart/10000/restart/30000"])
    return True, f"Servis kuruldu: {SERVICE_NAME} -> {exe}"


def start_service() -> tuple[bool, str]:
    if os.name != "nt":
        return False, "Yalnızca Windows'ta desteklenir."
    rc, out = _run_sc(["sc.exe", "start", SERVICE_NAME])
    if rc == 0 or "1056" in out:  # 1056 = already running
        return True, f"Servis çalışıyor ({SERVICE_NAME})."
    return False, f"Servis başlatılamadı (rc={rc}): {out}"


def stop_service() -> tuple[bool, str]:
    if os.name != "nt":
        return False, "Yalnızca Windows'ta desteklenir."
    rc, out = _run_sc(["sc.exe", "stop", SERVICE_NAME])
    if rc == 0 or "1062" in out:  # 1062 = not started
        return True, f"Servis durduruldu ({SERVICE_NAME})."
    return False, f"Servis durdurulamadı (rc={rc}): {out}"


def uninstall_service() -> tuple[bool, str]:
    if os.name != "nt":
        return False, "Yalnızca Windows'ta desteklenir."
    if not is_admin():
        return False, "Servis kaldırmak için Yönetici izni gerekli."
    _run_sc(["sc.exe", "stop", SERVICE_NAME])
    time.sleep(0.5)
    rc, out = _run_sc(["sc.exe", "delete", SERVICE_NAME])
    if rc == 0 or "1060" in out:  # 1060 = does not exist
        return True, f"Servis kaldırıldı ({SERVICE_NAME})."
    return False, f"Servis silinemedi (rc={rc}): {out}"


def service_status() -> dict:
    """Servisin SCM durumunu ve son heartbeat dosyasını döndürür."""
    info: dict = {
        "service_name": SERVICE_NAME,
        "installed": False,
        "running": False,
        "state": "UNAVAILABLE",
        "heartbeat": "",
        "watch_dirs": [],
        "imap_status": "unknown",
        "alerts_total": 0,
    }
    if os.name == "nt":
        try:
            rc, out = _run_sc(["sc.exe", "query", SERVICE_NAME])
            if rc == 0:
                info["installed"] = True
                up = out.upper()
                if "RUNNING" in up:
                    info["state"] = "RUNNING"
                    info["running"] = True
                elif "START_PENDING" in up:
                    info["state"] = "START_PENDING"
                elif "STOP_PENDING" in up:
                    info["state"] = "STOP_PENDING"
                elif "STOPPED" in up:
                    info["state"] = "STOPPED"
                else:
                    info["state"] = "UNKNOWN"
            else:
                info["state"] = "NOT_INSTALLED"
        except Exception as e:
            info["state"] = f"ERROR: {e}"

    status_file = machine_data_dir() / "service_status.json"
    if status_file.exists():
        try:
            hb = json.loads(status_file.read_text(encoding="utf-8"))
            if isinstance(hb, dict):
                info.update({
                    "heartbeat": hb.get("updated_at", ""),
                    "watch_dirs": hb.get("watch_dirs", []),
                    "imap_status": hb.get("imap_status", "unknown"),
                    "alerts_total": hb.get("alerts_total", 0),
                })
        except Exception:
            pass
    return info


class ServiceRunner:
    """Windows Servisi (veya önplan test) içinde çalışan birleşik koruma döngüsü."""

    def __init__(
        self,
        data_dir: Path | None = None,
        watch_dirs: list[Path] | None = None,
        watch_interval_sec: int = 10,
        mail_interval_min: int = 10,
        alert_on: str = "HIGH",
        action: str = "notify-only",
        folder: str = "INBOX",
        limit: int = 20,
        unseen: bool = True,
        notify: bool = False,
        enable_mail: bool = True,
    ):
        self.data_dir = Path(data_dir) if data_dir else machine_data_dir()
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            from app.settings_store import default_user_config_path

            self.data_dir = default_user_config_path().parent / "service_data"
            self.data_dir.mkdir(parents=True, exist_ok=True)
        self.watch_dirs = (
            list(watch_dirs)
            if watch_dirs is not None
            else default_watch_dirs(all_users=True, include_mail_apps=True)
        )
        self.watch_interval_sec = max(2, int(watch_interval_sec))
        self.mail_interval_sec = max(60, int(mail_interval_min) * 60)
        self.alert_on = alert_on
        self.action = action
        self.folder = folder
        self.limit = limit
        self.unseen = unseen
        self.notify = notify
        self.enable_mail = enable_mail

        self.alert_log = self.data_dir / "guard_alerts.jsonl"
        self.status_file = self.data_dir / "service_status.json"
        self.file_state = FileWatchState(self.data_dir / ".watch_seen.json")
        self.mail_state_path = str(self.data_dir / ".guard_seen.json")
        self.quarantine_dir = self.data_dir / "quarantine"
        self._last_mail_ts: float = 0.0
        self._alerts_total: int = 0
        self._imap_status: str = "disabled" if not enable_mail else "pending"

    def _run_mail_cycle(self) -> int:
        from app.cli import _guard_cycle, _imap_auth, _load_seen
        from app.settings_store import current_settings

        try:
            s = current_settings()
            pw, tok, _method = _imap_auth(s)
        except Exception as e:
            self._imap_status = f"error-config: {e}"
            return 0
        if not pw and not tok:
            self._imap_status = "unconfigured"
            return 0

        seen = _load_seen(self.mail_state_path)
        ns = argparse.Namespace(
            folder=self.folder,
            limit=self.limit,
            unseen=self.unseen,
            interval=max(1, self.mail_interval_sec // 60),
            alert_on=self.alert_on,
            alert_log=str(self.alert_log),
            state=self.mail_state_path,
            webhook="",
            webhook_header=[],
            once=True,
            quiet=True,
            fail_on="NEVER",
            tray=False,
            background=False,
            notify="on" if self.notify else "off",
            action=self.action,
            quarantine_folder="Junk",
            quarantine_log=str(self.data_dir / "quarantine.jsonl"),
            expand_urls=False,
            cef_log="",
            redact=False,
            retention_days=0,
        )
        alarms, _worst, _seen, status = _guard_cycle(ns, seen)
        self._imap_status = status
        return int(alarms)

    def _write_status(self) -> dict:
        snap = {
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "watch_dirs": [str(d) for d in self.watch_dirs],
            "imap_status": self._imap_status,
            "alerts_total": self._alerts_total,
            "action": self.action,
            "alert_on": self.alert_on,
        }
        try:
            self.status_file.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        return snap

    def run_once(self) -> dict:
        """Tek tur: İndirilenler klasörü taraması + zamanı geldiyse IMAP turu."""
        scanned, file_alerts = scan_watch_dirs_once(
            self.watch_dirs,
            self.file_state,
            alert_on=self.alert_on,
            action=self.action,
            quarantine_dir=self.quarantine_dir,
            alert_log=str(self.alert_log),
            notify=self.notify,
        )
        self._alerts_total += len(file_alerts)

        now_mono = time.monotonic()
        mail_alarms = 0
        if self.enable_mail and (self._last_mail_ts == 0.0 or (now_mono - self._last_mail_ts) >= self.mail_interval_sec):
            self._last_mail_ts = now_mono
            try:
                mail_alarms = self._run_mail_cycle()
                self._alerts_total += mail_alarms
            except Exception as e:
                self._imap_status = f"error: {e}"

        snap = self._write_status()
        snap["files_scanned"] = len(scanned)
        snap["file_alerts"] = len(file_alerts)
        snap["mail_alerts"] = mail_alarms
        return snap

    def run_forever(self, stop_event: threading.Event | None = None) -> None:
        ev = stop_event or threading.Event()
        while not ev.is_set():
            try:
                self.run_once()
            except Exception:
                pass
            for _ in range(self.watch_interval_sec):
                if ev.is_set():
                    break
                time.sleep(1)


# --- Native Win32 SCM Dispatcher (ctypes) ---

_SCM_REFS: list = []


def run_as_windows_service(runner: ServiceRunner) -> int:
    """Süreci Windows Service Control Manager (SCM) kontrolünde çalıştırır."""
    if os.name != "nt":
        return 2

    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.windll.advapi32

    SERVICE_WIN32_OWN_PROCESS = 0x00000010
    SERVICE_STOPPED = 0x00000001
    SERVICE_START_PENDING = 0x00000002
    SERVICE_STOP_PENDING = 0x00000003
    SERVICE_RUNNING = 0x00000004
    SERVICE_ACCEPT_STOP = 0x00000001
    SERVICE_ACCEPT_SHUTDOWN = 0x00000004
    SERVICE_CONTROL_STOP = 0x00000001
    SERVICE_CONTROL_INTERROGATE = 0x00000004
    SERVICE_CONTROL_SHUTDOWN = 0x00000005

    class SERVICE_STATUS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
        ]

    SERVICE_MAIN_PROC = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
    HANDLER_EX_PROC = ctypes.WINFUNCTYPE(
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p
    )

    class SERVICE_TABLE_ENTRYW(ctypes.Structure):
        _fields_ = [
            ("lpServiceName", wintypes.LPWSTR),
            ("lpServiceProc", SERVICE_MAIN_PROC),
        ]

    advapi32.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPWSTR, HANDLER_EX_PROC, ctypes.c_void_p]
    advapi32.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
    advapi32.SetServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(SERVICE_STATUS)]
    advapi32.SetServiceStatus.restype = wintypes.BOOL
    advapi32.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(SERVICE_TABLE_ENTRYW)]
    advapi32.StartServiceCtrlDispatcherW.restype = wintypes.BOOL

    stop_event = threading.Event()
    status_handle_box: dict = {"handle": None}

    def _set_state(state: int, wait_hint: int = 0, exit_code: int = 0) -> None:
        h = status_handle_box["handle"]
        if not h:
            return
        accepted = (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) if state == SERVICE_RUNNING else 0
        st = SERVICE_STATUS(
            dwServiceType=SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState=state,
            dwControlsAccepted=accepted,
            dwWin32ExitCode=exit_code,
            dwServiceSpecificExitCode=0,
            dwCheckPoint=0,
            dwWaitHint=wait_hint,
        )
        advapi32.SetServiceStatus(h, ctypes.byref(st))

    def _handler(control: int, _event_type: int, _event_data: int, _context: int) -> int:
        if control in (SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN):
            _set_state(SERVICE_STOP_PENDING, wait_hint=5000)
            stop_event.set()
            return 0
        if control == SERVICE_CONTROL_INTERROGATE:
            return 0
        return 0

    handler_cb = HANDLER_EX_PROC(_handler)

    def _service_main(_argc: int, _argv) -> None:
        h = advapi32.RegisterServiceCtrlHandlerExW(SERVICE_NAME, handler_cb, None)
        if not h:
            return
        status_handle_box["handle"] = h
        _set_state(SERVICE_START_PENDING, wait_hint=3000)
        _set_state(SERVICE_RUNNING)
        try:
            runner.run_forever(stop_event)
        finally:
            _set_state(SERVICE_STOPPED)

    main_cb = SERVICE_MAIN_PROC(_service_main)
    _SCM_REFS.extend([handler_cb, main_cb])

    table = (SERVICE_TABLE_ENTRYW * 2)(
        SERVICE_TABLE_ENTRYW(SERVICE_NAME, main_cb),
        SERVICE_TABLE_ENTRYW(None, SERVICE_MAIN_PROC()),
    )
    ok = advapi32.StartServiceCtrlDispatcherW(table)
    return 0 if ok else 2
