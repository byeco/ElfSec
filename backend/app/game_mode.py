"""ElfSec Oyun Modu (Ultra-Düşük Kaynak Motoru).

Kullanıcı tam ekran (Direct3D / borderless) veya bilinen bir oyun oynarken
ElfSec hem kullanıcı ajanını hem de Windows servisini otomatik olarak düşük
önceliğe alır, tarama aralıklarını uzatır, gereksiz bildirimleri oyun bitene
kadar bekletir ve oyunu terk edince normal korumaya geri döner.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from app.settings_store import default_user_config_path, machine_data_dir

VALID_MODES = ("auto", "on", "off")

IGNORED_PROCESSES = {
    "explorer.exe",
    "dwm.exe",
    "searchhost.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "applicationframehost.exe",
    "taskmgr.exe",
    "lockapp.exe",
    "logonui.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "code.exe",
    "windowsterminal.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "conhost.exe",
    "elfsec.exe",
    "python.exe",
    "pythonw.exe",
    "discord.exe",
    "spotify.exe",
}

LAUNCHER_PROCESSES = {
    "steam.exe",
    "steamwebhelper.exe",
    "epicgameslauncher.exe",
    "epicwebhelper.exe",
    "riotclientservices.exe",
    "riotclientux.exe",
    "battle.net.exe",
    "eadesktop.exe",
    "eabackgroundservice.exe",
    "upc.exe",
    "ubisoftconnect.exe",
    "galaxyclient.exe",
    "xboxpcapp.exe",
    "playnite.desktopapp.exe",
}

GAME_PATH_MARKERS = (
    "\\steamapps\\common\\",
    "\\epic games\\",
    "\\riot games\\",
    "\\xboxgames\\",
    "\\ea games\\",
    "\\origin games\\",
    "\\ubisoft game launcher\\games\\",
    "\\gog galaxy\\games\\",
    "\\blizzard\\",
    "\\hoyogame\\",
    "\\wargaming.net\\",
    "\\rockstar games\\",
)

KNOWN_GAME_EXES = {
    "cs2.exe",
    "csgo.exe",
    "valorant-win64-shipping.exe",
    "league of legends.exe",
    "dota2.exe",
    "gta5.exe",
    "gtav.exe",
    "r5apex.exe",
    "fortniteclient-win64-shipping.exe",
    "overwatch.exe",
    "eldenring.exe",
    "cyberpunk2077.exe",
    "tslgame.exe",
    "rocketleague.exe",
    "rustclient.exe",
    "escapefromtarkov.exe",
    "genshinimpact.exe",
    "starrail.exe",
    "palworld-win64-shipping.exe",
    "bg3.exe",
    "bg3_dx11.exe",
    "witcher3.exe",
    "rdr2.exe",
    "cod.exe",
    "bf2042.exe",
    "minecraft.windows.exe",
    "fc24.exe",
    "fc25.exe",
    "helldivers2.exe",
    "marvel-win64-shipping.exe",
    "deadlock.exe",
    "pubg.exe",
    "rainbow6.exe",
    "rainbowsix.exe",
    "destiny2.exe",
    "warframe.x64.exe",
    "wow.exe",
    "diablo iv.exe",
    "pathofexile.exe",
    "pathofexile_x64.exe",
}

_PRIORITY_LOCK = threading.Lock()
_LAST_LOW_POWER: bool | None = None


def classify_game_process(
    exe_name: str,
    exe_path: str = "",
    is_fullscreen: bool = False,
    quns_state: int | None = None,
    custom_processes: set[str] | None = None,
) -> tuple[bool, str]:
    """Ön plandaki sürecin oyun olup olmadığını saf biçimde sınıflandırır."""
    name = (exe_name or "").strip().lower()
    path = (exe_path or "").strip().lower().replace("/", "\\")
    custom = {p.strip().lower() for p in (custom_processes or set()) if p.strip()}

    if name and name in custom:
        return True, "custom_process"
    if name in IGNORED_PROCESSES or name in LAUNCHER_PROCESSES:
        return False, "ignored"
    if quns_state == 3:
        return True, "d3d_fullscreen"
    if name and (name in KNOWN_GAME_EXES or name.endswith(("-win64-shipping.exe", "-win64-test.exe"))):
        return True, "known_game_exe"
    if path and any(marker in path for marker in GAME_PATH_MARKERS):
        return True, "game_library_path"
    if is_fullscreen and name and (
        quns_state == 2
        or name in ("javaw.exe", "java.exe")
        or "unity" in path
        or "unreal" in path
    ):
        return True, "fullscreen_app"
    return False, "idle"


def query_user_notification_state() -> int | None:
    """Windows SHQueryUserNotificationState değerini okur (3 = D3D Tam Ekran)."""
    if os.name != "nt":
        return None
    try:
        import ctypes

        shell32 = ctypes.windll.shell32
        state = ctypes.c_int(0)
        shell32.SHQueryUserNotificationState.argtypes = [ctypes.POINTER(ctypes.c_int)]
        shell32.SHQueryUserNotificationState.restype = ctypes.c_long
        hr = shell32.SHQueryUserNotificationState(ctypes.byref(state))
        if hr == 0:
            return int(state.value)
    except Exception:
        pass
    return None


def get_foreground_window_info() -> dict:
    """Ön plandaki pencerenin süreç adını, dosya yolunu ve tam ekran durumunu döndürür."""
    empty = {"exe_name": "", "exe_path": "", "is_fullscreen": False, "pid": 0}
    if os.name != "nt":
        return empty
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        class RECT(ctypes.Structure):
            _fields_ = [
                ("left", ctypes.c_long),
                ("top", ctypes.c_long),
                ("right", ctypes.c_long),
                ("bottom", ctypes.c_long),
            ]

        class MONITORINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("rcMonitor", RECT),
                ("rcWork", RECT),
                ("dwFlags", wintypes.DWORD),
            ]

        user32.GetForegroundWindow.restype = wintypes.HWND
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return empty

        is_fullscreen = False
        try:
            win_rect = RECT()
            if user32.GetWindowRect(hwnd, ctypes.byref(win_rect)):
                hmon = user32.MonitorFromWindow(hwnd, 2)  # MONITOR_DEFAULTTONEAREST
                if hmon:
                    mi = MONITORINFO()
                    mi.cbSize = ctypes.sizeof(MONITORINFO)
                    if user32.GetMonitorInfoW(hmon, ctypes.byref(mi)):
                        mon_w = max(1, mi.rcMonitor.right - mi.rcMonitor.left)
                        mon_h = max(1, mi.rcMonitor.bottom - mi.rcMonitor.top)
                        win_w = win_rect.right - win_rect.left
                        win_h = win_rect.bottom - win_rect.top
                        is_fullscreen = (win_w >= mon_w * 0.98) and (win_h >= mon_h * 0.98)
        except Exception:
            is_fullscreen = False

        pid_val = wintypes.DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_val))
        pid = int(pid_val.value)
        exe_path = ""
        exe_name = ""
        if pid > 0:
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                try:
                    buf_len = wintypes.DWORD(1024)
                    buf = ctypes.create_unicode_buffer(1024)
                    kernel32.QueryFullProcessImageNameW.argtypes = [
                        wintypes.HANDLE,
                        wintypes.DWORD,
                        wintypes.LPWSTR,
                        ctypes.POINTER(wintypes.DWORD),
                    ]
                    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
                    if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(buf_len)):
                        exe_path = buf.value
                        exe_name = Path(exe_path).name
                finally:
                    kernel32.CloseHandle(handle)

        return {
            "exe_name": exe_name,
            "exe_path": exe_path,
            "is_fullscreen": is_fullscreen,
            "pid": pid,
        }
    except Exception:
        return empty


def detect_game_state(custom_processes: set[str] | None = None) -> dict:
    """Canlı Win32 sinyallerini okuyup oyun tespit sonucu döndürür."""
    fg = get_foreground_window_info()
    quns = query_user_notification_state()
    detected, reason = classify_game_process(
        exe_name=fg.get("exe_name", ""),
        exe_path=fg.get("exe_path", ""),
        is_fullscreen=bool(fg.get("is_fullscreen")),
        quns_state=quns,
        custom_processes=custom_processes,
    )
    return {
        "detected": detected,
        "reason": reason,
        "process": fg.get("exe_name", ""),
        "path": fg.get("exe_path", ""),
        "is_fullscreen": bool(fg.get("is_fullscreen")),
        "quns_state": quns,
    }


def apply_process_priority(low_power: bool) -> bool:
    """Süreci Windows'ta IDLE_PRIORITY_CLASS veya NORMAL_PRIORITY_CLASS yapar."""
    global _LAST_LOW_POWER
    if os.name != "nt":
        return False
    target = bool(low_power)
    with _PRIORITY_LOCK:
        if _LAST_LOW_POWER is target:
            return True
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            IDLE_PRIORITY_CLASS = 0x00000040
            NORMAL_PRIORITY_CLASS = 0x00000020
            prio = IDLE_PRIORITY_CLASS if target else NORMAL_PRIORITY_CLASS
            ok = bool(kernel32.SetPriorityClass(kernel32.GetCurrentProcess(), prio))
            if ok:
                _LAST_LOW_POWER = target
            return ok
        except Exception:
            return False


def game_mode_config_path() -> Path:
    return default_user_config_path().parent / "game_mode_config.json"


def shared_game_mode_paths() -> list[Path]:
    return [
        machine_data_dir() / "game_mode.json",
        default_user_config_path().parent / "game_mode.json",
    ]


def _normalize_exe_name(name: str) -> str:
    clean = Path((name or "").strip()).name.lower()
    if not clean:
        return ""
    if not clean.endswith(".exe"):
        clean += ".exe"
    return clean


def load_game_mode_config(path: Path | None = None) -> dict:
    cfg_path = Path(path) if path else game_mode_config_path()
    default = {"mode": "auto", "custom_games": []}
    if not cfg_path.exists():
        return default
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return default
        mode = str(data.get("mode", "auto")).lower()
        if mode not in VALID_MODES:
            mode = "auto"
        raw_games = data.get("custom_games", [])
        games: list[str] = []
        if isinstance(raw_games, list):
            seen: set[str] = set()
            for item in raw_games:
                norm = _normalize_exe_name(str(item))
                if norm and norm not in seen:
                    seen.add(norm)
                    games.append(norm)
        return {"mode": mode, "custom_games": games}
    except Exception:
        return default


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def save_game_mode_config(mode: str, custom_games: list[str], path: Path | None = None) -> dict:
    m = str(mode or "auto").strip().lower()
    if m not in VALID_MODES:
        raise ValueError(f"Geçersiz oyun modu: {mode}. Geçerli: {', '.join(VALID_MODES)}")
    seen: set[str] = set()
    cleaned: list[str] = []
    for item in custom_games or []:
        norm = _normalize_exe_name(str(item))
        if norm and norm not in seen:
            seen.add(norm)
            cleaned.append(norm)
    payload = {"mode": m, "custom_games": cleaned}
    cfg_path = Path(path) if path else game_mode_config_path()
    _atomic_write_json(cfg_path, payload)
    return payload


def write_shared_game_mode(state: dict, target_paths: list[Path] | None = None) -> None:
    paths = list(target_paths) if target_paths is not None else shared_game_mode_paths()
    for p in paths:
        try:
            _atomic_write_json(Path(p), state)
        except OSError:
            continue


def read_shared_game_mode(
    extra_paths: list[Path] | None = None,
    max_age_sec: float = 45.0,
) -> dict:
    """Paylaşılan oyun modu durumunu (servis ve UI için) okur."""
    candidates: list[Path] = []
    if extra_paths:
        candidates.extend(Path(p) for p in extra_paths)
    for p in shared_game_mode_paths():
        if p not in candidates:
            candidates.append(p)

    best: dict | None = None
    best_ts = -1.0
    for p in candidates:
        if not p.exists():
            continue
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(obj, dict):
                continue
            ts = float(obj.get("updated_ts", 0.0) or 0.0)
            if ts >= best_ts:
                best_ts = ts
                best = obj
        except Exception:
            continue

    cfg = load_game_mode_config()
    if best is None:
        mode = cfg["mode"]
        return {
            "mode": mode,
            "active": mode == "on",
            "reason": "manual_on" if mode == "on" else ("manual_off" if mode == "off" else "idle"),
            "process": "",
            "custom_games": cfg["custom_games"],
            "cpu_priority": "IDLE" if mode == "on" else "NORMAL",
            "updated_at": "",
            "updated_ts": 0.0,
        }

    mode = str(best.get("mode", cfg["mode"])).lower()
    if mode not in VALID_MODES:
        mode = "auto"
    active = bool(best.get("active", False))
    reason = str(best.get("reason", "idle"))
    process = str(best.get("process", ""))

    if mode == "on":
        active = True
        reason = reason or "manual_on"
    elif mode == "off":
        active = False
        reason = "manual_off"
        process = ""
    else:
        age = time.time() - best_ts
        if best_ts <= 0 or age > max_age_sec:
            active = False
            reason = "stale"
            process = ""

    return {
        "mode": mode,
        "active": active,
        "reason": reason,
        "process": process,
        "custom_games": best.get("custom_games", cfg["custom_games"]),
        "cpu_priority": "IDLE" if active else "NORMAL",
        "updated_at": str(best.get("updated_at", "")),
        "updated_ts": best_ts,
    }


class GameModeController:
    """Oyun modu yapılandırmasını, histerezis beklemesini ve paylaşım dosyasını yönetir."""

    def __init__(
        self,
        config_path: Path | None = None,
        shared_paths: list[Path] | None = None,
        cooldown_sec: float = 15.0,
        detector: Callable[[set[str]], dict] | None = None,
    ):
        self.config_path = Path(config_path) if config_path else game_mode_config_path()
        self.shared_paths = list(shared_paths) if shared_paths is not None else shared_game_mode_paths()
        self.cooldown_sec = max(0.0, float(cooldown_sec))
        self._detector = detector or (lambda custom: detect_game_state(custom))
        self._cfg_mtime: float = -1.0
        self._cfg: dict = load_game_mode_config(self.config_path)
        self._active: bool = False
        self._last_game_seen_mono: float = 0.0
        self._last_process: str = ""
        self._last_reason: str = "idle"
        self._last_write_mono: float = 0.0
        self._last_written_active: bool | None = None
        self._last_written_mode: str = ""

    def _reload_if_changed(self) -> None:
        try:
            mt = self.config_path.stat().st_mtime if self.config_path.exists() else -1.0
        except OSError:
            mt = -1.0
        if mt != self._cfg_mtime:
            self._cfg_mtime = mt
            self._cfg = load_game_mode_config(self.config_path)

    def evaluate(self, now: float | None = None) -> dict:
        self._reload_if_changed()
        now_mono = time.monotonic() if now is None else float(now)
        mode = self._cfg["mode"]
        custom_games = list(self._cfg["custom_games"])

        if mode == "on":
            self._active = True
            self._last_reason = "manual_on"
            if not self._last_process:
                self._last_process = "Manuel Oyun Modu"
        elif mode == "off":
            self._active = False
            self._last_reason = "manual_off"
            self._last_process = ""
        else:
            det = self._detector(set(custom_games))
            if det.get("detected"):
                self._active = True
                self._last_game_seen_mono = now_mono
                self._last_process = str(det.get("process") or "")
                self._last_reason = str(det.get("reason") or "detected")
            elif self._active and (now_mono - self._last_game_seen_mono) < self.cooldown_sec:
                self._last_reason = "cooldown"
            else:
                self._active = False
                self._last_process = ""
                self._last_reason = "idle"

        state = {
            "mode": mode,
            "active": self._active,
            "reason": self._last_reason,
            "process": self._last_process,
            "custom_games": custom_games,
            "cpu_priority": "IDLE" if self._active else "NORMAL",
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "updated_ts": time.time(),
        }

        state_changed = (
            self._last_written_active is not self._active
            or self._last_written_mode != mode
        )
        if state_changed or (now_mono - self._last_write_mono) >= 15.0:
            write_shared_game_mode(state, self.shared_paths)
            self._last_write_mono = now_mono
            self._last_written_active = self._active
            self._last_written_mode = mode

        return state

    def set_mode(self, mode: str) -> dict:
        self._reload_if_changed()
        self._cfg = save_game_mode_config(mode, self._cfg["custom_games"], self.config_path)
        self._cfg_mtime = self.config_path.stat().st_mtime if self.config_path.exists() else -1.0
        self._last_write_mono = 0.0
        return self.evaluate()

    def add_custom_game(self, exe_name: str) -> dict:
        self._reload_if_changed()
        norm = _normalize_exe_name(exe_name)
        if not norm:
            raise ValueError("Geçerli bir oyun .exe adı girin (örn: valorant.exe).")
        games = list(self._cfg["custom_games"])
        if norm not in games:
            games.append(norm)
        self._cfg = save_game_mode_config(self._cfg["mode"], games, self.config_path)
        self._cfg_mtime = self.config_path.stat().st_mtime if self.config_path.exists() else -1.0
        self._last_write_mono = 0.0
        return self.evaluate()

    def remove_custom_game(self, exe_name: str) -> dict:
        self._reload_if_changed()
        norm = _normalize_exe_name(exe_name)
        games = [g for g in self._cfg["custom_games"] if g != norm]
        self._cfg = save_game_mode_config(self._cfg["mode"], games, self.config_path)
        self._cfg_mtime = self.config_path.stat().st_mtime if self.config_path.exists() else -1.0
        self._last_write_mono = 0.0
        return self.evaluate()
