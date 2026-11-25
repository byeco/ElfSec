"""ElfSec Yerel Çerçevesiz (Frameless) Pencere Sistemi (Edge WebView2 / pywebview).

Dış tarayıcı (`msedge.exe --app`) yerine doğrudan ElfSec'e ait yerel bir
WebView2 penceresi oluşturur; Win32 DWM yuvarlatılmış köşeler, koyu çerçeve,
görev çubuğu ikonu ve özel başlık çubuğu pencere kontrolleri sağlar.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from typing import Any, Callable


def _find_elfsec_ico() -> Path | None:
    """ElfSec .ico dosyasını paketlenmiş (_MEIPASS) veya repo yollarından bulur."""
    candidates: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", "")
    if meipass:
        candidates.append(Path(meipass) / "assets" / "elfsec.ico")
    try:
        candidates.append(Path(sys.executable).resolve().parent / "elfsec.ico")
    except Exception:
        pass
    try:
        candidates.append(Path(__file__).resolve().parents[1] / "assets" / "elfsec.ico")
        candidates.append(Path(__file__).resolve().parents[2] / "installer" / "elfsec.ico")
    except Exception:
        pass
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    return None


def _webview_storage_dir() -> Path:
    """WebView2 kullanıcı veri klasörünü yazılabilir LocalAppData altında döndürür."""
    base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / ".config"))
    storage = base / "ElfSec" / "webview2"
    try:
        storage.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return storage


def _apply_win32_window_chrome(hwnd: int, ico_path: Path | None) -> None:
    """Windows 10/11 üzerinde koyu DWM çerçevesi, yuvarlatılmış köşeler ve ikon uygular."""
    if os.name != "nt" or not hwnd:
        return
    try:
        import ctypes
        from ctypes import wintypes

        dwmapi = ctypes.windll.dwmapi
        user32 = ctypes.windll.user32

        # DWMWA_USE_IMMERSIVE_DARK_MODE (20) = 1
        dark = ctypes.c_int(1)
        dwmapi.DwmSetWindowAttribute(
            wintypes.HWND(hwnd), 20, ctypes.byref(dark), ctypes.sizeof(dark)
        )

        # DWMWA_WINDOW_CORNER_PREFERENCE (33) = DWMWCP_ROUND (2)
        corner = ctypes.c_int(2)
        dwmapi.DwmSetWindowAttribute(
            wintypes.HWND(hwnd), 33, ctypes.byref(corner), ctypes.sizeof(corner)
        )

        # DWMWA_BORDER_COLOR (34) — koyu slate çerçeve (COLORREF 0x00BBGGRR -> #182433)
        border_color = ctypes.c_uint32(0x00332418)
        dwmapi.DwmSetWindowAttribute(
            wintypes.HWND(hwnd), 34, ctypes.byref(border_color), ctypes.sizeof(border_color)
        )

        if ico_path is not None and ico_path.exists():
            user32.LoadImageW.argtypes = [
                wintypes.HINSTANCE,
                wintypes.LPCWSTR,
                wintypes.UINT,
                ctypes.c_int,
                ctypes.c_int,
                wintypes.UINT,
            ]
            user32.LoadImageW.restype = wintypes.HANDLE
            user32.SendMessageW.argtypes = [
                wintypes.HWND,
                wintypes.UINT,
                wintypes.WPARAM,
                wintypes.LPARAM,
            ]
            user32.SendMessageW.restype = ctypes.c_ssize_t

            WM_SETICON = 0x0080
            IMAGE_ICON = 1
            LR_LOADFROMFILE = 0x0010

            h_big = user32.LoadImageW(None, str(ico_path), IMAGE_ICON, 32, 32, LR_LOADFROMFILE)
            h_small = user32.LoadImageW(None, str(ico_path), IMAGE_ICON, 16, 16, LR_LOADFROMFILE)
            if h_big:
                user32.SendMessageW(wintypes.HWND(hwnd), WM_SETICON, 1, h_big)
            if h_small:
                user32.SendMessageW(wintypes.HWND(hwnd), WM_SETICON, 0, h_small)
    except Exception:
        pass


def _set_dwm_corner_round(hwnd: int, rounded: bool) -> None:
    if os.name != "nt" or not hwnd:
        return
    try:
        import ctypes
        from ctypes import wintypes

        # DWMWCP_ROUND = 2, DWMWCP_DONOTROUND = 1
        val = ctypes.c_int(2 if rounded else 1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            wintypes.HWND(hwnd), 33, ctypes.byref(val), ctypes.sizeof(val)
        )
    except Exception:
        pass


def _get_window_rect(hwnd: int) -> tuple[int, int, int, int] | None:
    if os.name != "nt" or not hwnd:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        rc = wintypes.RECT()
        user32 = ctypes.windll.user32
        user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
        user32.GetWindowRect.restype = wintypes.BOOL
        if user32.GetWindowRect(wintypes.HWND(hwnd), ctypes.byref(rc)):
            return (int(rc.left), int(rc.top), int(rc.right - rc.left), int(rc.bottom - rc.top))
    except Exception:
        pass
    return None


def _get_monitor_work_area(hwnd: int) -> tuple[int, int, int, int] | None:
    """Görev çubuğu hariç monitör çalışma alanını (rcWork) döndürür."""
    if os.name != "nt" or not hwnd:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class MONITORINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("rcMonitor", wintypes.RECT),
                ("rcWork", wintypes.RECT),
                ("dwFlags", wintypes.DWORD),
            ]

        user32 = ctypes.windll.user32
        user32.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
        user32.MonitorFromWindow.restype = wintypes.HANDLE
        user32.GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MONITORINFO)]
        user32.GetMonitorInfoW.restype = wintypes.BOOL

        # MONITOR_DEFAULTTONEAREST = 2
        hmon = user32.MonitorFromWindow(wintypes.HWND(hwnd), 2)
        if not hmon:
            return None
        mi = MONITORINFO()
        mi.cbSize = ctypes.sizeof(MONITORINFO)
        if user32.GetMonitorInfoW(hmon, ctypes.byref(mi)):
            w_rc = mi.rcWork
            return (int(w_rc.left), int(w_rc.top), int(w_rc.right - w_rc.left), int(w_rc.bottom - w_rc.top))
    except Exception:
        pass
    return None


def _set_window_rect(hwnd: int, rect: tuple[int, int, int, int]) -> bool:
    if os.name != "nt" or not hwnd:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        x, y, w, h = rect
        user32 = ctypes.windll.user32
        user32.SetWindowPos.argtypes = [
            wintypes.HWND,
            wintypes.HWND,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.UINT,
        ]
        user32.SetWindowPos.restype = wintypes.BOOL
        SWP_NOZORDER = 0x0004
        SWP_NOACTIVATE = 0x0010
        SWP_FRAMECHANGED = 0x0020
        return bool(
            user32.SetWindowPos(
                wintypes.HWND(hwnd),
                None,
                int(x),
                int(y),
                int(w),
                int(h),
                SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
            )
        )
    except Exception:
        return False


class NativeWindowController:
    """Özel başlık çubuğu üzerinden yerel pywebview penceresini yöneten denetleyici."""

    def __init__(self, window: Any, on_close_cb: Callable[[], None] | None = None):
        self._window = window
        self._on_close_cb = on_close_cb
        self._maximized = False
        self._pinned = False
        self._restore_rect: tuple[int, int, int, int] | None = None

    def _get_hwnd(self) -> int | None:
        try:
            native = getattr(self._window, "native", None)
            if native is None:
                return None
            handle = getattr(native, "Handle", None)
            if handle is None:
                return None
            to_int64 = getattr(handle, "ToInt64", None)
            if callable(to_int64):
                return int(to_int64())
            return int(handle)
        except Exception:
            return None

    def is_maximized(self) -> bool:
        if self._maximized:
            return True
        try:
            native = getattr(self._window, "native", None)
            if native is not None and hasattr(native, "WindowState"):
                ws = str(native.WindowState).lower()
                if "maximized" in ws:
                    return True
                if "normal" in ws or "minimized" in ws:
                    return False
        except Exception:
            pass
        return self._maximized

    def get_state(self) -> dict:
        return {
            "native": True,
            "maximized": self.is_maximized(),
            "pinned": bool(self._pinned),
        }

    def minimize(self) -> dict:
        try:
            self._window.minimize()
        except Exception:
            pass
        return self.get_state()

    def toggle_maximize(self) -> dict:
        hwnd = self._get_hwnd() if os.name == "nt" else None
        if self.is_maximized():
            if hwnd and self._restore_rect and _set_window_rect(hwnd, self._restore_rect):
                _set_dwm_corner_round(hwnd, True)
            else:
                try:
                    self._window.restore()
                except Exception:
                    pass
                if hwnd:
                    _set_dwm_corner_round(hwnd, True)
            self._maximized = False
        else:
            if hwnd:
                cur_rect = _get_window_rect(hwnd)
                work = _get_monitor_work_area(hwnd)
                if work and _set_window_rect(hwnd, work):
                    if cur_rect:
                        self._restore_rect = cur_rect
                    _set_dwm_corner_round(hwnd, False)
                    self._maximized = True
                    return self.get_state()
            try:
                self._window.maximize()
            except Exception:
                pass
            self._maximized = True
        return self.get_state()

    def toggle_pin(self) -> dict:
        self._pinned = not self._pinned
        try:
            self._window.on_top = self._pinned
        except Exception:
            pass
        return self.get_state()

    def close(self) -> dict:
        try:
            self._window.destroy()
        except Exception:
            pass
        if self._on_close_cb is not None:
            try:
                self._on_close_cb()
            except Exception:
                pass
        return {"closed": True}

    def apply_chrome(self) -> None:
        hwnd = self._get_hwnd()
        if hwnd:
            _apply_win32_window_chrome(hwnd, _find_elfsec_ico())


def launch_native_window(
    server: Any,
    title: str = "ElfSec Güvenlik Merkezi",
    width: int = 860,
    height: int = 580,
    min_size: tuple[int, int] = (720, 500),
) -> bool:
    """ElfSec Güvenlik Merkezi'ni yerel çerçevesiz Edge WebView2 penceresinde başlatır."""
    if os.environ.get("ELFSEC_UI_BROWSER_FALLBACK") == "1":
        return False
    if threading.current_thread() is not threading.main_thread():
        return False

    try:
        import webview
    except Exception:
        return False

    try:
        win = webview.create_window(
            title=title,
            url=server.url,
            width=width,
            height=height,
            min_size=min_size,
            resizable=True,
            frameless=True,
            easy_drag=False,
            background_color="#070b14",
        )
        ctrl = NativeWindowController(win, on_close_cb=server.stop_event.set)
        server.window_controller = ctrl

        def _on_shown() -> None:
            ctrl.apply_chrome()

        def _on_closed() -> None:
            server.stop_event.set()

        win.events.shown += _on_shown
        win.events.closed += _on_closed

        webview.start(
            gui="edgechromium",
            storage_path=str(_webview_storage_dir()),
            debug=False,
        )
        return True
    except Exception:
        server.window_controller = None
        return False
