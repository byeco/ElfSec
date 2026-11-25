"""Arka planda sessizce çalışan koruma ve Windows Sistem Tepsisi (System Tray) ikonu.

Kullanım (tek exe):
    elfsec.exe guard --unseen --interval 10 --tray
    elfsec.exe agent --tray

- Windows'ta konsol penceresi gizlenir (hide_console).
- Ek bağımlılık olmadan doğrudan Win32 Shell_NotifyIconW + sağ-tık menüsü çizer.
- Win32 tepsi kullanılamazsa pystray'e düşer, o da yoksa False döner.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from typing import Callable

_TRAY_REFS: list = []


def _find_elfsec_ico() -> Path | None:
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


def _load_elfsec_tray_icon(user32, hinst, fallback_shield, fallback_app):
    import ctypes
    from ctypes import wintypes

    ico = _find_elfsec_ico()
    if ico is not None:
        try:
            user32.LoadImageW.argtypes = [
                wintypes.HINSTANCE,
                wintypes.LPCWSTR,
                wintypes.UINT,
                ctypes.c_int,
                ctypes.c_int,
                wintypes.UINT,
            ]
            user32.LoadImageW.restype = wintypes.HANDLE
            h = user32.LoadImageW(None, str(ico), 1, 16, 16, 0x0010)
            if h:
                return h
        except Exception:
            pass
    hicon = user32.LoadIconW(None, ctypes.cast(fallback_shield, wintypes.LPCWSTR))
    if not hicon:
        hicon = user32.LoadIconW(None, ctypes.cast(fallback_app, wintypes.LPCWSTR))
    return hicon


def hide_console() -> None:
    """Console penceresini gizle (sadece Windows, sessiz)."""
    if os.name != "nt":
        return
    try:
        import ctypes

        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
    except Exception:
        pass


def wants_background(argv: list[str] | None = None) -> bool:
    import sys

    args = argv if argv is not None else sys.argv[1:]
    if "guard" not in args and "agent" not in args:
        return False
    return any(a in ("--tray", "--background") for a in args)


def _run_win32_tray(
    stop_event: threading.Event | None = None,
    tooltip: str = "ElfSec Güvenlik Eklentisi",
    callbacks: dict[str, Callable[[], None]] | None = None,
) -> bool:
    """Saf ctypes ile native Windows Sistem Tepsisi ikonu + sağ-tık menüsü."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        shell32 = ctypes.windll.shell32
        kernel32 = ctypes.windll.kernel32

        WM_DESTROY = 0x0002
        WM_COMMAND = 0x0111
        WM_TIMER = 0x0113
        WM_USER = 0x0400
        WM_TRAYICON = WM_USER + 20
        WM_RBUTTONUP = 0x0205
        WM_LBUTTONDBLCLK = 0x0203

        NIM_ADD = 0x00000000
        NIM_DELETE = 0x00000002
        NIF_MESSAGE = 0x00000001
        NIF_ICON = 0x00000002
        NIF_TIP = 0x00000004

        MF_STRING = 0x00000000
        MF_SEPARATOR = 0x00000800
        MF_GRAYED = 0x00000001
        TPM_LEFTALIGN = 0x0000
        TPM_BOTTOMALIGN = 0x0020
        TPM_RIGHTBUTTON = 0x0002

        IDI_SHIELD = 32518
        IDI_APPLICATION = 32512

        ID_SCAN_CLIP = 1001
        ID_SCAN_DL = 1002
        ID_TOGGLE_CLIP = 1003
        ID_STATUS = 1004
        ID_DASHBOARD = 1005
        ID_TOGGLE_GAMEMODE = 1006
        ID_EXIT = 1099

        LRESULT = ctypes.c_ssize_t
        WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

        class WNDCLASSEXW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.UINT),
                ("style", wintypes.UINT),
                ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HICON),
                ("hCursor", wintypes.HANDLE),
                ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR),
                ("hIconSm", wintypes.HICON),
            ]

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("hWnd", wintypes.HWND),
                ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT),
                ("uCallbackMessage", wintypes.UINT),
                ("hIcon", wintypes.HICON),
                ("szTip", wintypes.WCHAR * 128),
            ]

        class POINT(ctypes.Structure):
            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

        class MSG(ctypes.Structure):
            _fields_ = [
                ("hwnd", wintypes.HWND),
                ("message", wintypes.UINT),
                ("wParam", wintypes.WPARAM),
                ("lParam", wintypes.LPARAM),
                ("time", wintypes.DWORD),
                ("pt", POINT),
            ]

        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wintypes.HINSTANCE
        user32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
        user32.LoadIconW.restype = wintypes.HICON
        user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
        user32.RegisterClassExW.restype = wintypes.ATOM
        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, ctypes.c_void_p,
        ]
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.DefWindowProcW.restype = LRESULT
        user32.CreatePopupMenu.restype = wintypes.HMENU
        user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.UINT, wintypes.LPCWSTR]
        user32.AppendMenuW.restype = wintypes.BOOL
        user32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.TrackPopupMenu.argtypes = [
            wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int,
            ctypes.c_int, wintypes.HWND, ctypes.c_void_p,
        ]
        user32.DestroyMenu.argtypes = [wintypes.HMENU]
        user32.SetTimer.argtypes = [wintypes.HWND, ctypes.c_size_t, wintypes.UINT, ctypes.c_void_p]
        user32.KillTimer.argtypes = [wintypes.HWND, ctypes.c_size_t]
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.PostQuitMessage.argtypes = [ctypes.c_int]
        user32.GetMessageW.argtypes = [ctypes.POINTER(MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
        user32.TranslateMessage.argtypes = [ctypes.POINTER(MSG)]
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
        shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
        shell32.Shell_NotifyIconW.restype = wintypes.BOOL

        cb = callbacks or {}

        def _invoke(key: str) -> None:
            fn = cb.get(key)
            if fn:
                threading.Thread(target=fn, daemon=True).start()

        def _show_menu(hwnd) -> None:
            menu = user32.CreatePopupMenu()
            if not menu:
                return
            try:
                user32.AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, "ElfSec Güvenlik Eklentisi")
                user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
                user32.AppendMenuW(menu, MF_STRING, ID_SCAN_CLIP, "Panoyu Şimdi Tara")
                user32.AppendMenuW(menu, MF_STRING, ID_SCAN_DL, "İndirilenleri Şimdi Tara")
                user32.AppendMenuW(menu, MF_STRING, ID_TOGGLE_CLIP, "Pano Koruması (Aç/Kapat)")
                user32.AppendMenuW(menu, MF_STRING, ID_TOGGLE_GAMEMODE, "Oyun Modu (Oto/Açık/Kapalı)")
                user32.AppendMenuW(menu, MF_STRING, ID_STATUS, "Servis & Eklenti Durumu")
                user32.AppendMenuW(menu, MF_STRING, ID_DASHBOARD, "Güvenlik Panelini Aç")
                user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
                user32.AppendMenuW(menu, MF_STRING, ID_EXIT, "Çıkış")
                pt = POINT()
                user32.GetCursorPos(ctypes.byref(pt))
                user32.SetForegroundWindow(hwnd)
                user32.TrackPopupMenu(menu, TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON,
                                      pt.x, pt.y, 0, hwnd, None)
            finally:
                user32.DestroyMenu(menu)

        def _wnd_proc(hwnd, msg, wparam, lparam):
            if msg == WM_TRAYICON:
                ev = lparam & 0xFFFF
                if ev == WM_RBUTTONUP:
                    _show_menu(hwnd)
                    return 0
                if ev == WM_LBUTTONDBLCLK:
                    _invoke("dashboard")
                    return 0
            elif msg == WM_COMMAND:
                cmd_id = wparam & 0xFFFF
                if cmd_id == ID_SCAN_CLIP:
                    _invoke("scan_clipboard")
                elif cmd_id == ID_SCAN_DL:
                    _invoke("scan_downloads")
                elif cmd_id == ID_TOGGLE_CLIP:
                    _invoke("toggle_clipboard")
                elif cmd_id == ID_TOGGLE_GAMEMODE:
                    _invoke("toggle_game_mode")
                elif cmd_id == ID_STATUS:
                    _invoke("status")
                elif cmd_id == ID_DASHBOARD:
                    _invoke("dashboard")
                elif cmd_id == ID_EXIT:
                    if stop_event is not None:
                        stop_event.set()
                    user32.DestroyWindow(hwnd)
                return 0
            elif msg == WM_TIMER:
                if stop_event is not None and stop_event.is_set():
                    user32.DestroyWindow(hwnd)
                return 0
            elif msg == WM_DESTROY:
                user32.KillTimer(hwnd, 1)
                user32.PostQuitMessage(0)
                return 0
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        wnd_proc_cb = WNDPROC(_wnd_proc)
        _TRAY_REFS.append(wnd_proc_cb)

        hinst = kernel32.GetModuleHandleW(None)
        hicon = _load_elfsec_tray_icon(user32, hinst, IDI_SHIELD, IDI_APPLICATION)

        cls_name = f"ElfSecTrayWnd_{os.getpid()}"
        wc = WNDCLASSEXW(
            cbSize=ctypes.sizeof(WNDCLASSEXW),
            style=0,
            lpfnWndProc=wnd_proc_cb,
            cbClsExtra=0,
            cbWndExtra=0,
            hInstance=hinst,
            hIcon=hicon,
            hCursor=None,
            hbrBackground=None,
            lpszMenuName=None,
            lpszClassName=cls_name,
            hIconSm=hicon,
        )
        user32.RegisterClassExW(ctypes.byref(wc))

        hwnd = user32.CreateWindowExW(
            0, cls_name, tooltip, 0, 0, 0, 0, 0, None, None, hinst, None
        )
        if not hwnd:
            return False

        nid = NOTIFYICONDATAW(
            cbSize=ctypes.sizeof(NOTIFYICONDATAW),
            hWnd=hwnd,
            uID=1,
            uFlags=NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage=WM_TRAYICON,
            hIcon=hicon,
            szTip=tooltip[:127],
        )
        if not shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)):
            user32.DestroyWindow(hwnd)
            return False

        user32.SetTimer(hwnd, 1, 500, None)
        msg = MSG()
        try:
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        finally:
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
        return True
    except Exception:
        return False


def _run_pystray(stop_event=None, tooltip: str = "ElfSec Guard") -> bool:
    try:
        from pystray import Icon, Menu, MenuItem  # type: ignore
        from PIL import Image, ImageDraw  # type: ignore
    except Exception:
        return False

    try:
        img = Image.new("RGB", (64, 64), (20, 20, 20))
        d = ImageDraw.Draw(img)
        d.ellipse([8, 8, 56, 56], fill=(0, 180, 90))

        def _quit(icon, _item):
            icon.stop()
            if stop_event is not None:
                try:
                    stop_event.set()
                except Exception:
                    pass

        icon = Icon("ElfSec", img, tooltip, menu=Menu(MenuItem("Çıkış", _quit)))
        icon.run()
        return True
    except Exception:
        return False


def run_tray_loop(
    stop_event: threading.Event | None = None,
    tooltip: str = "ElfSec Güvenlik Eklentisi",
    callbacks: dict[str, Callable[[], None]] | None = None,
) -> bool:
    """Önce native Win32 tray dener, olmazsa pystray, olmazsa False döner."""
    if _run_win32_tray(stop_event=stop_event, tooltip=tooltip, callbacks=callbacks):
        return True
    return _run_pystray(stop_event=stop_event, tooltip=tooltip)
