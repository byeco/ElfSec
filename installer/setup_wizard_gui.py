"""ElfSec Güvenlik Sistemi — Özel Çerçevesiz Windows Kurulum Sihirbazı (ElfSecSetup.exe).

Sıfır dış bağımlılıkla (yalnızca tkinter + ctypes + winreg + subprocess + shutil)
kendi özel başlık çubuğuna, Win11 DWM yuvarlatılmış köşelere, görev çubuğu ikonuna,
Canvas tabanlı adım izleyicisine, özel onay kutularına ve ilerleme çubuğuna sahip
Obsidian & Emerald kurulum deneyimi sunar.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

APP_NAME = "ElfSec Güvenlik Sistemi"
APP_VERSION = "1.6.0"
APP_PUBLISHER = "byeco"
APP_URL = "https://byeco.com.tr"
UNINSTALL_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\ElfSec"


def build_uninstall_reg_values(
    install_dir: str,
    version: str = APP_VERSION,
    estimated_kb: int = 24000,
) -> dict:
    """Windows Program Ekle/Kaldır kayıt defteri değerlerini saf veri olarak üretir."""
    base = str(Path(install_dir))
    return {
        "DisplayName": APP_NAME,
        "DisplayVersion": str(version),
        "Publisher": APP_PUBLISHER,
        "URLInfoAbout": APP_URL,
        "DisplayIcon": str(Path(base) / "elfsec.ico"),
        "InstallLocation": base,
        "UninstallString": f'cmd.exe /c "{Path(base) / "uninstall.cmd"}"',
        "NoModify": 1,
        "NoRepair": 1,
        "EstimatedSize": int(estimated_kb),
    }


def build_uninstall_cmd(install_dir: str) -> str:
    """ElfSec kurulumunu temizce kaldıran uninstall.cmd betiğini üretir."""
    base = str(Path(install_dir))
    exe = str(Path(base) / "elfsec.exe")
    return (
        "@echo off\r\n"
        "chcp 65001 >nul\r\n"
        f'"{exe}" plugin uninstall\r\n'
        'taskkill /F /IM elfsec.exe >nul 2>&1\r\n'
        f'del /F /Q "%PUBLIC%\\Desktop\\ElfSec.lnk" "%USERPROFILE%\\Desktop\\ElfSec.lnk" >nul 2>&1\r\n'
        'rmdir /S /Q "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\ElfSec" >nul 2>&1\r\n'
        f'reg delete "HKLM\\{UNINSTALL_REG_PATH}" /f >nul 2>&1\r\n'
        f'start "" /min cmd /c "ping 127.0.0.1 -n 3 >nul & rmdir /S /Q \\"{base}\\""\r\n'
    )


def _resolve_payload_paths() -> dict[str, Path | None]:
    meipass = getattr(sys, "_MEIPASS", "")
    if meipass:
        p = Path(meipass) / "payload"
        return {
            "exe": p / "elfsec.exe",
            "ico": p / "elfsec.ico",
            "png": p / "icon128.png",
            "ext": p / "extension",
        }
    repo = Path(__file__).resolve().parents[1]
    return {
        "exe": repo / "backend" / "dist" / "elfsec.exe",
        "ico": repo / "installer" / "elfsec.ico",
        "png": repo / "extension" / "icons" / "icon128.png",
        "ext": repo / "extension",
    }


def _create_shortcut(lnk_path: Path, target: str, args: str, icon: str, workdir: str) -> None:
    lnk_path.parent.mkdir(parents=True, exist_ok=True)
    ps_script = (
        "$ws = New-Object -ComObject WScript.Shell; "
        f"$sc = $ws.CreateShortcut('{str(lnk_path).replace(chr(39), chr(39)*2)}'); "
        f"$sc.TargetPath = '{target.replace(chr(39), chr(39)*2)}'; "
        f"$sc.Arguments = '{args.replace(chr(39), chr(39)*2)}'; "
        f"$sc.IconLocation = '{icon.replace(chr(39), chr(39)*2)}'; "
        f"$sc.WorkingDirectory = '{workdir.replace(chr(39), chr(39)*2)}'; "
        "$sc.Save()"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_script],
        capture_output=True,
        timeout=15,
        check=False,
        creationflags=0x08000000 if os.name == "nt" else 0,
    )


def _write_uninstall_registry(install_dir: str) -> None:
    if os.name != "nt":
        return
    import winreg

    vals = build_uninstall_reg_values(install_dir)
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_REG_PATH, 0, winreg.KEY_WRITE) as key:
        for name, val in vals.items():
            if isinstance(val, int):
                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, val)
            else:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(val))


def _setup_frameless_taskbar_and_dwm(root, ico_path: Path | None) -> int:
    """overrideredirect(True) penceresini görev çubuğunda gösterir ve Win11 DWM stili uygular."""
    if os.name != "nt":
        return 0
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        dwmapi = ctypes.windll.dwmapi

        root.update_idletasks()
        hwnd = user32.GetParent(root.winfo_id()) or root.winfo_id()

        GWL_EXSTYLE = -20
        WS_EX_APPWINDOW = 0x00040000
        WS_EX_TOOLWINDOW = 0x00000080

        if ctypes.sizeof(ctypes.c_void_p) == 8:
            get_long = user32.GetWindowLongPtrW
            set_long = user32.SetWindowLongPtrW
            get_long.restype = ctypes.c_ssize_t
            set_long.restype = ctypes.c_ssize_t
            set_long.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t]
        else:
            get_long = user32.GetWindowLongW
            set_long = user32.SetWindowLongW
            get_long.restype = ctypes.c_long
            set_long.restype = ctypes.c_long
            set_long.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_long]

        ex_style = get_long(wintypes.HWND(hwnd), GWL_EXSTYLE)
        ex_style = (ex_style | WS_EX_APPWINDOW) & ~WS_EX_TOOLWINDOW
        set_long(wintypes.HWND(hwnd), GWL_EXSTYLE, ex_style)

        # Görev çubuğu stilini tazele
        SWP_NOMOVE = 0x0002
        SWP_NOSIZE = 0x0001
        SWP_NOZORDER = 0x0004
        SWP_FRAMECHANGED = 0x0020
        user32.SetWindowPos(
            wintypes.HWND(hwnd), None, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED,
        )

        # Win11 DWM koyu mod + yuvarlatılmış köşeler + slate kenarlık
        dark = ctypes.c_int(1)
        dwmapi.DwmSetWindowAttribute(wintypes.HWND(hwnd), 20, ctypes.byref(dark), ctypes.sizeof(dark))
        corner = ctypes.c_int(2)
        dwmapi.DwmSetWindowAttribute(wintypes.HWND(hwnd), 33, ctypes.byref(corner), ctypes.sizeof(corner))
        border_col = ctypes.c_uint32(0x004D3522)
        dwmapi.DwmSetWindowAttribute(wintypes.HWND(hwnd), 34, ctypes.byref(border_col), ctypes.sizeof(border_col))

        if ico_path and ico_path.exists():
            user32.LoadImageW.argtypes = [
                wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
                ctypes.c_int, ctypes.c_int, wintypes.UINT,
            ]
            user32.LoadImageW.restype = wintypes.HANDLE
            user32.SendMessageW.argtypes = [
                wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
            ]
            h_big = user32.LoadImageW(None, str(ico_path), 1, 32, 32, 0x0010)
            h_small = user32.LoadImageW(None, str(ico_path), 1, 16, 16, 0x0010)
            if h_big:
                user32.SendMessageW(wintypes.HWND(hwnd), 0x0080, 1, h_big)
            if h_small:
                user32.SendMessageW(wintypes.HWND(hwnd), 0x0080, 0, h_small)
        return int(hwnd)
    except Exception:
        return 0


def _minimize_frameless(root, hwnd: int) -> None:
    if os.name == "nt" and hwnd:
        try:
            import ctypes

            ctypes.windll.user32.ShowWindow(hwnd, 6)  # SW_MINIMIZE
            return
        except Exception:
            pass
    try:
        root.iconify()
    except Exception:
        pass


def launch_wizard() -> int:
    import tkinter as tk
    from tkinter import filedialog, messagebox

    BG = "#080d18"
    CHROME = BG
    SIDEBAR = BG
    SURFACE_SOFT = "#0d1526"
    SURFACE = "#101a2e"
    SURFACE_2 = "#15213a"
    ACTIVE_STEP_BG = "#102826"
    HOVER = "#1b2a4a"
    BORDER = "#18243b"
    TEXT = "#eef4ff"
    MUTED = "#869ab8"
    BRAND = "#10b981"
    BRAND_LIGHT = "#34d399"
    BRAND_DARK = "#059669"
    CLOSE_RED = "#e11d48"

    WIN_W = 840
    WIN_H = 580

    payload = _resolve_payload_paths()
    root = tk.Tk()
    root.title(f"{APP_NAME} — Kurulum")
    root.overrideredirect(True)
    root.configure(bg=BORDER)

    root.update_idletasks()
    sx = max(0, (root.winfo_screenwidth() - WIN_W) // 2)
    sy = max(0, (root.winfo_screenheight() - WIN_H) // 2)
    root.geometry(f"{WIN_W}x{WIN_H}+{sx}+{sy}")

    ico_p = payload.get("ico")
    if ico_p and ico_p.exists():
        try:
            root.iconbitmap(str(ico_p))
        except Exception:
            pass

    hwnd_box = {"hwnd": 0}
    root.after(10, lambda: hwnd_box.__setitem__("hwnd", _setup_frameless_taskbar_and_dwm(root, ico_p)))

    # 1px dış kenarlık içinde ana çerçeve
    shell = tk.Frame(root, bg=BG)
    shell.pack(fill="both", expand=True, padx=1, pady=1)

    logo_big = None
    logo_small = None
    png_p = payload.get("png")
    if png_p and png_p.exists():
        try:
            raw_png = tk.PhotoImage(file=str(png_p))
            logo_big = raw_png.subsample(2, 2)    # 64x64
            logo_small = raw_png.subsample(6, 6)  # ~21x21
        except Exception:
            logo_big = None
            logo_small = None

    # ==================== ÖZEL BAŞLIK ÇUBUĞU (40px) ====================
    titlebar = tk.Frame(shell, bg=CHROME, height=40)
    titlebar.pack(side="top", fill="x")
    titlebar.pack_propagate(False)

    drag_box = {"x": 0, "y": 0}

    def _start_drag(ev) -> None:
        drag_box["x"] = ev.x_root - root.winfo_x()
        drag_box["y"] = ev.y_root - root.winfo_y()

    def _on_drag(ev) -> None:
        nx = ev.x_root - drag_box["x"]
        ny = ev.y_root - drag_box["y"]
        root.geometry(f"+{nx}+{ny}")

    tb_left = tk.Frame(titlebar, bg=CHROME)
    tb_left.pack(side="left", fill="both", expand=True, padx=(12, 0))
    if logo_small is not None:
        lbl_ico = tk.Label(tb_left, image=logo_small, bg=CHROME)
        lbl_ico.pack(side="left", padx=(0, 8))
        lbl_ico.bind("<ButtonPress-1>", _start_drag)
        lbl_ico.bind("<B1-Motion>", _on_drag)

    lbl_tb_title = tk.Label(tb_left, text=APP_NAME, fg=TEXT, bg=CHROME, font=("Segoe UI", 9, "bold"))
    lbl_tb_title.pack(side="left")
    lbl_tb_sub = tk.Label(tb_left, text="  ·  Kurulum Sihirbazı", fg=MUTED, bg=CHROME, font=("Segoe UI", 9))
    lbl_tb_sub.pack(side="left")
    lbl_tb_ver = tk.Label(
        tb_left, text=f"v{APP_VERSION}", fg=BRAND_LIGHT, bg=SURFACE_2,
        font=("Consolas", 8, "bold"), padx=6, pady=1,
        highlightthickness=1, highlightbackground=BORDER,
    )
    lbl_tb_ver.pack(side="left", padx=(10, 0))

    for w in (titlebar, tb_left, lbl_tb_title, lbl_tb_sub, lbl_tb_ver):
        w.bind("<ButtonPress-1>", _start_drag)
        w.bind("<B1-Motion>", _on_drag)

    # Sağ pencere butonları (Küçült / Kapat)
    can_close_box = {"allow": True}

    def _safe_close() -> None:
        if can_close_box["allow"]:
            root.destroy()

    btn_win_close = tk.Label(
        titlebar, text="✕", fg=TEXT, bg=CHROME, width=5,
        font=("Segoe UI", 10), cursor="hand2",
    )
    btn_win_close.pack(side="right", fill="y")
    btn_win_close.bind("<Button-1>", lambda _e: _safe_close())
    btn_win_close.bind("<Enter>", lambda _e: btn_win_close.config(bg=CLOSE_RED if can_close_box["allow"] else CHROME))
    btn_win_close.bind("<Leave>", lambda _e: btn_win_close.config(bg=CHROME))

    btn_win_min = tk.Label(
        titlebar, text="—", fg=MUTED, bg=CHROME, width=5,
        font=("Segoe UI", 10), cursor="hand2",
    )
    btn_win_min.pack(side="right", fill="y")
    btn_win_min.bind("<Button-1>", lambda _e: _minimize_frameless(root, hwnd_box["hwnd"]))
    btn_win_min.bind("<Enter>", lambda _e: btn_win_min.config(bg=HOVER, fg=TEXT))
    btn_win_min.bind("<Leave>", lambda _e: btn_win_min.config(bg=CHROME, fg=MUTED))

    # ==================== GÖVDE ====================
    body = tk.Frame(shell, bg=BG)
    body.pack(fill="both", expand=True)

    # Sol kenar çubuğu (236px, ana tuvalle bütünleşik)
    side = tk.Frame(body, bg=SIDEBAR, width=236)
    side.pack(side="left", fill="y")
    side.pack_propagate(False)

    brand_box = tk.Frame(side, bg=SIDEBAR, padx=10, pady=10)
    brand_box.pack(fill="x", padx=16, pady=(10, 12))
    if logo_big is not None:
        tk.Label(brand_box, image=logo_big, bg=SIDEBAR).pack(pady=(2, 6))
    tk.Label(brand_box, text="ElfSec", fg=TEXT, bg=SIDEBAR, font=("Segoe UI", 16, "bold")).pack()
    tk.Label(brand_box, text=f"v{APP_VERSION} · {APP_PUBLISHER}", fg=BRAND_LIGHT, bg=SIDEBAR, font=("Segoe UI", 9, "bold")).pack(pady=(2, 0))

    # Adım İzleyici (numaralı daireler)
    step_defs = [
        ("1", "Hoş Geldiniz"),
        ("2", "Kurulum Ayarları"),
        ("3", "Kurulum İşlemi"),
        ("4", "Tamamlandı"),
    ]
    step_rows: list[tuple[tk.Frame, tk.Canvas, int, int, tk.Label]] = []
    steps_wrap = tk.Frame(side, bg=SIDEBAR)
    steps_wrap.pack(fill="x", padx=14)
    for num, name in step_defs:
        row = tk.Frame(steps_wrap, bg=SIDEBAR, padx=10, pady=8, highlightthickness=0)
        row.pack(fill="x", pady=3)
        cv = tk.Canvas(row, width=24, height=24, bg=SIDEBAR, highlightthickness=0)
        cv.pack(side="left", padx=(0, 10))
        oval = cv.create_oval(2, 2, 22, 22, fill=SURFACE_SOFT, outline=BORDER, width=1.5)
        txt_id = cv.create_text(12, 12, text=num, fill=MUTED, font=("Segoe UI", 9, "bold"))
        lbl = tk.Label(row, text=name, fg=MUTED, bg=SIDEBAR, anchor="w", font=("Segoe UI", 10))
        lbl.pack(side="left", fill="x", expand=True)
        step_rows.append((row, cv, oval, txt_id, lbl))

    priv_badge = tk.Frame(side, bg=SURFACE_SOFT, padx=10, pady=8)
    priv_badge.pack(side="bottom", fill="x", padx=16, pady=16)
    tk.Label(priv_badge, text="%100 Yerel · Sıfır Bulut", fg=BRAND_LIGHT, bg=SURFACE_SOFT, font=("Segoe UI", 8, "bold")).pack()
    tk.Label(priv_badge, text="© 2026 byeco · GPL-3.0", fg=MUTED, bg=SURFACE_SOFT, font=("Segoe UI", 8)).pack(pady=(2, 0))

    # Sağ ana alan (önce footer alt kenara sabitlenir ki content hiçbir zaman butonları dışarı itmesin)
    right = tk.Frame(body, bg=BG)
    right.pack(side="right", fill="both", expand=True, padx=(8, 22), pady=(8, 18))

    footer = tk.Frame(right, bg=BG)
    footer.pack(side="bottom", fill="x", pady=(12, 0))

    content = tk.Frame(right, bg=SURFACE, highlightthickness=1, highlightbackground=BORDER)
    content.pack(side="top", fill="both", expand=True)
    content.pack_propagate(False)

    # ==================== YARDIMCI BİLEŞENLER ====================
    def _make_btn(parent, text: str, variant: str = "secondary", command=None, padx: int = 18) -> tk.Button:
        if variant == "primary":
            bg_c, fg_c, hov_c = BRAND, "#ffffff", BRAND_DARK
        elif variant == "ghost":
            bg_c, fg_c, hov_c = BG, MUTED, SURFACE
        else:
            bg_c, fg_c, hov_c = SURFACE, TEXT, HOVER
        btn = tk.Button(
            parent, text=text, bg=bg_c, fg=fg_c,
            activebackground=hov_c, activeforeground=fg_c,
            relief="flat", bd=0, padx=padx, pady=8,
            font=("Segoe UI", 10, "bold" if variant != "ghost" else "normal"),
            cursor="hand2", command=command,
            highlightthickness=1 if variant == "secondary" else 0,
            highlightbackground=BORDER,
        )

        def _enter(_e) -> None:
            if str(btn["state"]) != "disabled":
                btn.config(bg=hov_c, fg="#ffffff" if variant == "primary" else TEXT)

        def _leave(_e) -> None:
            btn.config(bg=bg_c, fg=fg_c)

        btn.bind("<Enter>", _enter)
        btn.bind("<Leave>", _leave)
        return btn

    def _make_checkbox(parent, text: str, var: tk.BooleanVar, bold: bool = False) -> tk.Frame:
        row = tk.Frame(parent, bg=SURFACE_2, padx=11, pady=7, cursor="hand2")
        cv = tk.Canvas(row, width=18, height=18, bg=SURFACE_2, highlightthickness=0, cursor="hand2")
        cv.pack(side="left", padx=(0, 10))
        lbl = tk.Label(
            row, text=text, fg=TEXT, bg=SURFACE_2, anchor="w",
            font=("Segoe UI", 10, "bold" if bold else "normal"), cursor="hand2",
        )
        lbl.pack(side="left", fill="x", expand=True)

        def _redraw(*_args) -> None:
            cv.delete("all")
            checked = bool(var.get())
            fill_c = BRAND if checked else BG
            out_c = BRAND_LIGHT if checked else BORDER
            cv.create_rectangle(2, 2, 16, 16, fill=fill_c, outline=out_c, width=1.5)
            if checked:
                cv.create_line(5, 9.5, 8, 12.5, 13.5, 6, fill="#ffffff", width=2, capstyle="round", joinstyle="round")

        def _toggle(_e=None) -> None:
            var.set(not var.get())
            _redraw()

        def _enter(_e) -> None:
            row.config(bg=HOVER)
            cv.config(bg=HOVER)
            lbl.config(bg=HOVER)

        def _leave(_e) -> None:
            row.config(bg=SURFACE_2)
            cv.config(bg=SURFACE_2)
            lbl.config(bg=SURFACE_2)

        for w in (row, cv, lbl):
            w.bind("<Button-1>", _toggle)
            w.bind("<Enter>", _enter)
            w.bind("<Leave>", _leave)
        _redraw()
        return row

    # State değişkenleri
    default_dir = str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ElfSec")
    var_dir = tk.StringVar(value=default_dir)
    var_service = tk.BooleanVar(value=True)
    var_tray = tk.BooleanVar(value=True)
    var_context = tk.BooleanVar(value=True)
    var_desktop = tk.BooleanVar(value=True)
    var_startmenu = tk.BooleanVar(value=True)
    var_launch = tk.BooleanVar(value=True)

    btn_cancel = _make_btn(footer, "İptal", variant="ghost", command=_safe_close, padx=14)
    btn_next = _make_btn(footer, "İleri  ›", variant="primary", padx=22)
    btn_back = _make_btn(footer, "‹  Geri", variant="secondary", padx=16)
    btn_cancel.pack(side="left")
    btn_next.pack(side="right")
    btn_back.pack(side="right", padx=(0, 8))

    current_step = {"idx": 0}
    pages: list[tk.Frame] = []

    # ==================== SAYFA 0: HOŞ GELDİNİZ ====================
    p0 = tk.Frame(content, bg=SURFACE, padx=24, pady=18)
    tk.Label(p0, text="ElfSec Güvenlik Sistemine Hoş Geldiniz", fg=TEXT, bg=SURFACE, font=("Segoe UI", 14, "bold"), anchor="w").pack(fill="x")
    tk.Label(
        p0,
        text="Bu kurulum sihirbazı yerel koruma motorunu, Windows servisini ve çerçevesiz ElfSec Güvenlik Merkezini kurar.",
        fg=MUTED, bg=SURFACE, wraplength=480, justify="left", font=("Segoe UI", 9),
    ).pack(fill="x", pady=(4, 10))

    features = (
        ("Gerçek Zamanlı İndirilenler Kalkanı", "PE maskeleme, çift uzantı (.pdf.exe) ve ek önbellek analizi"),
        ("ClickFix & Pano Koruması", "Gizli PowerShell, mshta ve zararlı komutları yapıştırmadan yakalar"),
        ("Akıllı Oyun Modu", "Tam ekran oyun algılandığında CPU ve bildirim yükünü sıfıra yaklaştırır"),
        ("Tarayıcı Native Host Köprüsü", "Chrome, Edge ve Brave uzantınızla şifreli yerel iletişim kurar"),
        ("%100 Cihaz Üzerinde Gizlilik", "Bulut yüklemesi yok, harici API anahtarı yok, telemetri yok"),
    )
    for title_f, desc_f in features:
        fcard = tk.Frame(p0, bg=SURFACE_2, padx=12, pady=6)
        fcard.pack(fill="x", pady=3)
        dot = tk.Canvas(fcard, width=10, height=10, bg=SURFACE_2, highlightthickness=0)
        dot.pack(side="left", padx=(0, 10))
        dot.create_oval(1, 1, 9, 9, fill=BRAND_LIGHT, outline="")
        txt_col = tk.Frame(fcard, bg=SURFACE_2)
        txt_col.pack(side="left", fill="x", expand=True)
        tk.Label(txt_col, text=title_f, fg=TEXT, bg=SURFACE_2, font=("Segoe UI", 9, "bold"), anchor="w").pack(fill="x")
        tk.Label(txt_col, text=desc_f, fg=MUTED, bg=SURFACE_2, font=("Segoe UI", 8), anchor="w").pack(fill="x")
    pages.append(p0)

    # ==================== SAYFA 1: KURULUM AYARLARI ====================
    p1 = tk.Frame(content, bg=SURFACE, padx=24, pady=18)
    tk.Label(p1, text="Kurulum Dizini ve Bileşenler", fg=TEXT, bg=SURFACE, font=("Segoe UI", 14, "bold"), anchor="w").pack(fill="x")
    tk.Label(p1, text="Hedef kurulum klasörü:", fg=MUTED, bg=SURFACE, anchor="w", font=("Segoe UI", 9)).pack(fill="x", pady=(8, 4))

    dir_row = tk.Frame(p1, bg=SURFACE)
    dir_row.pack(fill="x", pady=(0, 8))
    dir_box = tk.Frame(dir_row, bg=SURFACE_2, highlightthickness=1, highlightbackground=BORDER, padx=8, pady=2)
    dir_box.pack(side="left", fill="x", expand=True)
    tk.Entry(
        dir_box, textvariable=var_dir, bg=SURFACE_2, fg=TEXT, insertbackground=TEXT,
        relief="flat", bd=0, font=("Consolas", 10),
    ).pack(fill="x", ipady=5)

    def _browse() -> None:
        chosen = filedialog.askdirectory(initialdir=var_dir.get() or default_dir)
        if chosen:
            var_dir.set(str(Path(chosen) / "ElfSec") if not chosen.lower().endswith("elfsec") else chosen)

    _make_btn(dir_row, "Gözat…", variant="secondary", command=_browse, padx=14).pack(side="right", padx=(8, 0))

    for var, txt in (
        (var_service, "Windows Arka Plan Güvenlik Servisi (ElfSecGuard)"),
        (var_tray, "Sistem Tepsisi, Pano Kalkanı & Akıllı Oyun Modu"),
        (var_context, "Sağ-tık tarama menüsü & Tarayıcı Native Host köprüsü"),
        (var_desktop, "Masaüstü kısayolu oluştur"),
        (var_startmenu, "Başlat Menüsü kısayolları oluştur"),
    ):
        _make_checkbox(p1, txt, var).pack(fill="x", pady=4)
    pages.append(p1)

    # ==================== SAYFA 2: KURULUM İŞLEMİ ====================
    p2 = tk.Frame(content, bg=SURFACE, padx=26, pady=22)
    tk.Label(p2, text="ElfSec Kuruluyor…", fg=TEXT, bg=SURFACE, font=("Segoe UI", 14, "bold"), anchor="w").pack(fill="x")

    prog_hdr = tk.Frame(p2, bg=SURFACE)
    prog_hdr.pack(fill="x", pady=(14, 6))
    lbl_prog = tk.Label(prog_hdr, text="Hazırlanıyor…", fg=BRAND_LIGHT, bg=SURFACE, anchor="w", font=("Segoe UI", 10, "bold"))
    lbl_prog.pack(side="left", fill="x", expand=True)
    lbl_pct = tk.Label(prog_hdr, text="%0", fg=TEXT, bg=SURFACE, font=("Consolas", 10, "bold"))
    lbl_pct.pack(side="right")

    pb_canvas = tk.Canvas(p2, height=14, bg=SURFACE_2, highlightthickness=1, highlightbackground=BORDER)
    pb_canvas.pack(fill="x", pady=(0, 14))
    prog_val = {"pct": 0}

    def _draw_pb() -> None:
        pb_canvas.delete("all")
        w = max(10, pb_canvas.winfo_width())
        pct = max(0, min(100, prog_val["pct"]))
        fill_w = int((w - 2) * (pct / 100.0))
        if fill_w > 0:
            pb_canvas.create_rectangle(1, 1, 1 + fill_w, 13, fill=BRAND, outline="")
            pb_canvas.create_rectangle(1, 1, 1 + fill_w, 5, fill=BRAND_LIGHT, outline="")

    pb_canvas.bind("<Configure>", lambda _e: _draw_pb())

    log_wrap = tk.Frame(p2, bg=SURFACE_2, padx=8, pady=8)
    log_wrap.pack(fill="both", expand=True)
    log_box = tk.Text(log_wrap, bg=SURFACE_2, fg=MUTED, height=11, relief="flat", bd=0, font=("Consolas", 9), state="disabled")
    log_box.pack(fill="both", expand=True)
    pages.append(p2)

    # ==================== SAYFA 3: TAMAMLANDI ====================
    p3 = tk.Frame(content, bg=SURFACE, padx=26, pady=24)
    done_badge = tk.Frame(p3, bg=ACTIVE_STEP_BG, padx=12, pady=6)
    done_badge.pack(anchor="w", pady=(0, 12))
    tk.Label(done_badge, text="✓  KURULUM BAŞARILI", fg=BRAND_LIGHT, bg=ACTIVE_STEP_BG, font=("Segoe UI", 9, "bold")).pack()

    tk.Label(p3, text="ElfSec Güvenlik Sistemi Hazır!", fg=TEXT, bg=SURFACE, font=("Segoe UI", 16, "bold"), anchor="w").pack(fill="x")
    lbl_done = tk.Label(p3, text="", fg=MUTED, bg=SURFACE, wraplength=470, justify="left", font=("Segoe UI", 10))
    lbl_done.pack(fill="x", pady=(10, 16))

    summary_card = tk.Frame(p3, bg=SURFACE_2, padx=14, pady=12)
    summary_card.pack(fill="x", pady=(0, 16))
    lbl_summary = tk.Label(summary_card, text="", fg=TEXT, bg=SURFACE_2, justify="left", anchor="w", font=("Consolas", 9))
    lbl_summary.pack(fill="x")

    _make_checkbox(p3, "ElfSec Güvenlik Merkezini şimdi aç", var_launch, bold=True).pack(fill="x")
    pages.append(p3)

    def _append_log(msg: str, pct: int | None = None) -> None:
        def _ui() -> None:
            if pct is not None:
                prog_val["pct"] = pct
                lbl_pct.config(text=f"%{pct}")
                _draw_pb()
            lbl_prog.config(text=msg)
            log_box.config(state="normal")
            log_box.insert("end", f"› {msg}\n")
            log_box.see("end")
            log_box.config(state="disabled")
        root.after(0, _ui)

    def _run_install() -> None:
        install_dir = Path(var_dir.get().strip() or default_dir)
        try:
            _append_log("Kurulum dizini hazırlanıyor…", 15)
            install_dir.mkdir(parents=True, exist_ok=True)
            exe_src = payload.get("exe")
            if not exe_src or not exe_src.exists():
                raise FileNotFoundError("Kurulum paketi içinde elfsec.exe bulunamadı.")

            target_exe = install_dir / "elfsec.exe"
            _append_log("Çalışan ElfSec süreçleri durduruluyor…", 25)
            subprocess.run(["taskkill", "/F", "/IM", "elfsec.exe"], capture_output=True, check=False, creationflags=0x08000000)

            _append_log(f"elfsec.exe kopyalanıyor -> {target_exe}", 40)
            shutil.copy2(exe_src, target_exe)

            ico_src = payload.get("ico")
            target_ico = install_dir / "elfsec.ico"
            if ico_src and ico_src.exists():
                shutil.copy2(ico_src, target_ico)

            ext_src = payload.get("ext")
            if ext_src and ext_src.exists():
                _append_log("Tarayıcı uzantı dosyaları kopyalanıyor…", 52)
                ext_dst = install_dir / "extension"
                if ext_dst.exists():
                    shutil.rmtree(ext_dst, ignore_errors=True)
                shutil.copytree(ext_src, ext_dst)

            (install_dir / "uninstall.cmd").write_text(build_uninstall_cmd(str(install_dir)), encoding="utf-8")

            if var_context.get() or var_service.get() or var_tray.get():
                _append_log("Windows Güvenlik Eklentisi ve servis kaydediliyor…", 70)
                cmd = [str(target_exe), "plugin", "install", "--exe", str(target_exe)]
                if not var_service.get():
                    cmd.append("--no-service")
                if not var_tray.get():
                    cmd.append("--no-start")
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=45, check=False, creationflags=0x08000000)
                if res.returncode != 0:
                    _append_log(f"Uyarı: plugin install kodu={res.returncode}")

            ico_arg = str(target_ico if target_ico.exists() else target_exe)
            if var_startmenu.get():
                _append_log("Başlat Menüsü kısayolları oluşturuluyor…", 84)
                sm_dir = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "ElfSec"
                _create_shortcut(sm_dir / "ElfSec Güvenlik Merkezi.lnk", str(target_exe), "ui", ico_arg, str(install_dir))
                _create_shortcut(sm_dir / "ElfSec Tepsi Koruması.lnk", str(target_exe), "agent --tray", ico_arg, str(install_dir))
                _create_shortcut(sm_dir / "ElfSec Kaldır.lnk", str(install_dir / "uninstall.cmd"), "", ico_arg, str(install_dir))

            if var_desktop.get():
                _append_log("Masaüstü kısayolu oluşturuluyor…", 92)
                desk = Path(os.environ.get("PUBLIC", r"C:\Users\Public")) / "Desktop" / "ElfSec.lnk"
                _create_shortcut(desk, str(target_exe), "ui", ico_arg, str(install_dir))

            _append_log("Windows Program Ekle/Kaldır kaydı ekleniyor…", 96)
            try:
                _write_uninstall_registry(str(install_dir))
            except Exception:
                pass

            _append_log("Kurulum tamamlandı!", 100)
            root.after(0, lambda: _finish_install(install_dir, target_exe))
        except Exception as e:
            err_msg = str(e)
            root.after(0, lambda msg=err_msg: _fail_install(msg))

    installed_exe_box = {"exe": None}

    def _finish_install(install_dir: Path, target_exe: Path) -> None:
        installed_exe_box["exe"] = target_exe
        lbl_done.config(
            text="Arka plan koruması, ClickFix Pano Kalkanı, Akıllı Oyun Modu ve yerel Güvenlik Merkezi kullanıma hazır."
        )
        lbl_summary.config(
            text=f"Hedef Klasör : {install_dir}\n"
                 f"Uygulama     : {target_exe}\n"
                 f"Servis       : {'Etkin (ElfSecGuard)' if var_service.get() else 'Atlandı'}"
        )
        show_step(3)

    def _fail_install(err: str) -> None:
        messagebox.showerror("Kurulum Hatası", f"Kurulum sırasında hata oluştu:\n{err}")
        show_step(1)

    def show_step(idx: int) -> None:
        current_step["idx"] = idx
        can_close_box["allow"] = idx != 2
        btn_win_close.config(fg=MUTED if idx == 2 else TEXT)

        for i, p in enumerate(pages):
            if i == idx:
                p.pack(fill="both", expand=True)
            else:
                p.pack_forget()

        for i, (row, cv, oval, txt_id, lbl) in enumerate(step_rows):
            if i < idx:
                row.config(bg=SIDEBAR)
                cv.config(bg=SIDEBAR)
                cv.itemconfig(oval, fill=BRAND_DARK, outline=BRAND_LIGHT)
                cv.itemconfig(txt_id, text="✓", fill="#ffffff")
                lbl.config(fg=TEXT, bg=SIDEBAR, font=("Segoe UI", 10))
            elif i == idx:
                row.config(bg=ACTIVE_STEP_BG)
                cv.config(bg=ACTIVE_STEP_BG)
                cv.itemconfig(oval, fill=BRAND, outline=BRAND_LIGHT)
                cv.itemconfig(txt_id, text=str(i + 1), fill="#ffffff")
                lbl.config(fg=BRAND_LIGHT, bg=ACTIVE_STEP_BG, font=("Segoe UI", 10, "bold"))
            else:
                row.config(bg=SIDEBAR)
                cv.config(bg=SIDEBAR)
                cv.itemconfig(oval, fill=SURFACE_SOFT, outline=BORDER)
                cv.itemconfig(txt_id, text=str(i + 1), fill=MUTED)
                lbl.config(fg=MUTED, bg=SIDEBAR, font=("Segoe UI", 10))

        btn_back.config(state="normal" if idx == 1 else "disabled")
        btn_cancel.config(state="disabled" if idx >= 2 else "normal")
        if idx == 0:
            btn_next.config(text="İleri  ›", state="normal")
        elif idx == 1:
            btn_next.config(text="Kurulumu Başlat", state="normal")
        elif idx == 2:
            btn_next.config(text="Kuruluyor…", state="disabled")
        elif idx == 3:
            btn_next.config(text="Bitir", state="normal")

    def _on_back() -> None:
        if current_step["idx"] == 1:
            show_step(0)

    def _on_next() -> None:
        idx = current_step["idx"]
        if idx == 0:
            show_step(1)
        elif idx == 1:
            show_step(2)
            threading.Thread(target=_run_install, daemon=True).start()
        elif idx == 3:
            exe = installed_exe_box["exe"]
            if var_launch.get() and exe and Path(exe).exists():
                try:
                    subprocess.Popen([str(exe), "ui"], creationflags=0x08000008, close_fds=True)
                except Exception:
                    pass
            root.destroy()

    btn_back.config(command=_on_back)
    btn_next.config(command=_on_next)
    root.bind("<Return>", lambda _e: _on_next() if str(btn_next["state"]) == "normal" else None)
    show_step(0)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(launch_wizard())
