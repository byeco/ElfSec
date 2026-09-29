"""Arka planda sessizce çalışan koruma — konsol penceresi gözükmesin diye yazdım.

Kullanım (tek exe):
    elfsec.exe guard --unseen --interval 10 --tray
    elfsec.exe guard --unseen --interval 10 --background   # --tray ile aynı

- Windows'ta konsol penceresi gizleniyor (açılışta minik bir kırpışma oluyor, normal).
- pystray kuruluysa tepside ikon çıkıyor, yoksa sessizce arkada dönüyor.
- Hata olursa program ölmüyor: bildirim + log atıp sonraki tura devam ediyor.
  (İlk sürümde hata alınca her şey duruyordu, guard'ın mantığına aykırıydı.)
"""

from __future__ import annotations

import os


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
    if "guard" not in args:
        return False
    return any(a in ("--tray", "--background") for a in args)


def run_tray_loop(stop_event=None, tooltip: str = "ElfSec Guard") -> bool:
    """pystray varsa ikon göster, yoksa False dön (çağıran sessiz devam eder)."""
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
