"""Programın giriş kapısı — PyInstaller bunu tek exe'ye paketliyor.

Fikrim şuydu: kullanıcı tek dosya indirsin, o dosya her şeyi yapsın.
  elfsec.exe health                      -> konsol
  elfsec.exe guard --tray/--background   -> konsolu gizle + toast + loop
Argümansız açılırsa (çift tık) menü geliyor, yoksa komut çalışıyor.
"""
import os
import sys

try:
    from app.table import ensure_utf8

    ensure_utf8()
except Exception:
    pass


def _maybe_hide_console() -> None:
    args = sys.argv[1:]
    hide_for_bg = any(c in args for c in ("guard", "agent")) and any(
        a in ("--tray", "--background") for a in args
    )
    hide_for_ui = "ui" in args and "--no-browser" not in args and "--console" not in args
    hide_for_double_click = (
        len(args) == 0
        and os.name == "nt"
        and os.environ.get("ELFSEC_CLI_MENU") != "1"
    )
    if hide_for_bg or hide_for_ui or hide_for_double_click:
        try:
            from app.tray import hide_console

            hide_console()
        except Exception:
            pass


_maybe_hide_console()

from app.cli import main

if __name__ == "__main__":
    if len(sys.argv) == 1:
        if os.name == "nt" and os.environ.get("ELFSEC_CLI_MENU") != "1":
            try:
                from app.desktop_ui import run_desktop_panel

                raise SystemExit(run_desktop_panel(port=0, open_browser=True))
            except SystemExit:
                raise
            except Exception:
                pass
        # Çift tıkla açılış (CLI yedek modu): pencere anında kapanmasın diye interaktif menü.
        try:
            from app.interactive import run_menu

            code = run_menu()
        except Exception as e:
            print(f"HATA: {type(e).__name__}: {e}")
            code = 2
        try:
            input("Çıkmak için Enter'a basın...")
        except (EOFError, KeyboardInterrupt):
            pass
        raise SystemExit(code)
    raise SystemExit(main())
