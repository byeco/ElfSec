"""Programın giriş kapısı — PyInstaller bunu tek exe'ye paketliyor.

Fikrim şuydu: kullanıcı tek dosya indirsin, o dosya her şeyi yapsın.
  elfsec.exe health                      -> konsol
  elfsec.exe guard --tray/--background   -> konsolu gizle + toast + loop
Argümansız açılırsa (çift tık) menü geliyor, yoksa komut çalışıyor.
"""
import sys

try:
    from app.table import ensure_utf8

    ensure_utf8()
except Exception:
    pass


def _maybe_hide_console() -> None:
    if "guard" in sys.argv[1:] and any(a in ("--tray", "--background") for a in sys.argv[1:]):
        try:
            from app.tray import hide_console

            hide_console()
        except Exception:
            pass


_maybe_hide_console()

from app.cli import main

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Çift tıkla açılış: pencere anında kapanmasın diye interaktif menü.
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
