"""Çift-tık menüsü — exe'ye çift tıklayınca pencere anında kapanıyordu,
kullanıcı hiçbir şey okuyamadan gidiyordu. Ben de menü ekledim.

Menü mantığını saf yazdım (input/print dışarıdan verilebiliyor) ki
testler sahte girişle koşabilsin, gerçek main'e dokunmadan.
"""

from __future__ import annotations

from typing import Callable

MENU: tuple[tuple[str, str, list[str] | None], ...] = (
    ("1", "Kurulum sihirbazı (e-posta bağla)", ["config", "setup"]),
    ("2", "Durum kontrolü", ["health"]),
    ("3", "Kutuyu tara (son 5 mail)", ["triage", "--limit", "5"]),
    ("4", "Tek tur koruma", ["guard", "--once"]),
    ("5", "Güvenlik denetimi", ["kontrol", "--fail-only"]),
    ("6", "Panel (durum + son alarmlar)", ["dashboard"]),
    ("7", "Web API'yi başlat (site bu adresten skor çeker)", ["serve"]),
    ("0", "Çıkış", None),
)


def run_menu(input_fn: Callable[[str], str] = input,
             print_fn: Callable[[str], None] = print,
             main_fn: Callable[[list[str]], int] | None = None) -> int:
    """Menü döngüsü. Dönüş: son komutun exit-code'u (çıkışta 0)."""
    run = main_fn
    if run is None:
        from app.cli import main as _main

        def _run(argv: list[str]) -> int:
            return int(_main(argv) or 0)

        run = _run

    print_fn("ElfSec — E-posta Güvenlik Tool'u (v" + _version() + ")")
    last = 0
    while True:
        print_fn("")
        for key, label, _ in MENU:
            print_fn(f"  [{key}] {label}")
        try:
            choice = input_fn("Seçim: ").strip()
        except (EOFError, KeyboardInterrupt):
            print_fn("")
            return last
        if choice in ("0", "q", "Q"):
            return last
        hit = next((m for m in MENU if m[0] == choice), None)
        if hit is None:
            print_fn(f"HATA: 0-{len(MENU) - 2} arası bir numara girin.")
            continue
        assert hit[2] is not None and run is not None  # "0" yukarıda elendi
        print_fn("")
        try:
            last = int(run(list(hit[2])) or 0)
        except SystemExit as e:
            last = int(e.code or 0)
        except Exception as e:
            print_fn(f"HATA: {type(e).__name__}: {e}")
            last = 2
        print_fn(f"(çıkış kodu: {last})")


def _version() -> str:
    try:
        from app.__version__ import __version__

        return __version__
    except Exception:
        return "?"
