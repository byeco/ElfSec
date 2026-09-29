"""Terminalde kutulu tablolar basan küçük motor — ekstra kütüphanesiz yazdım.

Düz liste çıktısı çok çirkin duruyordu, o yüzden tablo yaptım. Ama
dikkat ettiğim bir şey var: pipe/CI bozulmasın diye renk ve tablo
sadece gerçek terminalde (tty) çıkıyor; `--json/--out/--quiet`
verilirse eski düz metin aynen korunuyor (testler de bunu kontrol ediyor).
Türkçe karakterler eski cmd'de � oluyordu, onu da düzelttim (ensure_utf8).
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import unicodedata

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

COLORS = {
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "cyan": "\x1b[36m",
    "gray": "\x1b[90m",
    "bold": "\x1b[1m",
    "reset": "\x1b[0m",
}

SEV_COLORS = {
    "CRITICAL": "red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "FAIL": "red",
    "WARN": "yellow",
    "PASS": "green",
    "SKIP": "gray",
    "HAZIR": "green",
    "EKSIK": "red",
    "açık": "green",
    "KAPALI": "gray",
}

_ascii = False


def _vt_enable() -> None:
    """Windows konsolunda ANSI (VT) işlemeyi açmayı dene. Başarısızlık sessiz."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


def ensure_utf8() -> None:
    """Windows legacy konsolda (cp1254/cp437) Türkçe karakterlerin � olmasını engelle.

    - stdout/stderr'i UTF-8'e zorlar (best-effort, asla crash yok).
    - Hâlâ UTF-8 değilse (çok eski cmd) kutu çizgilerini ASCII'ye düşürür.
    """
    global _ascii
    try:
        reconfig = getattr(sys.stdout, "reconfigure", None)
        if callable(reconfig):
            reconfig(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        reconfig = getattr(sys.stderr, "reconfigure", None)
        if callable(reconfig):
            reconfig(encoding="utf-8", errors="replace")
    except Exception:
        pass
    _vt_enable()
    try:
        enc = (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "")
        if enc and "utf8" not in enc:
            _ascii = True
    except Exception:
        pass


def supports_color() -> bool:
    """Renk basılsın mı? NO_COLOR saygılı, pipe'ta kapalı."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("ELFSEC_COLOR") == "1":
        _vt_enable()
        return True
    if os.environ.get("ELFSEC_COLOR") == "0":
        return False
    try:
        if not sys.stdout.isatty():
            return False
    except Exception:
        return False
    _vt_enable()
    return True


def color(text: object, name: str) -> str:
    """Renk destekleniyorsa sar, yoksa düz metin."""
    s = str(text)
    if not supports_color() or name not in COLORS:
        return s
    return f"{COLORS[name]}{s}{COLORS['reset']}"


def sev(text: object) -> str:
    """Seviye/durum kelimesini rengine boyar (LOW, HIGH, PASS, FAIL...)."""
    s = str(text)
    return color(s, SEV_COLORS[s]) if s in SEV_COLORS else s


def use_table(args) -> bool:
    """Tablo basılsın mı? tty + insan çıktısıysa True.

    `--json/--out/--quiet` veya pipe her zaman eski düz metni korur
    (testler ve otomasyon bozulmaz).
    """
    try:
        if getattr(args, "json", False) or getattr(args, "out", "") or getattr(args, "quiet", False):
            return False
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def visible_width(s: str) -> int:
    """ANSI kaçışsız, CJK-uyumlu görünür genişlik."""
    s = _ANSI_RE.sub("", s)
    w = 0
    for ch in s:
        w += 2 if unicodedata.east_asian_width(ch) in ("F", "W") else 1
    return w


def truncate(s: str, n: int) -> str:
    """Görünür genişliği n'yi aşarsa … ile kısalt (renk korunur)."""
    s = str(s)
    if visible_width(s) <= n or n <= 1:
        return s
    plain = _ANSI_RE.sub("", s)
    out, w = "", 0
    for ch in plain:
        cw = 2 if unicodedata.east_asian_width(ch) in ("F", "W") else 1
        if w + cw > n - 1:
            break
        out += ch
        w += cw
    return out + "…"


def _term_width(default: int = 100) -> int:
    try:
        return max(40, shutil.get_terminal_size().columns)
    except Exception:
        return default


def _fit_widths(widths: list[int], max_total: int, min_col: int = 6) -> list[int]:
    """Toplam genişliği max_total'e sığdır: en geniş sütundan kıs."""
    widths = list(widths)
    while sum(widths) + 3 * len(widths) + 1 > max_total:
        i = max(range(len(widths)), key=lambda k: widths[k])
        if widths[i] <= min_col:
            break
        widths[i] -= 1
    return widths


def render(headers: list[str], rows: list[list[object]], title: str = "",
           max_width: int | None = None, aligns: list[str] | None = None) -> str:
    """Kutulu tablo üret. Hücreler önceden renklendirilmiş olabilir."""
    cells = [[str(c) for c in r] + [""] * (len(headers) - len(r)) for r in rows]
    cells = [row[:len(headers)] for row in cells]
    widths = [visible_width(h) for h in headers]
    for row in cells:
        for i, c in enumerate(row):
            widths[i] = max(widths[i], visible_width(c))
    widths = _fit_widths(widths, max_width or _term_width())

    def _pad(s: str, w: int, align: str) -> str:
        t = truncate(s, w)
        pad = w - visible_width(t)
        if align == "r":
            return " " * pad + t
        if align == "c":
            left = pad // 2
            return " " * left + t + " " * (pad - left)
        return t + " " * pad

    aligns = list(aligns or []) + ["l"] * len(headers)
    hbar = "─"
    if _ascii or os.environ.get("ELFSEC_ASCII") == "1":
        tl, tm, tr, ml, mm, mr, bl, bm, br, v, hbar = ("+", "+", "+", "+", "+", "+",
                                                      "+", "+", "+", "|", "-")
    else:
        tl, tm, tr, ml, mm, mr, bl, bm, br, v = "┌", "┬", "┐", "├", "┼", "┤", "└", "┴", "┘", "│"

    def _line(left: str, mid: str, right: str) -> str:
        return left + mid.join(hbar * (w + 2) for w in widths) + right

    lines = []
    if title:
        lines.append(color(title, "bold"))
    lines.append(_line(tl, tm, tr))
    lines.append(v + v.join(f" {color(h, 'bold')}" + " " * (w - visible_width(h) + 1)
                            for h, w in zip(headers, widths)) + v)
    lines.append(_line(ml, mm, mr))
    for row in cells:
        lines.append(v + v.join(f" {_pad(c, w, aligns[i])} "
                                for i, (c, w) in enumerate(zip(row, widths))) + v)
    lines.append(_line(bl, bm, br))
    return "\n".join(lines)


def panel(title: str, items: list[tuple[str, object]], max_width: int | None = None) -> str:
    """İki sütunlu anahtar-değer kutusu (health/durum için)."""
    return render(["Özellik", "Değer"], [[k, v] for k, v in items],
                  title=title, max_width=max_width)
