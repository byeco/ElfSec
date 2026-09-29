"""Log tutma işi — ekrana print basmaya devam ediyorum ama makine
için olan izi de dosyaya yazıyorum (elfsec.log, 1 MB x 3 rotasyon).

Kullanım: get_logger("guard") -> logger.info/warning/error.
Not: Windows'ta açık dosya kilitli kalıyor, handler'ı kapatmayı
unutunca temp-dizin silinemeyip WinError 32 patlamıştı. Ders oldu,
artık kapatıyorum.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOGGERS: dict[str, logging.Logger] = {}


def get_logger(name: str = "elfsec", log_file: str = "elfsec.log") -> logging.Logger:
    """Aynı isim farklı dosyaya geçerse eski handler kapatılır.

    (Windows'ta açık dosya kilitli kalır — kapatılmazsa temp-dizin temizliği
    WinError 32 ile patlar. Kontrol bunu yakaladı.)
    """
    lg = logging.getLogger(f"elfsec.{name}")
    lg.setLevel(logging.INFO)
    want = str(Path(log_file).resolve())
    have = [getattr(h, "baseFilename", "") for h in lg.handlers
            if isinstance(h, RotatingFileHandler)]
    if have == [want]:
        _LOGGERS[name] = lg
        return lg
    for h in lg.handlers[:]:
        try:
            h.close()
        except Exception:
            pass
        lg.removeHandler(h)
    try:
        fh = RotatingFileHandler(want, maxBytes=1_000_000,
                                 backupCount=3, encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s [%(name)s] %(message)s"))
        lg.addHandler(fh)
    except Exception:
        lg.addHandler(logging.StreamHandler())
    _LOGGERS[name] = lg
    return lg


def close_logger(name: str = "elfsec") -> None:
    """Handler'ları kapat (temp-dizin kilidi kalkar, WinError 32 önlenir)."""
    lg = logging.getLogger(f"elfsec.{name}")
    for h in lg.handlers[:]:
        try:
            h.close()
        except Exception:
            pass
        lg.removeHandler(h)
    _LOGGERS.pop(name, None)
