"""Şifre kasası: hassas değerleri (IMAP şifresi, API anahtarı) diske şifreli yazar.

Windows: DPAPI (CryptProtectData) — o kullanıcı hesabına bağlı şifreleme,
ek bağımlılık yok (ctypes). Başka kullanıcı/PC'de çözülemez.
Diğer platformlar: açık saklanır + çağrı yerinde uyarı verilir.

Dosya formatı: ENC(<base64>)
"""

import base64
import os

PREFIX = "ENC("
SUFFIX = ")"


def is_protected(value: str) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX) and value.endswith(SUFFIX)


def available() -> tuple[bool, str]:
    """(kullanılabilir-mi, açıklama) — kullanıcıya nedenini söylemek için."""
    if os.name == "nt":
        return True, "Windows DPAPI (kullanıcı hesabına bağlı şifreleme)"
    return False, "bu platformda DPAPI yok — hassas değerler açık saklanır"


def _dpapi_blob(data: bytes):
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_byte))]

    buf = ctypes.create_string_buffer(data)
    blob = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
    return blob, buf  # buf referansı caller'da canlı tutulmalı


def _dpapi_protect(plain: bytes) -> bytes:
    import ctypes

    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    in_blob, _keep = _dpapi_blob(plain)
    out_blob, _ = _dpapi_blob(b"")
    if not crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise OSError("DPAPI şifreleme başarısız")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(blob: bytes) -> bytes:
    import ctypes

    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    in_blob, _keep = _dpapi_blob(blob)
    out_blob, _ = _dpapi_blob(b"")
    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise OSError("DPAPI çözme başarısız (farklı kullanıcı/PC olabilir)")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def protect(plain: str) -> str:
    """Açık metni saklanabilir forma çevir (Windows'ta şifreli)."""
    if os.name == "nt":
        return PREFIX + base64.b64encode(_dpapi_protect(plain.encode("utf-8"))).decode("ascii") + SUFFIX
    return plain


def unprotect(stored: str) -> str:
    """Saklanan değeri çöz (şifreli değilse aynen döndür)."""
    if not is_protected(stored):
        return stored
    if os.name != "nt":
        raise OSError("ENC(...) değer Windows dışında çözülemez")
    raw = base64.b64decode(stored[len(PREFIX):-len(SUFFIX)])
    return _dpapi_unprotect(raw).decode("utf-8")
