"""Kısaltılmış linklerin arkasını merak edip yazdığım küçük modül.

Normalde ElfSec çevrimdışı çalışıyor, bu benim için önemli bir ilkeydi.
O yüzden genişletme varsayılan olarak KAPALI — sadece kullanıcı
`--expand-urls` verirse bit.ly gibi linklerin gerçek adresi bulunuyor
ve o puanlanıyor. İnternet yoksa ya da site cevap vermezse sessizce
geçiliyor, offline skor korunuyor.
"""

from __future__ import annotations

import urllib.request


def expand_url(url: str, timeout: int = 8, max_hops: int = 3) -> str:
    """Kısa URL'yi HEAD istekleriyle genişlet. Dönüş: son URL (ya da giriş)."""
    cur = url
    for _ in range(max_hops):
        try:
            req = urllib.request.Request(cur, method="HEAD",
                                         headers={"User-Agent": "ElfSec/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                nxt = resp.geturl()
            if not nxt or nxt == cur:
                return cur
            cur = nxt
        except Exception:
            return cur
    return cur


def maybe_expand(urls: list[str], enabled: bool) -> tuple[list[str], dict[str, str]]:
    """Genişletme kapalıysa aynen döndür. Dönüş: (url-listesi, {kısa: gerçek})."""
    if not enabled:
        return urls, {}
    from app.services.ai_analyzer import SHORTENERS

    out: list[str] = []
    mapping: dict[str, str] = {}
    for u in urls:
        ul = u.lower()
        if any(s in ul for s in SHORTENERS):
            try:
                real = expand_url(u)
            except Exception:
                real = u
            mapping[u] = real
            if real not in out:
                out.append(real)
        if u not in out:
            out.append(u)
    return out[:100], mapping
