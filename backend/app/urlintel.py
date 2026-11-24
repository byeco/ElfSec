"""Kısaltılmış linklerin arkasını merak edip yazdığım küçük modül.

Normalde ElfSec çevrimdışı çalışıyor, bu benim için önemli bir ilkeydi.
O yüzden genişletme varsayılan olarak KAPALI — sadece kullanıcı
`--expand-urls` verirse bit.ly gibi linklerin gerçek adresi bulunuyor
ve o puanlanıyor. İnternet yoksa ya da site cevap vermezse sessizce
geçiliyor, offline skor korunuyor.

GÜVENLİK: E-posta içeriği saldırgan kontrollü olduğu için genişletme
sırasında yalnızca herkese açık http(s) hedeflerine gidilir. localhost,
özel ağ (10/8, 172.16/12, 192.168/16), link-local (169.254/16 bulut
metadata dahil), loopback, multicast ve rezerve adresler engellenir.
Yönlendirmeler de tek tek doğrulanır; aksi halde kısa bir link
`http://127.0.0.1:...` adresine yönlendirilerek SSRF yapılabilirdi.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request


def _is_public_ip(raw: str) -> bool:
    """Çözümlenen IP herkese açık mı? (özel/loopback/link-local/rezerve hayır)"""
    try:
        ip = ipaddress.ip_address(str(raw).split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    )


def _is_public_host(host: str, port: int | None = None) -> bool:
    """Alan adını çözümleyip tüm adreslerin herkese açık olduğunu doğrula.

    Çözümleme başarısızsa kapalı davran (fail-closed): genişletme atlanır.
    """
    h = (host or "").strip().strip("[]").lower().rstrip(".")
    if not h:
        return False
    if h in {"localhost", "localhost.localdomain"} or h.endswith((".local", ".internal", ".home.arpa")):
        return False
    try:
        infos = socket.getaddrinfo(h, port, type=socket.SOCK_STREAM)
    except OSError:
        return False
    if not infos:
        return False
    return all(_is_public_ip(info[4][0]) for info in infos)


def _is_safe_public_url(url: str) -> bool:
    """Yalnızca http/https + herkese açık host/port kombinasyonlarına izin ver."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    if parts.username or parts.password:
        return False
    return _is_public_host(parts.hostname, port)


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Yönlendirme zincirindeki her adımı SSRF'e karşı doğrula."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _is_safe_public_url(newurl):
            raise urllib.error.URLError("Engellendi: özel/yerel adrese yönlendirme.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeRedirectHandler)


def expand_url(url: str, timeout: int = 8, max_hops: int = 3) -> str:
    """Kısa URL'yi HEAD istekleriyle genişlet. Dönüş: son URL (ya da giriş)."""
    if not _is_safe_public_url(url):
        return url
    cur = url
    for _ in range(max_hops):
        try:
            req = urllib.request.Request(cur, method="HEAD",
                                         headers={"User-Agent": "ElfSec/1.0"})
            with _OPENER.open(req, timeout=timeout) as resp:
                nxt = resp.geturl()
            if not nxt or nxt == cur or not _is_safe_public_url(nxt):
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
