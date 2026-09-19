"""Güvenlik ve Temizlik — sistemin kalbi.

Pipeline: ham HTML -> Bleach (katı süzgeç) -> BeautifulSoup+lxml (saf metin).

Engellenenler:
- <script>, <style>, <iframe>, <object>, <embed>, <form>, <img> (takip pikseli riski)
- on* event handler'lar, javascript:/data: URL'ler
- 1x1 takip pikselleri ve track/open/click içeren URL'ler sayılır ve atılır.
"""

import re
from urllib.parse import urlparse

import bleach
from bs4 import BeautifulSoup

# Bilerek DAR tutulan izin listesi: yapıyı koru, riski at.
ALLOWED_TAGS = ["p", "br", "a", "ul", "ol", "li", "b", "i", "u", "strong", "em",
                "blockquote", "code", "pre", "h1", "h2", "h3", "h4", "hr", "span", "div"]
ALLOWED_ATTRS = {"a": ["href", "title", "rel"]}
ALLOWED_PROTOCOLS = ["http", "https", "mailto"]

TRACKING_HINTS = ("track", "open", "click", "pixel", "beacon", "utm_", "mailtrack", "sendgrid", "mailgun")

URL_RE = re.compile(r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+", re.IGNORECASE)

# Tek e-postada işlenecek en fazla karakter (IMAP yolu sınırsız olabilir)
MAX_INPUT = 500_000


def _is_tracking_url(url: str) -> bool:
    u = url.lower()
    return any(h in u for h in TRACKING_HINTS)


def _count_tracking_pixels(soup: BeautifulSoup) -> int:
    count = 0
    for img in soup.find_all("img"):
        src = str(img.get("src", ""))
        w, h = str(img.get("width", "")), str(img.get("height", ""))
        style = str(img.get("style", "")).replace(" ", "").lower()
        is_1px = (w == "1" and h == "1") or ("1px" in style)
        if is_1px or _is_tracking_url(src):
            count += 1
    # CSS image-set / background ile gizli takip denemeleri
    for tag in soup.find_all(style=True):
        if "image-set" in str(tag.get("style", "")).lower():
            count += 1
            break
    return count


def extract_urls(raw: str, soup_text_source: str = "") -> list[str]:
    found: list[str] = []
    for m in URL_RE.finditer(raw or ""):
        url = m.group(0).rstrip(".,;)]}!")
        if url not in found:
            found.append(url)
    # <a href> içindekileri de yakala
    try:
        soup = BeautifulSoup(raw or "", "lxml")
        for a in soup.find_all("a", href=True):
            href = str(a["href"]).strip()
            if href.startswith(("http://", "https://", "www.")) and href not in found:
                found.append(href)
    except Exception:
        pass
    return found[:100]


def sanitize_email(raw_body: str) -> dict:
    """Ham e-posta gövdesini temizle.

    Returns: {safe_html, plain_text, urls, tracking_pixels_blocked}
    safe_html HER ZAMAN gövde parçasıdır (tam <html> belgesi değil).
    """
    raw = raw_body or ""
    if len(raw) > MAX_INPUT:  # devasa maillerde bellek/CPU sömürüsünü engelle
        raw = raw[:MAX_INPUT]

    # 1) URL'leri TEMİZLEMEDEN ÖNCE topla (AI analizi için lazım)
    urls = extract_urls(raw)

    # 2) Ön ayrıştırma: takip pikseli say, tehlikeli düğümleri düşür
    try:
        pre_soup = BeautifulSoup(raw, "lxml")
    except Exception:
        pre_soup = BeautifulSoup(raw, "html.parser")
    tracking = _count_tracking_pixels(pre_soup)
    for tag in pre_soup(["script", "style", "iframe", "object", "embed", "form", "img", "picture", "video", "audio", "link", "meta", "noscript"]):
        tag.decompose()
    # image-set içeren style'ları kırp
    for tag in pre_soup.find_all(style=True):
        if "image-set" in str(tag.get("style", "")).lower():
            del tag["style"]
    pre_cleaned = str(pre_soup)

    # 3) Bleach katı temizlik
    safe_html = bleach.clean(
        pre_cleaned,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
        strip_comments=True,
    )
    # linkleri güvenli hale getir
    try:
        link_soup = BeautifulSoup(safe_html, "lxml")
        for a in link_soup.find_all("a", href=True):
            href = str(a["href"])
            if href.lower().startswith(("javascript:", "data:", "vbscript:")):
                del a["href"]
                continue
            if _is_tracking_url(href):
                # şüpheli takip linkini metin olarak bırak, tıklanamaz yap
                a.name = "span"
                del a["href"]
                continue
            a["rel"] = "noopener noreferrer nofollow"
            a["target"] = "_blank"
        # Tam belge değil gövde parçası döndür (embed eden taraf şaşırmasın)
        body = link_soup.body
        safe_html = "".join(str(c) for c in body.contents) if body is not None else str(link_soup)
    except Exception:
        pass  # Bleach çıktısı zaten güvenli taban; link sertleştirme atlanır

    # 4) Saf düz metin
    try:
        text_soup = BeautifulSoup(safe_html, "lxml")
    except Exception:
        text_soup = BeautifulSoup(safe_html, "html.parser")
    for tag in text_soup(["script", "style"]):
        tag.decompose()
    plain = text_soup.get_text(separator="\n")
    plain = re.sub(r"[ \t]+", " ", plain)
    plain = re.sub(r"\n{3,}", "\n\n", plain).strip()

    # 5) Temizlik sonrası URL listesinden takip linklerini işaretle (analiz için tutulur)
    return {
        "safe_html": safe_html,
        "plain_text": plain,
        "urls": urls,
        "tracking_pixels_blocked": tracking,
    }
