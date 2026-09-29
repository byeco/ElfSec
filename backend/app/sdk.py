"""ElfSec SDK — motoru başka kodun içinden kullanmak isteyenler için.

Hocam "CLI ile SDK aynı kodu kullansın, iki ayrı mantık olmasın" dedi,
o yüzden burası aslında CLI'nın kullandığı fonksiyonların ince bir
sarmalayıcısı. Kullanımı şöyle:

    from app.sdk import scan_text, scan_file
    report = scan_text(subject="...", body="<p>...</p>", sender="a@b.com")
    assert report["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
"""

import asyncio
from pathlib import Path


def scan_text(subject: str = "", body: str = "", sender: str = "",
              headers: dict | None = None, attachments: list[dict] | None = None,
              expand_urls: bool = False) -> dict:
    """Ham gövdeyi temizle + analiz et (senkron kolay arayüz)."""
    from app.services.ai_analyzer import analyze_threat
    from app.services.sanitizer import sanitize_email
    from app.urlintel import maybe_expand

    clean = sanitize_email(body or "")
    urls, _ = maybe_expand(clean["urls"], expand_urls)
    result = asyncio.run(analyze_threat(subject or "", clean["plain_text"], urls,
                                        sender or "", headers, attachments))
    return {**result, "subject": subject, "sender": sender,
            "tracking_pixels_blocked": clean["tracking_pixels_blocked"],
            "plain_text": clean["plain_text"]}


def scan_file(path: str | Path, subject: str = "", sender: str = "",
              headers: dict | None = None, attachments: list[dict] | None = None,
              expand_urls: bool = False) -> dict:
    """Dosyadan oku + analiz et."""
    p = Path(path)
    raw = p.read_text(encoding="utf-8", errors="replace")
    return scan_text(subject or p.name, raw, sender, headers, attachments, expand_urls) | {"file": str(p)}


def sanitize(body: str) -> dict:
    """Sadece temizlik katmanı (AI'sız, hızlı)."""
    from app.services.sanitizer import sanitize_email

    return sanitize_email(body or "")
