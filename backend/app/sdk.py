"""ElfSec SDK — yazılımcılar için import edilebilir çekirdek.

CLI/API ile aynı pipeline, kod içinden tek çağrı:

    from app.sdk import scan_text, scan_file
    report = scan_text(subject="...", body="<p>...</p>", sender="a@b.com")
    assert report["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
"""

import asyncio
from pathlib import Path


def scan_text(subject: str = "", body: str = "", sender: str = "") -> dict:
    """Ham gövdeyi temizle + analiz et (senkron kolay arayüz)."""
    from app.services.ai_analyzer import analyze_threat
    from app.services.sanitizer import sanitize_email

    clean = sanitize_email(body or "")
    result = asyncio.run(analyze_threat(subject or "", clean["plain_text"], clean["urls"], sender or ""))
    return {**result, "subject": subject, "sender": sender,
            "tracking_pixels_blocked": clean["tracking_pixels_blocked"],
            "plain_text": clean["plain_text"]}


def scan_file(path: str | Path, subject: str = "", sender: str = "") -> dict:
    """Dosyadan oku + analiz et."""
    p = Path(path)
    raw = p.read_text(encoding="utf-8", errors="replace")
    return scan_text(subject or p.name, raw, sender) | {"file": str(p)}


def sanitize(body: str) -> dict:
    """Sadece temizlik katmanı (AI'sız, hızlı)."""
    from app.services.sanitizer import sanitize_email

    return sanitize_email(body or "")
