"""Windows Pano (Clipboard) Phishing & ClickFix Güvenlik Koruması.

Kullanıcı tarayıcıdan bir "Ben robot değilim / doğrulama için Win+R yapıştır"
(ClickFix) komutu veya kimlik-avı bağlantısı kopyaladığında anında analiz eder
ve tehlike tespitinde uyarı verir.
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from datetime import datetime, timezone

from app.rules import load_rules
from app.services.ai_analyzer import ENGINE, _W, _check_url, local_analyze
from app.services.sanitizer import extract_urls

LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

CLICKFIX_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"powershell(?:\.exe)?\b[^\n]*(?:-enc\b|-encodedcommand\b|-w\s+h(?:idden)?|-ep\s+bypass|\biex\b|downloadstring|invoke-webrequest|\birm\b)",
     "ClickFix / gizli PowerShell komutu panoya kopyalandı"),
    (r"\bmshta(?:\.exe)?\s+(?:https?://|javascript:|vbscript:)",
     "ClickFix / MSHTA uzaktan komut çalıştırma tuzağı"),
    (r"\bcmd(?:\.exe)?\s+/[ck]\s+[^\n]*(?:curl|powershell|mshta|certutil|bitsadmin)",
     "ClickFix / CMD üzerinden uzaktan yük indirme komutu"),
    (r"\bcertutil(?:\.exe)?\b[^\n]*-urlcache[^\n]*https?://",
     "Certutil ile dosya indirme komutu"),
    (r"\b(?:curl|wget)(?:\.exe)?\s+https?://[^\n]*\|\s*(?:sh|bash|powershell|cmd)",
     "İnternetten indirip doğrudan çalıştırma (pipe-to-shell)"),
    (r"^\s*(?:javascript|data:text/html|vbscript):",
     "Zararlı tarayıcı URI şeması (javascript:/data:)"),
)


def analyze_clipboard_text(text: str, rules: dict | None = None) -> dict:
    """Pano metnini ClickFix ve phishing URL açısından çevrimdışı analiz eder."""
    raw = (text or "").strip()
    if not raw:
        return {
            "source": "clipboard",
            "risk_score": 0,
            "risk_level": "LOW",
            "summary": "Pano boş.",
            "reasons": ["İncelenecek metin yok."],
            "suspicious_urls": [],
            "clickfix_detected": False,
            "phishing_detected": False,
            "prompt_injection_detected": False,
            "preview": "",
            "engine": ENGINE,
            "analyzed_at": datetime.now(timezone.utc),
        }

    R = rules if rules is not None else load_rules()
    score = 0
    reasons: list[str] = []
    sus_urls: list[str] = []
    clickfix = False

    for pat, desc in CLICKFIX_PATTERNS:
        if re.search(pat, raw, re.IGNORECASE | re.MULTILINE):
            w = _W(R, "clipboard_clickfix", 40)
            if w:
                score += w
                reasons.append(f"ClickFix / zararlı komut tuzağı: {desc}.")
            clickfix = True
            break

    urls = extract_urls(raw[:10_000])
    for u in urls:
        pts, why = _check_url(u, R)
        if pts and u not in sus_urls:
            score += pts
            sus_urls.append(u)
            if why:
                reasons.append(why)

    # Uzun metinde olta/prompt-injection kalıpları da varsa ekle (URL puanını çift sayma)
    rep = local_analyze("", raw[:4000], [], "", None, None, R)
    if rep["risk_score"] > 0:
        score += rep["risk_score"]
        for r in rep["reasons"]:
            if r != "Bilinen oltalama / injection kalıbı eşleşmedi." and r not in reasons:
                reasons.append(r)

    score = max(0, min(100, score))
    level = "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"
    phishing = bool(rep.get("phishing_detected")) or bool(sus_urls)

    return {
        "source": "clipboard",
        "risk_score": score,
        "risk_level": level,
        "summary": (
            f"Pano güvenlik analizi: {len(reasons)} bulgu, skor {score}/100."
            if reasons else "Panoda tehdit kalıbı tespit edilmedi."
        ),
        "reasons": reasons or ["Bilinen ClickFix veya phishing kalıbı eşleşmedi."],
        "suspicious_urls": sus_urls,
        "clickfix_detected": clickfix,
        "phishing_detected": phishing,
        "prompt_injection_detected": bool(rep.get("prompt_injection_detected")),
        "preview": raw[:120],
        "recommended_action": (
            "Bu komutu Win+R/terminale YAPIŞTIRMAYIN ve şüpheli bağlantıyı açmayın!"
            if score >= 25 else "Güvenli görünüyor."
        ),
        "engine": ENGINE,
        "analyzed_at": datetime.now(timezone.utc),
    }


def get_clipboard_sequence() -> int:
    """Windows pano değişiklik sayaç numarasını döndür (non-Windows: 0)."""
    if os.name != "nt":
        return 0
    try:
        import ctypes

        user32 = ctypes.windll.user32
        user32.GetClipboardSequenceNumber.restype = ctypes.c_uint32
        return int(user32.GetClipboardSequenceNumber())
    except Exception:
        return 0


def read_windows_clipboard() -> str | None:
    """Windows panosundan CF_UNICODETEXT (13) metnini güvenli şekilde okur."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        user32.OpenClipboard.argtypes = [wintypes.HWND]
        user32.OpenClipboard.restype = wintypes.BOOL
        user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
        user32.IsClipboardFormatAvailable.restype = wintypes.BOOL
        user32.GetClipboardData.argtypes = [wintypes.UINT]
        user32.GetClipboardData.restype = wintypes.HANDLE
        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = wintypes.BOOL

        kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalUnlock.restype = wintypes.BOOL

        CF_UNICODETEXT = 13
        if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
            return None
        if not user32.OpenClipboard(None):
            return None
        try:
            handle = user32.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                return None
            ptr = kernel32.GlobalLock(handle)
            if not ptr:
                return None
            try:
                return ctypes.wstring_at(ptr)
            finally:
                kernel32.GlobalUnlock(handle)
        finally:
            user32.CloseClipboard()
    except Exception:
        return None


class ClipboardGuard:
    """Pano değişikliklerini izleyen ve tekrarlayan içerikte tek sefer uyaran sınıf."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._last_seq: int = -1
        self._last_hash: str = ""

    def toggle(self) -> bool:
        self.enabled = not self.enabled
        return self.enabled

    def check_once(self, text_override: str | None = None, force: bool = False) -> dict | None:
        """Yeni pano metni varsa analiz raporu döndür, değişiklik yoksa None."""
        if not self.enabled and not force:
            return None

        if text_override is None:
            seq = get_clipboard_sequence()
            if not force and seq and seq == self._last_seq:
                return None
            text = read_windows_clipboard()
            if seq:
                self._last_seq = seq
        else:
            text = text_override

        if not text or not text.strip():
            return None

        digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        if not force and digest == self._last_hash:
            return None
        self._last_hash = digest
        return analyze_clipboard_text(text)

    def run_loop(
        self,
        stop_event: threading.Event,
        interval_sec: float = 1.5,
        alert_on: str = "MEDIUM",
        on_alert=None,
    ) -> None:
        """Pano korumasını arka planda çalıştır (asla çökmez)."""
        # Açılışta mevcut pano içeriğini referans alıp eski kopya için spam yapma
        try:
            self.check_once()
        except Exception:
            pass
        while not stop_event.is_set():
            try:
                rep = self.check_once()
                if rep and LEVEL_ORDER.get(rep.get("risk_level", "LOW"), 0) >= LEVEL_ORDER.get(alert_on.upper(), 1):
                    if on_alert:
                        on_alert(rep)
            except Exception:
                pass
            time.sleep(max(0.5, float(interval_sec)))
