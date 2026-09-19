"""Yerel tehdit analizi — API anahtarı yok, internet yok, %100 deterministik.

ElfSec bilinçli olarak harici LLM kullanmaz: e-posta içeriği üçüncü partiye
gitmez, sonuçlar tekrarlanabilir, tool çevrimdışı çalışır.

Tespit hedefleri: phishing, şüpheli bağlantılar, prompt injection,
gönderici taklidi, aciliyet baskısı, zararlı ek tuzağı.
"""

import re
from datetime import datetime, timezone
from urllib.parse import urlparse

ENGINE = "elfsec-local/1.0"

PROMPT_INJECTION_PATTERNS = [
    r"ignore (all |prior |previous )?instructions",
    r"disregard .*instructions",
    r"system prompt",
    r"you are now",
    r"act as .*assistant",
    r"reveal .*prompt",
    r"önceki talimatları (yoksay|unut)",
    r"talimatları görmezden gel",
    r"sistem prompt",
]
PHISHING_PATTERNS = [
    r"acil.*(hesabınız|hesabiniz|kapanacak|doğrula|dogrula)",
    r"(hesabınız|hesabiniz|şifreniz|sifreniz).*(askıya|askiya|kilitlendi|kapanacak|donduruldu)",
    r"hemen (tıkla|tikla|doğrula|dogrula|giriş yap|giris yap)",
    r"son (gün|gun|uyarı|uyari|şans|sans)",
    r"verify your account",
    r"urgent.*(suspend|verify|click|action required)",
    r"password.*expir",
    r"(şifreniz|sifreniz).*(süresi| suresi).*(dol|bit)",
    r"banka.*güvenlik.*güncelle",
    r"hediye.*kazandınız",
    r"fatura.*ödenmedi",
    r"kargonuz.*(teslim edilemedi|bekliyor|ücret)",
    r"e-devlet.*(ceza|borç|borc|doğrulama)",
]
URGENCY_PATTERNS = [
    r"\b(acil|hemen|derhal|son gün|24 saat|48 saat|hemen şimdi)\b",
    r"\b(urgent|immediately|act now|last chance|expires today)\b",
]
CREDENTIAL_WORDS = r"(şifre|sifre|password|iban|kart (numara|bilgi)|otp|sms kodu|doğrulama kodu|dogrulama kodu|t\.?c\.? (kimlik|no)|cvv)"
ACTION_WORDS = r"(gönder|gonder|paylaş|paylas|ilet|gir|tıkla|tikla|onayla|güncelle|guncelle)"

SUSPICIOUS_TLD = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".sbs", ".quest")
SHORTENERS = ("bit.ly", "tinyurl", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly", "shorturl")
FREEMAIL = ("gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "yandex.com", "proton.me",
            "protonmail.com", "icloud.com", "live.com", "gmx.com")
BRAND_WORDS = ("banka", "bank", "garanti", "akbank", "ziraat", "işbank", "yapıkredi", "paypal",
               "apple", "microsoft", "netflix", "vodafone", "turkcell", "türk telekom", "e-devlet",
               "edevlet", "ptt", "kargo", "trendyol", "hepsiburada", "n11", "amazon", "whatsapp",
               "instagram", "facebook", "teknosa", "vatan")
RISKY_EXT = (".exe", ".zip", ".rar", ".scr", ".js", ".vbs", ".bat", ".ps1", ".msi", ".jar", ".iso")


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _check_url(url: str) -> tuple[int, str | None]:
    """Tek URL'yi puanla. Dönüş: (puan, gerekçe|None)."""
    ul = url.lower()
    host = _host(url)
    if any(s in ul for s in SHORTENERS):
        return 15, f"Kısaltılmış URL (gerçek adres gizli): {url}"
    if host.startswith("xn--") or ".xn--" in host:
        return 25, f"Homoglif/IDN sahteciliği (punycode): {url}"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or ""):
        return 25, f"IP adresine giden link (alan adı yok): {url}"
    if host.endswith(SUSPICIOUS_TLD):
        return 20, f"Şüpheli TLD içeren URL: {url}"
    if "@" in ul:
        return 15, f"Aldatıcı yapıda URL (@ işareti): {url}"
    if ul.rstrip("/").lower().endswith(RISKY_EXT):
        return 20, f"Çalıştırılabilir/arsiv dosyasına link: {url}"
    return 0, None


def _sender_domain(sender: str) -> str:
    m = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", sender or "")
    return m.group(1).lower() if m else ""


def local_analyze(subject: str, plain_text: str, urls: list[str], sender: str = "") -> dict:
    score = 0
    reasons: list[str] = []
    sus_urls: list[str] = []
    blob = f"{subject}\n{plain_text}"
    low = blob.lower()

    for pat in PHISHING_PATTERNS:
        if re.search(pat, low, re.IGNORECASE):
            score += 25
            reasons.append("Oltalama kalıbı: aciliyet + hesap/kapanma/doğrulama baskısı.")
            break

    for pat in PROMPT_INJECTION_PATTERNS:
        if re.search(pat, low, re.IGNORECASE):
            score += 30
            reasons.append("Prompt injection: modele/LLM'e gizli talimat enjekte edilmiş.")
            break

    if re.search(URGENCY_PATTERNS[0], low) or re.search(URGENCY_PATTERNS[1], low, re.IGNORECASE):
        score += 10
        reasons.append("Aciliyet baskısı ('hemen', 'son gün' dili).")

    for u in urls:
        pts, why = _check_url(u)
        if pts and u not in sus_urls:
            score += pts
            sus_urls.append(u)
            reasons.append(why or "")

    if re.search(CREDENTIAL_WORDS, low) and re.search(ACTION_WORDS, low):
        score += 15
        reasons.append("Hassas bilgi talebi (şifre/IBAN/OTP) + aksiyon isteği bir arada.")

    # Gönderici taklidi: görünen ad kurumsal, alan adı bedava posta
    domain = _sender_domain(sender)
    if domain in FREEMAIL and any(b in low[:500] or b in sender.lower() for b in BRAND_WORDS):
        score += 25
        reasons.append(f"Gönderici taklidi: kurumsal kimlik + bedava posta alan adı ({domain}).")

    # Zararlı ek tuzağı
    if re.search(r"\.(exe|zip|rar|scr|msi|iso|js|vbs)\b", low) and re.search(
            r"(ek|ekte|indir|download|fatura|dekont|belge|invoice)", low):
        score += 20
        reasons.append("Şüpheli ek/indirilebilir dosya tuzağı.")

    score = max(0, min(100, score))
    level = "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"
    return {
        "risk_score": score,
        "risk_level": level,
        "summary": f"Yerel analiz: {len(reasons)} bulgu, skor {score}/100." if reasons else "Belirgin tehdit kalıbı bulunamadı.",
        "reasons": reasons or ["Bilinen oltalama / injection kalıbı eşleşmedi."],
        "suspicious_urls": sus_urls,
        "prompt_injection_detected": any("Prompt injection" in r for r in reasons),
        "phishing_detected": any(("Oltalama" in r or "taklidi" in r or "Hassas bilgi" in r) for r in reasons),
        "recommended_action": (
            "Bağlantılara tıklama, eki açma, göndericiyi resmi kanaldan doğrula."
            if score >= 50 else "Şüpheli bir durum yok, normal dikkat yeterli."
        ),
        "engine": ENGINE,
        "analyzed_at": datetime.now(timezone.utc),
    }


async def analyze_threat(subject: str, plain_text: str, urls: list[str], sender: str = "") -> dict:
    """Tek analiz girişi (imza sabit — CLI/API/SDK aynı fonksiyonu kullanır)."""
    return local_analyze(subject, plain_text, urls, sender)
