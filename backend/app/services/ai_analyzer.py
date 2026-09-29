"""Kendi yazdığım tehdit analiz motoru — API anahtarı yok, internet yok.

Başta "acaba bir AI API'sine mi bağlasam" diye düşündüm ama sonra
vazgeçtim: hem API paralı olurdu, hem de milletin e-postası üçüncü
partiye giderdi. Onun yerine kural tabanlı, deterministik bir motor
yazdım — aynı maile her zaman aynı skoru veriyor, testleri de bu
sayede yazabildim.

Neleri yakalamaya çalışıyor: phishing, şüpheli bağlantılar,
prompt injection, gönderici taklidi, aciliyet baskısı, zararlı ek tuzağı.
Kural ağırlıkları rules.json'dan geliyor, yani kodu değiştirmeden
ayar yapılabiliyor (bunu sonradan ekledim, iyi ki eklemişim).
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

# Marka → resmi alan adları (display-name taklit avı için)
BRAND_DOMAINS = {
    "garanti": ("garanti.com.tr", "garantibbva.com.tr"),
    "akbank": ("akbank.com",),
    "ziraat": ("ziraatbank.com.tr",),
    "isbank": ("isbank.com.tr",),
    "işbank": ("isbank.com.tr",),
    "yapıkredi": ("yapikredi.com.tr",),
    "paypal": ("paypal.com",),
    "apple": ("apple.com", "icloud.com"),
    "microsoft": ("microsoft.com", "outlook.com", "live.com", "hotmail.com"),
    "netflix": ("netflix.com",),
    "e-devlet": ("turkiye.gov.tr",),
    "edevlet": ("turkiye.gov.tr",),
    "trendyol": ("trendyol.com",),
    "hepsiburada": ("hepsiburada.com",),
    "ptt": ("ptt.gov.tr", "pttavm.com"),
}


def _root(domain: str) -> str:
    """Kaba kök alan adı (son iki etiket)."""
    parts = (domain or "").lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (domain or "").lower()


# v0.5.0: makro/ofis riskli uzantılar + çift uzantı tuzağı
MACRO_EXT = (".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm")
OFFICE_EXT = (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx") + MACRO_EXT


def _mixed_script(host: str) -> bool:
    """Kiril/Yunan harfi + Latin karışımı mı? (homoglif, punycode ötesi)."""
    import unicodedata

    try:
        scripts = set()
        for ch in host:
            if ch == "." or ch.isdigit() or ch == "-":
                continue
            name = unicodedata.name(ch, "")
            if not name:
                return True  # adsız kontrol karakteri
            if name.startswith("LATIN"):
                scripts.add("latin")
            elif name.startswith("CYRILLIC"):
                scripts.add("cyrillic")
            elif name.startswith("GREEK"):
                scripts.add("greek")
            elif name.startswith("ARMENIAN") or name.startswith("HEBREW") or name.startswith("ARABIC"):
                scripts.add("other")
        return len(scripts) > 1
    except Exception:
        return False


def _W(R: dict | None, rule_id: str, default: int) -> int:
    """v0.6.0 kural ağırlığı: kapalıysa 0, açıksa kullanıcı ağırlığı."""
    if not R:
        return default
    r = R.get(rule_id)
    if not r or not r.get("enabled", True):
        return 0
    try:
        return max(0, min(100, int(r.get("weight", default))))
    except Exception:
        return default


def _attachments_score(attachments: list[dict] | None, R: dict | None = None) -> tuple[int, list[str]]:
    """v0.5.0 ek analizi (yalnızca üstveri — içerik indirilmez, çevrimdışı).

    attachments: [{filename, size, content_type}].
    """
    if not attachments:
        return 0, []
    score = 0
    reasons: list[str] = []
    for a in attachments:
        fn = str(a.get("filename", "") or "").lower()
        size = int(a.get("size", 0) or 0)
        if not fn:
            continue
        parts = fn.split(".")
        # Çift uzantı: fatura.pdf.exe
        if len(parts) >= 3 and f".{parts[-1]}" in RISKY_EXT and f".{parts[-2]}" in (
                ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"):
            if (w := _W(R, "attach_double", 25)):
                score += w
                reasons.append(f"Çift uzantı tuzağı: {a.get('filename')} (maskeli çalıştırılabilir).")
            continue
        if any(fn.endswith(e) for e in RISKY_EXT):
            if (w := _W(R, "attach_risky", 20)):
                score += w
                reasons.append(f"Riskli ek: {a.get('filename')} ({size // 1024} KB).")
        elif any(fn.endswith(e) for e in MACRO_EXT):
            if (w := _W(R, "attach_macro", 15)):
                score += w
                reasons.append(f"Makrolu Office eki: {a.get('filename')} (makro = kod çalıştırır).")
        elif fn.endswith(".zip") or fn.endswith(".rar") or fn.endswith(".7z"):
            if (w := _W(R, "attach_archive", 8)):
                score += w
                reasons.append(f"Arşiv eki: {a.get('filename')} (açmadan taratın).")
    return score, reasons


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _check_url(url: str, R: dict | None = None) -> tuple[int, str | None]:
    """Tek URL'yi puanla. Dönüş: (puan, gerekçe|None)."""

    def _hit(rule_id: str, default: int, reason: str) -> tuple[int, str | None]:
        w = _W(R, rule_id, default)
        return (w, reason) if w else (0, None)

    ul = url.lower()
    host = _host(url)
    if any(s in ul for s in SHORTENERS):
        return _hit("url_shortener", 15, f"Kısaltılmış URL (gerçek adres gizli): {url}")
    if host.startswith("xn--") or ".xn--" in host:
        return _hit("url_punycode", 25, f"Homoglif/IDN sahteciliği (punycode): {url}")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or ""):
        return _hit("url_ip", 25, f"IP adresine giden link (alan adı yok): {url}")
    if host.endswith(SUSPICIOUS_TLD):
        return _hit("url_tld", 20, f"Şüpheli TLD içeren URL: {url}")
    if "@" in ul:
        return _hit("url_at", 15, f"Aldatıcı yapıda URL (@ işareti): {url}")
    if ul.rstrip("/").lower().endswith(RISKY_EXT):
        return _hit("url_risky_ext", 20, f"Çalıştırılabilir/arsiv dosyasına link: {url}")
    if _mixed_script(host):
        return _hit("url_homoglif", 25, f"Karışık alfabe sahteciliği (homoglif): {url}")
    if re.search(r"(login|signin|verify|account|update|secure|banking)", ul):
        return _hit("url_keyword", 8, f"Kimlik-avı anahtar kelimeli URL: {url}")
    return 0, None


def _sender_domain(sender: str) -> str:
    m = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", sender or "")
    return m.group(1).lower() if m else ""


def _headers_score(headers: dict | None, sender: str, R: dict | None = None) -> tuple[int, list[str]]:
    """v0.4.0 başlık doğrulaması: SPF/DKIM/DMARC + Reply-To/Return-Path/Message-ID.

    headers: {reply_to, return_path, auth_results, message_id} (hepsi opsiyonel).
    Eksik başlık ceza almaz (sahte-pozitifi önlemek için) — sadece ÇELİŞKİ puanlanır.
    """
    if not headers:
        return 0, []
    score = 0
    reasons: list[str] = []
    from_dom = _sender_domain(sender)
    from_root = _root(from_dom)

    def _dom(addr: str) -> str:
        m = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", addr or "")
        return m.group(1).lower() if m else ""

    # 1) Authentication-Results: spf/dkim/dmarc fail
    ar = str(headers.get("auth_results", "") or "").lower()
    for mech in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{mech}\s*=\s*fail\b", ar):
            if (w := _W(R, "auth_fail", 20)):
                score += w
                reasons.append(f"Kimlik doğrulama başarısız: {mech.upper()}=fail (sahte gönderici olasılığı).")
        elif re.search(rf"\b{mech}\s*=\s*(softfail|temperror|permerror)\b", ar):
            if (w := _W(R, "auth_weak", 8)):
                score += w
                reasons.append(f"Kimlik doğrulama şüpheli: {mech.upper()} zayıf sonuç.")

    # 2) Reply-To ≠ From (yanıt farklı adrese gider — klasik olta)
    rt = _dom(str(headers.get("reply_to", "") or ""))
    if rt and from_dom and rt != from_dom:
        if (w := _W(R, "reply_to", 20)):
            score += w
            reasons.append(f"Yanıt adresi farklı: From {from_dom} ama Reply-To {rt}.")

    # 3) Return-Path ≠ From (zarf gönderen ile görünen gönderen uyuşmuyor)
    rp = _dom(str(headers.get("return_path", "") or ""))
    if rp and from_dom and _root(rp) != from_root:
        if (w := _W(R, "return_path", 15)):
            score += w
            reasons.append(f"Zarf gönderen uyuşmazlığı: Return-Path {rp}, From {from_dom}.")

    # 4) Message-ID alanı gönderenle alakasız
    mid = str(headers.get("message_id", "") or "")
    mid_dom = _dom(mid)
    if mid_dom and from_dom and _root(mid_dom) != from_root:
        if (w := _W(R, "message_id", 10)):
            score += w
            reasons.append(f"Message-ID alanı yabancı: {mid_dom} (gönderen {from_dom}).")

    # 5) Display-name marka taklidi (freemail dışı alan adları için genelleme)
    disp = f"{sender}".lower()
    if from_dom and from_dom not in FREEMAIL:
        for brand, official in BRAND_DOMAINS.items():
            if brand in disp and from_dom not in official and _root(from_dom) not in [_root(o) for o in official]:
                if (w := _W(R, "brand_display", 20)):
                    score += w
                    reasons.append(f"Marka taklidi: '{brand}' adı + resmi olmayan alan adı ({from_dom}).")
                break
    return score, reasons


def local_analyze(subject: str, plain_text: str, urls: list[str], sender: str = "",
                  headers: dict | None = None, attachments: list[dict] | None = None,
                  rules: dict | None = None) -> dict:
    # v0.6.0: kural ağırlıkları (verilmezse rules.json + varsayılanlar)
    if rules is None:
        try:
            from app.rules import load_rules
            rules = load_rules()
        except Exception:
            rules = {}
    score = 0
    reasons: list[str] = []
    sus_urls: list[str] = []
    blob = f"{subject}\n{plain_text}"
    low = blob.lower()

    for pat in PHISHING_PATTERNS:
        if re.search(pat, low, re.IGNORECASE):
            if (w := _W(rules, "phishing_pattern", 25)):
                score += w
                reasons.append("Oltalama kalıbı: aciliyet + hesap/kapanma/doğrulama baskısı.")
            break

    for pat in PROMPT_INJECTION_PATTERNS:
        if re.search(pat, low, re.IGNORECASE):
            if (w := _W(rules, "prompt_injection", 30)):
                score += w
                reasons.append("Prompt injection: modele/LLM'e gizli talimat enjekte edilmiş.")
            break

    if re.search(URGENCY_PATTERNS[0], low) or re.search(URGENCY_PATTERNS[1], low, re.IGNORECASE):
        if (w := _W(rules, "urgency", 10)):
            score += w
            reasons.append("Aciliyet baskısı ('hemen', 'son gün' dili).")

    for u in urls:
        pts, why = _check_url(u, rules)
        if pts and u not in sus_urls:
            score += pts
            sus_urls.append(u)
            reasons.append(why or "")

    if re.search(CREDENTIAL_WORDS, low) and re.search(ACTION_WORDS, low):
        if (w := _W(rules, "credential_combo", 15)):
            score += w
            reasons.append("Hassas bilgi talebi (şifre/IBAN/OTP) + aksiyon isteği bir arada.")

    # Gönderici taklidi: görünen ad kurumsal, alan adı bedava posta
    domain = _sender_domain(sender)
    if domain in FREEMAIL and any(b in low[:500] or b in sender.lower() for b in BRAND_WORDS):
        if (w := _W(rules, "sender_spoof", 25)):
            score += w
            reasons.append(f"Gönderici taklidi: kurumsal kimlik + bedava posta alan adı ({domain}).")

    # Zararlı ek tuzağı
    if re.search(r"\.(exe|zip|rar|scr|msi|iso|js|vbs)\b", low) and re.search(
            r"(ek|ekte|indir|download|fatura|dekont|belge|invoice)", low):
        if (w := _W(rules, "attachment_trap", 20)):
            score += w
            reasons.append("Şüpheli ek/indirilebilir dosya tuzağı.")

    # v0.4.0: başlık doğrulaması (eksik başlık ceza almaz, çelişki puanlanır)
    try:
        hscore, hreasons = _headers_score(headers, sender, rules)
        score += hscore
        reasons.extend(hreasons)
    except Exception:
        pass

    # v0.5.0: ek analizi (üstveri)
    try:
        ascore, areasons = _attachments_score(attachments, rules)
        score += ascore
        reasons.extend(areasons)
    except Exception:
        pass

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


async def analyze_threat(subject: str, plain_text: str, urls: list[str], sender: str = "",
                         headers: dict | None = None,
                         attachments: list[dict] | None = None,
                         rules: dict | None = None) -> dict:
    """Tek analiz girişi (CLI/SDK/guard aynı fonksiyonu kullanır)."""
    return local_analyze(subject, plain_text, urls, sender, headers, attachments, rules)
