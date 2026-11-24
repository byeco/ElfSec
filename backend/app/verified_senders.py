"""Doğrulanmış resmi marka göndericileri ve taklit (impersonation / spoofing) motoru.

Apple, Google, Microsoft, PayPal, Amazon, bankalar ve e-Devlet gibi markaların
resmi gönderici alan adları ve ulaşabileceği bilinen e-posta adreslerini tutar.
Kullanıcı `elfsec verified add ...` ile kendi kurum/markalarını ekleyebilir.

Önemli güvenlik ilkesi:
- Resmi adresten gelen mailde SPF/DKIM/DMARC=fail veya Reply-To uyuşmazlığı varsa
  asla "doğrulanmış" sayılmaz -> `SPOOFED` olarak işaretlenir.
- Resmi adresten gelse bile mailde kötü niyetli URL veya zararlı ek varsa
  güven puanı indirimi uygulanmaz.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

APP_NAME = "ElfSec"

DEFAULT_VERIFIED_SENDERS: dict[str, dict] = {
    "apple": {
        "label": "Apple",
        "aliases": ["apple", "apple id", "icloud", "app store", "itunes"],
        "domains": ["apple.com", "email.apple.com", "id.apple.com", "insideicloud.icloud.com", "icloud.com"],
        "emails": [
            "no_reply@email.apple.com",
            "noreply@email.apple.com",
            "appleid@id.apple.com",
            "do_not_reply@apple.com",
            "noreply@insideicloud.icloud.com",
            "apple_support@apple.com",
        ],
    },
    "google": {
        "label": "Google",
        "aliases": ["google", "gmail", "google play", "youtube"],
        "domains": ["google.com", "accounts.google.com", "youtube.com"],
        "emails": [
            "no-reply@accounts.google.com",
            "security-noreply@google.com",
            "noreply@google.com",
        ],
    },
    "microsoft": {
        "label": "Microsoft",
        "aliases": ["microsoft", "outlook", "office 365", "onedrive", "xbox"],
        "domains": [
            "microsoft.com",
            "accountprotection.microsoft.com",
            "email.microsoft.com",
            "mail.support.microsoft.com",
            "communication.microsoft.com",
        ],
        "emails": [
            "account-security-noreply@accountprotection.microsoft.com",
            "msa@communication.microsoft.com",
            "noreply@microsoft.com",
        ],
    },
    "paypal": {
        "label": "PayPal",
        "aliases": ["paypal"],
        "domains": ["paypal.com", "mail.paypal.com"],
        "emails": ["service@paypal.com", "paypal@mail.paypal.com"],
    },
    "amazon": {
        "label": "Amazon",
        "aliases": ["amazon", "amazon prime"],
        "domains": ["amazon.com", "amazon.com.tr"],
        "emails": ["no-reply@amazon.com", "auto-confirm@amazon.com", "siparis-guncelleme@amazon.com.tr"],
    },
    "netflix": {
        "label": "Netflix",
        "aliases": ["netflix"],
        "domains": ["netflix.com", "mailer.netflix.com", "account.netflix.com"],
        "emails": ["info@account.netflix.com", "info@mailer.netflix.com"],
    },
    "meta": {
        "label": "Meta / Instagram",
        "aliases": ["instagram", "facebook", "whatsapp", "meta"],
        "domains": ["mail.instagram.com", "facebookmail.com", "whatsapp.com", "meta.com"],
        "emails": [
            "security@mail.instagram.com",
            "security@facebookmail.com",
            "no-reply@mail.instagram.com",
        ],
    },
    "github": {
        "label": "GitHub",
        "aliases": ["github"],
        "domains": ["github.com"],
        "emails": ["noreply@github.com"],
    },
    "steam": {
        "label": "Steam",
        "aliases": ["steam", "steampowered"],
        "domains": ["steampowered.com"],
        "emails": ["noreply@steampowered.com"],
    },
    "discord": {
        "label": "Discord",
        "aliases": ["discord"],
        "domains": ["discord.com", "discordapp.com"],
        "emails": ["noreply@discord.com"],
    },
    "edevlet": {
        "label": "e-Devlet",
        "aliases": ["e-devlet", "edevlet", "turkiye.gov"],
        "domains": ["turkiye.gov.tr"],
        "emails": ["bilgilendirme@turkiye.gov.tr", "noreply@turkiye.gov.tr"],
    },
    "garanti": {
        "label": "Garanti BBVA",
        "aliases": ["garanti", "garanti bbva"],
        "domains": ["garanti.com.tr", "garantibbva.com.tr"],
        "emails": ["bilgilendirme@garantibbva.com.tr", "noreply@garantibbva.com.tr"],
    },
    "akbank": {
        "label": "Akbank",
        "aliases": ["akbank"],
        "domains": ["akbank.com"],
        "emails": ["bilgilendirme@akbank.com", "noreply@akbank.com"],
    },
    "ziraat": {
        "label": "Ziraat Bankası",
        "aliases": ["ziraat", "ziraat bank", "ziraat bankası", "ziraat bankasi"],
        "domains": ["ziraatbank.com.tr"],
        "emails": ["bilgilendirme@ziraatbank.com.tr", "noreply@ziraatbank.com.tr"],
    },
    "isbank": {
        "label": "İş Bankası",
        "aliases": ["işbank", "isbank", "iş bankası", "is bankasi"],
        "domains": ["isbank.com.tr"],
        "emails": ["bilgilendirme@isbank.com.tr", "noreply@isbank.com.tr"],
    },
    "yapikredi": {
        "label": "Yapı Kredi",
        "aliases": ["yapıkredi", "yapikredi", "yapı kredi", "yapi kredi"],
        "domains": ["yapikredi.com.tr"],
        "emails": ["bilgilendirme@yapikredi.com.tr", "noreply@yapikredi.com.tr"],
    },
    "ptt": {
        "label": "PTT",
        "aliases": ["ptt", "ptt kargo"],
        "domains": ["ptt.gov.tr", "pttavm.com"],
        "emails": ["bilgi@ptt.gov.tr", "noreply@ptt.gov.tr"],
    },
    "trendyol": {
        "label": "Trendyol",
        "aliases": ["trendyol"],
        "domains": ["trendyol.com", "mail.trendyol.com"],
        "emails": ["no-reply@trendyol.com", "bilgi@mail.trendyol.com"],
    },
    "hepsiburada": {
        "label": "Hepsiburada",
        "aliases": ["hepsiburada"],
        "domains": ["hepsiburada.com"],
        "emails": ["no-reply@hepsiburada.com", "bilgi@hepsiburada.com"],
    },
    "turkcell": {
        "label": "Turkcell",
        "aliases": ["turkcell"],
        "domains": ["turkcell.com.tr"],
        "emails": ["bilgilendirme@turkcell.com.tr"],
    },
    "turktelekom": {
        "label": "Türk Telekom",
        "aliases": ["türk telekom", "turk telekom", "turktelekom"],
        "domains": ["turktelekom.com.tr"],
        "emails": ["bilgilendirme@turktelekom.com.tr"],
    },
    "vodafone": {
        "label": "Vodafone",
        "aliases": ["vodafone"],
        "domains": ["vodafone.com.tr"],
        "emails": ["bilgilendirme@vodafone.com.tr"],
    },
}


def verified_path() -> Path:
    override = os.environ.get("ELFSEC_CONFIG_DIR", "").strip()
    if override:
        return Path(override) / "verified_senders.json"
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
        return base / APP_NAME / "verified_senders.json"
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(xdg) if xdg else (Path.home() / ".config")
    return base / "elfsec" / "verified_senders.json"


def _clone_defaults() -> dict[str, dict]:
    return {
        k: {
            "label": str(v["label"]),
            "aliases": list(v["aliases"]),
            "domains": list(v["domains"]),
            "emails": list(v["emails"]),
        }
        for k, v in DEFAULT_VERIFIED_SENDERS.items()
    }


def load_verified_senders() -> dict[str, dict]:
    """Varsayılan + kullanıcı özel marka kayıtlarını birleştir."""
    merged = _clone_defaults()
    p = verified_path()
    try:
        if p.exists():
            raw = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for k, v in raw.items():
                    bid = str(k).strip().lower()
                    if not bid:
                        continue
                    if v is None:
                        merged.pop(bid, None)
                        continue
                    if not isinstance(v, dict):
                        continue
                    domains = [str(d).strip().lower() for d in v.get("domains", []) if str(d).strip()]
                    emails = [str(e).strip().lower() for e in v.get("emails", []) if str(e).strip()]
                    aliases = [str(a).strip().lower() for a in v.get("aliases", []) if str(a).strip()]
                    if domains or emails:
                        merged[bid] = {
                            "label": str(v.get("label") or bid.title()),
                            "aliases": aliases or [bid],
                            "domains": domains,
                            "emails": emails,
                        }
    except Exception:
        pass
    return merged


def _read_user_overrides() -> dict:
    p = verified_path()
    if not p.exists():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def _write_user_overrides(data: dict) -> Path:
    p = verified_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def add_verified_sender(
    brand_id: str,
    domains: list[str],
    emails: list[str] | None = None,
    label: str = "",
    aliases: list[str] | None = None,
) -> Path:
    bid = re.sub(r"[^a-z0-9_-]", "", (brand_id or "").strip().lower())
    if not bid:
        raise ValueError("Geçersiz marka ID'si (yalnızca a-z, 0-9, -, _).")
    doms = [d.strip().lower().lstrip("@") for d in (domains or []) if d and d.strip()]
    addrs = [e.strip().lower() for e in (emails or []) if e and "@" in e]
    if not doms and not addrs:
        raise ValueError("En az bir --domain veya --email verilmeli.")
    for a in addrs:
        dom = a.split("@", 1)[1]
        if dom and dom not in doms:
            doms.append(dom)
    als = [a.strip().lower() for a in (aliases or []) if a and a.strip()] or [bid]
    overrides = _read_user_overrides()
    overrides[bid] = {
        "label": (label or bid.title()).strip(),
        "aliases": als,
        "domains": doms,
        "emails": addrs,
    }
    return _write_user_overrides(overrides)


def remove_verified_sender(brand_id: str) -> bool:
    bid = (brand_id or "").strip().lower()
    if not bid:
        return False
    overrides = _read_user_overrides()
    if bid in DEFAULT_VERIFIED_SENDERS:
        overrides[bid] = None
        _write_user_overrides(overrides)
        return True
    if bid in overrides:
        overrides.pop(bid, None)
        _write_user_overrides(overrides)
        return True
    return False


def reset_verified_senders() -> Path:
    p = verified_path()
    if p.exists():
        p.unlink()
    return p


def _parse_sender(sender: str) -> tuple[str, str, str]:
    """(display_name, email_addr, domain) ayır."""
    raw = (sender or "").strip()
    m = re.search(r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})", raw)
    email_addr = m.group(1).lower() if m else ""
    domain = email_addr.split("@", 1)[1] if "@" in email_addr else ""
    disp = raw
    if m:
        disp = (raw[:m.start()] + raw[m.end():]).replace("<", " ").replace(">", " ").strip(" \"'")
    return disp.lower(), email_addr, domain


def _domain_matches(domain: str, official_domains: list[str]) -> bool:
    if not domain:
        return False
    d = domain.lower().strip(".")
    for od in official_domains:
        od_l = od.lower().strip(".")
        if d == od_l or d.endswith("." + od_l):
            return True
    return False


def _extract_domain(addr: str) -> str:
    m = re.search(r"@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", addr or "")
    return m.group(1).lower() if m else ""


def _alias_in_text(alias: str, text: str) -> bool:
    if not alias or not text:
        return False
    return bool(re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", text, re.IGNORECASE))


def verify_sender(
    sender: str,
    subject: str = "",
    plain_text: str = "",
    headers: dict | None = None,
    registry: dict | None = None,
) -> dict:
    """Gönderici adresini doğrulanmış marka listesi ve SPF/DKIM/DMARC başlıklarıyla doğrular."""
    reg = registry if registry is not None else load_verified_senders()
    disp, email_addr, domain = _parse_sender(sender)

    hdrs = headers or {}
    ar = str(hdrs.get("auth_results", "") or "").lower()
    auth_fail = any(re.search(rf"\b{m}\s*=\s*fail\b", ar) for m in ("spf", "dkim", "dmarc"))
    auth_pass = (not auth_fail) and any(
        re.search(rf"\b{m}\s*=\s*pass\b", ar) for m in ("spf", "dkim", "dmarc")
    )
    reply_dom = _extract_domain(str(hdrs.get("reply_to", "") or ""))

    # 1) Gönderici resmi doğrulanmış alan adı/adres ile eşleşiyor mu?
    for bid, info in reg.items():
        official_domains = [d.lower() for d in info.get("domains", [])]
        official_emails = [e.lower() for e in info.get("emails", [])]
        exact_addr = bool(email_addr and email_addr in official_emails)
        domain_ok = _domain_matches(domain, official_domains)
        if not (exact_addr or domain_ok):
            continue

        label = str(info.get("label") or bid)
        reply_mismatch = bool(reply_dom and not _domain_matches(reply_dom, official_domains))
        if auth_fail or reply_mismatch:
            why = "SPF/DKIM/DMARC=fail" if auth_fail else f"Reply-To ({reply_dom}) resmi alan adına ait değil"
            return {
                "status": "SPOOFED",
                "brand_id": bid,
                "brand": label,
                "matched_address": email_addr,
                "exact_official_address": exact_addr,
                "official_domains": official_domains,
                "auth_passed": False,
                "detail": (
                    f"Resmi '{label}' adresi taklit edilmiş ({email_addr}): {why}!"
                ),
            }
        if auth_pass:
            addr_tag = f"resmi adres ({email_addr})" if exact_addr else f"resmi alan adı ({domain})"
            return {
                "status": "VERIFIED_STRONG",
                "brand_id": bid,
                "brand": label,
                "matched_address": email_addr,
                "exact_official_address": exact_addr,
                "official_domains": official_domains,
                "auth_passed": True,
                "detail": f"Doğrulanmış '{label}' göndericisi: {addr_tag} + SPF/DKIM/DMARC geçerli.",
            }
        addr_tag = f"resmi adres ({email_addr})" if exact_addr else f"resmi alan adı ({domain})"
        return {
            "status": "VERIFIED_DOMAIN",
            "brand_id": bid,
            "brand": label,
            "matched_address": email_addr,
            "exact_official_address": exact_addr,
            "official_domains": official_domains,
            "auth_passed": False,
            "detail": f"Bilinen '{label}' {addr_tag} eşleşti (başlık doğrulaması sağlanmadı).",
        }

    # 2) Resmi listede değil ama görünen ad, alan adı benzerliği veya konuda marka iddiası var mı?
    if domain:
        subj_low = (subject or "").lower()
        body_head = (plain_text or "")[:300].lower()
        for bid, info in reg.items():
            official_domains = [d.lower() for d in info.get("domains", [])]
            if _domain_matches(domain, official_domains):
                continue
            label = str(info.get("label") or bid)
            aliases = [str(a).lower() for a in info.get("aliases", []) if a]
            claimed = (
                any(_alias_in_text(a, disp) for a in aliases)
                or any(a.replace(" ", "") in domain for a in aliases if len(a.replace(" ", "")) >= 4)
                or any(_alias_in_text(a, subj_low) for a in aliases)
                or (disp and any(_alias_in_text(a, body_head) for a in aliases))
            )
            if claimed:
                return {
                    "status": "IMPERSONATION",
                    "brand_id": bid,
                    "brand": label,
                    "matched_address": email_addr,
                    "exact_official_address": False,
                    "official_domains": official_domains,
                    "auth_passed": False,
                    "detail": (
                        f"Doğrulanmamış marka göndericisi: '{label}' adına geliyor ancak resmi alan adı "
                        f"({', '.join(official_domains[:3])}) değil ({domain})!"
                    ),
                }

    return {
        "status": "UNKNOWN",
        "brand_id": "",
        "brand": "",
        "matched_address": email_addr,
        "exact_official_address": False,
        "official_domains": [],
        "auth_passed": auth_pass,
        "detail": "",
    }
