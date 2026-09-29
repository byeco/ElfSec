"""Kişisel veriyi loglara yazmadan önce maskelediğim yer.

E-posta adresleri `a***@d***.com` oluyor, IBAN/TC/kart numaraları
yıldızlanıyor. Konu ve gövdeyi aynen bırakıyorum çünkü tehdit
içeriği analiz için lazım — sadece kimlik bilgisi kalıplarını
gizliyorum. Log dosyası birinin eline geçerse diye önlem.
"""

from __future__ import annotations

import re

_EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-])([A-Za-z0-9._%+-]*?)@([A-Za-z0-9.-]*?)([A-Za-z0-9-])\.([A-Za-z]{2,})")
_IBAN_RE = re.compile(r"\bTR\d{2}[\d\s]{16,30}\b")
_TC_RE = re.compile(r"\b1\d{10}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def mask_email(addr: str) -> str:
    """a***@d***.com — tek harfli/adresiz girdi aynen döner."""

    def _m(m: re.Match) -> str:
        user_head, user_rest, dom_head, dom_tail, tld = m.groups()
        user = user_head + ("***" if user_rest else "")
        dom = (dom_head[0] + "***" + dom_tail) if dom_head else "***"
        return f"{user}@{dom}.{tld}"

    return _EMAIL_RE.sub(_m, addr or "")


def mask_secrets(text: str) -> str:
    """IBAN/TC/kart kalıplarını maskele."""
    t = _IBAN_RE.sub("TR** **** **** **** **** ****", text or "")
    t = _TC_RE.sub("***********", t)

    def _card(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and digits != m.group(0).strip():
            return "****-****-****-" + digits[-4:]
        if 13 <= len(digits) <= 19 and len(m.group(0)) >= 15:
            return "****-****-****-" + digits[-4:]
        return m.group(0)

    return _CARD_RE.sub(_card, t)


def redact_report(report: dict) -> dict:
    """Alarm raporunun kopyasını redakte et (orijinal değişmez)."""
    r = dict(report)
    for k in ("from", "sender", "to", "to_addr"):
        if r.get(k):
            r[k] = mask_email(str(r[k]))
    if r.get("plain_text"):
        r["plain_text"] = mask_secrets(mask_email(str(r["plain_text"])[:2000]))
    if r.get("snippet"):
        r["snippet"] = mask_secrets(mask_email(str(r["snippet"])[:300]))
    return r


def prune_jsonl(path: str, keep_days: int) -> int:
    """JSONL dosyasından eski satırları buda. Dönüş: silinen satır sayısı."""
    from datetime import datetime, timedelta, timezone
    from pathlib import Path

    p = Path(path)
    if not path or not p.exists() or keep_days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)
    kept: list[str] = []
    dropped = 0
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            row = json_loads(line)
            ts = row.get("alerted_at") or row.get("at") or ""
            dt = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            if dt >= cutoff:
                kept.append(line)
            else:
                dropped += 1
        except Exception:
            kept.append(line)  # tarihi okunamayan satır silinmez (veri kaybı yok)
    if dropped:
        p.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    return dropped


def json_loads(line: str) -> dict:
    import json

    v = json.loads(line)
    return v if isinstance(v, dict) else {}
