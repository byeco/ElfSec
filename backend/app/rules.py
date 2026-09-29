"""Motorun kural ağırlıklarını kullanıcının değiştirebilmesi için yazdım.

Ağırlıklar başta kodun içine gömülüydü, sonra "ya biri hassasiyeti
artırmak isterse" diye düşünüp rules.json dosyasına taşıdım.
Dosya: %APPDATA%/ElfSec/rules.json (Win) / ~/.config/elfsec/rules.json.
Dosya yoksa gömülü varsayılanlar kullanılıyor.

CLI: `elfsec rules show|set|reset`.
Format: {"kural_id": {"weight": int, "enabled": bool}} — bilinmeyen id reddedilir.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

APP_NAME = "ElfSec"

DEFAULT_RULES: dict[str, dict] = {
    "phishing_pattern": {"weight": 25, "enabled": True},
    "prompt_injection": {"weight": 30, "enabled": True},
    "urgency": {"weight": 10, "enabled": True},
    "credential_combo": {"weight": 15, "enabled": True},
    "sender_spoof": {"weight": 25, "enabled": True},
    "attachment_trap": {"weight": 20, "enabled": True},
    "url_shortener": {"weight": 15, "enabled": True},
    "url_punycode": {"weight": 25, "enabled": True},
    "url_ip": {"weight": 25, "enabled": True},
    "url_tld": {"weight": 20, "enabled": True},
    "url_at": {"weight": 15, "enabled": True},
    "url_risky_ext": {"weight": 20, "enabled": True},
    "url_homoglif": {"weight": 25, "enabled": True},
    "url_keyword": {"weight": 8, "enabled": True},
    "auth_fail": {"weight": 20, "enabled": True},
    "auth_weak": {"weight": 8, "enabled": True},
    "reply_to": {"weight": 20, "enabled": True},
    "return_path": {"weight": 15, "enabled": True},
    "message_id": {"weight": 10, "enabled": True},
    "brand_display": {"weight": 20, "enabled": True},
    "attach_double": {"weight": 25, "enabled": True},
    "attach_risky": {"weight": 20, "enabled": True},
    "attach_macro": {"weight": 15, "enabled": True},
    "attach_archive": {"weight": 8, "enabled": True},
}

_CACHE: dict = {"mtime": 0.0, "rules": {}}


def rules_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
        return base / APP_NAME / "rules.json"
    return Path.home() / ".config" / "elfsec" / "rules.json"


def load_rules() -> dict:
    """Varsayılan + kullanıcı geçersiz kılmaları (dosya yoksa varsayılan)."""
    merged = {k: dict(v) for k, v in DEFAULT_RULES.items()}
    p = rules_path()
    try:
        if p.exists():
            mtime = p.stat().st_mtime
            if _CACHE["mtime"] == mtime and _CACHE["rules"]:
                return _CACHE["rules"]
            user = json.loads(p.read_text(encoding="utf-8"))
            for k, v in (user or {}).items():
                if k in merged and isinstance(v, dict):
                    if "weight" in v:
                        merged[k]["weight"] = max(0, min(100, int(v["weight"])))
                    if "enabled" in v:
                        merged[k]["enabled"] = bool(v["enabled"])
            _CACHE.update(mtime=mtime, rules=merged)
            return merged
    except Exception:
        pass
    return merged


def weight(rules: dict, rule_id: str, default: int) -> int:
    """Kural kapalıysa 0, açıksa kullanıcı ağırlığı (yoksa kod varsayılanı)."""
    r = rules.get(rule_id)
    if not r or not r.get("enabled", True):
        return 0
    return int(r.get("weight", default))


def save_rules(rules: dict) -> Path:
    p = rules_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rules, indent=2, ensure_ascii=False), encoding="utf-8")
    _CACHE.update(mtime=p.stat().st_mtime, rules=rules)
    return p
