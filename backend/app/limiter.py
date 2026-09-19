"""Paylaşımlı rate-limit instance (slowapi DDoS/Brute-Force kalkanı)."""

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.settings_store import build_settings

_settings, _found, _warnings = build_settings()
for _w in _warnings:
    print(f"UYARI: {_w}")

limiter = Limiter(key_func=get_remote_address, default_limits=[_settings.rate_limit_default])
