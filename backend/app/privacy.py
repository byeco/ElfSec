"""ElfSec KVKK Gizlilik Ayarları ve Veri Minimizasyonu Yardımcıları.

İlkeler:
- Arka plan pano izleme varsayılan olarak KAPALI (`clipboard_auto_watch = False`);
  kullanıcı açık rızasıyla etkinleştirirse yalnızca ClickFix komutları / URL'ler
  RAM'de denetlenir.
- Günlük dosyalarına (`guard_alerts.jsonl`, `clipboard_alerts.jsonl`) ham e-posta
  gövdesi (`plain_text`), ham pano içeriği (`preview`) ve açık kişisel veriler
  (e-posta, TC Kimlik, IBAN, kredi kartı) yazılmaz.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from app.redact import mask_email, mask_secrets, redact_report
from app.settings_store import default_user_config_path, machine_data_dir

DEFAULT_PRIVACY: dict = {
    "clipboard_auto_watch": False,
    "clipboard_clickfix_only": True,
    "kvkk_mask_logs": True,
    "log_retention_days": 14,
}


def privacy_config_path() -> Path:
    return default_user_config_path().parent / "privacy_settings.json"


def load_privacy_settings(path: Path | None = None) -> dict:
    p = Path(path) if path is not None else privacy_config_path()
    out = dict(DEFAULT_PRIVACY)
    if not p.exists():
        return out
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return out
    if not isinstance(data, dict):
        return out
    for k in ("clipboard_auto_watch", "clipboard_clickfix_only", "kvkk_mask_logs"):
        if k in data:
            out[k] = bool(data[k])
    if "log_retention_days" in data:
        try:
            days = int(data["log_retention_days"])
            out["log_retention_days"] = max(1, min(90, days))
        except Exception:
            pass
    return out


def save_privacy_settings(updates: dict, path: Path | None = None) -> dict:
    p = Path(path) if path is not None else privacy_config_path()
    cur = load_privacy_settings(p)
    if isinstance(updates, dict):
        for k in ("clipboard_auto_watch", "clipboard_clickfix_only", "kvkk_mask_logs"):
            if k in updates:
                cur[k] = bool(updates[k])
        if "log_retention_days" in updates:
            try:
                days = int(updates["log_retention_days"])
                cur["log_retention_days"] = max(1, min(90, days))
            except Exception:
                pass
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(cur, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, p)
    return cur


def sanitize_alert_for_storage(report: dict, mask: bool = True) -> dict:
    """Alarm kaydını diske yazmadan önce KVKK veri minimizasyonu ve maskeleme uygular."""
    r = redact_report(report) if mask else dict(report)
    # Ham e-posta gövdesini diske yazma (veri minimizasyonu)
    r.pop("plain_text", None)

    if mask:
        if r.get("subject"):
            r["subject"] = mask_secrets(mask_email(str(r["subject"])))
        if r.get("source") == "clipboard":
            r["preview"] = "[KVKK: Ham pano içeriği saklanmadı]"
        elif r.get("preview"):
            r["preview"] = mask_secrets(mask_email(str(r["preview"])[:80]))
    else:
        if r.get("source") == "clipboard":
            r["preview"] = "[KVKK: Ham pano içeriği saklanmadı]"
    return r


def clear_alert_logs(extra_paths: list[Path] | None = None) -> int:
    """Yerel alarm günlüklerini KVKK silme talebi kapsamında temizler."""
    targets: list[Path] = [
        machine_data_dir() / "guard_alerts.jsonl",
        Path("guard_alerts.jsonl"),
        default_user_config_path().parent / "guard_alerts.jsonl",
        default_user_config_path().parent / "clipboard_alerts.jsonl",
    ]
    for p in extra_paths or []:
        targets.append(Path(p))

    seen: set[str] = set()
    cleared = 0
    for tp in targets:
        try:
            key = str(tp.resolve())
        except OSError:
            key = str(tp)
        if key in seen:
            continue
        seen.add(key)
        if tp.exists() and tp.is_file():
            try:
                tp.write_text("", encoding="utf-8")
                cleared += 1
            except OSError:
                pass
    return cleared
