"""Windows bildirimleri (toast) — ekstra kütüphane kurmadan yazmaya çalıştım.

Önce plyer varsa onu kullanıyorum, yoksa PowerShell üzerinden
Windows'un kendi bildirim sistemine gidiyorum, o da olmazsa sessizce
konsola yazıp geçiyorum (asla çökmemesi lazım, bildirim yüzünden
program patlarsa çok ayıp olur).

Tehlike ve hata bildirimleri buradan geçiyor.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import xml.sax.saxutils as _sax
from pathlib import Path

_LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_BURST_WINDOW_SEC = 60.0
_BURST_MAX_COUNT = 2


def _via_plyer(title: str, message: str) -> bool:
    try:
        from plyer import notification  # type: ignore

        notification.notify(title=title, message=message[:250], app_name="ElfSec", timeout=10)
        return True
    except Exception:
        return False


def _clean(s: str, n: int) -> str:
    return (s or "").replace('"', "").replace("`", "").replace("\n", " ")[:n]


def build_toast_xml(title: str, message: str, actions: list[tuple[str, str]] | None = None) -> str:
    """Butonlu toast XML'i üret (saf fonksiyon — test edilebilir).

    actions: [(etiket, argüman)] — argüman `elfsec:...` protokolü veya
    `dismiss` (sistem kapatma). Örn: [("Karantinaya al", "elfsec:quarantine?uid=123")].
    """
    t = _sax.escape(_clean(title, 120))
    m = _sax.escape(_clean(message, 300))
    xml = (f"<toast><visual><binding template=\"ToastGeneric\">"
           f"<text>{t}</text><text>{m}</text>"
           f"</binding></visual>")
    acts = [(label, arg) for label, arg in (actions or []) if label and arg][:3]
    if acts:
        xml += "<actions>"
        for label, arg in acts:
            lab = _sax.escape(_clean(label, 40))
            argument = _sax.escape(arg[:300])
            if arg == "dismiss":
                xml += (f"<action activationType=\"system\" arguments=\"dismiss\" "
                        f"content=\"{lab}\"/>")
            else:
                xml += (f"<action activationType=\"protocol\" arguments=\"{argument}\" "
                        f"content=\"{lab}\"/>")
        xml += "</actions>"
    return xml + "</toast>"


def _via_powershell(title: str, message: str, actions: list[tuple[str, str]] | None = None) -> bool:
    safe_t = _clean(title, 120)
    safe_m = _clean(message, 300)
    if actions:
        import base64
        import json as _json

        # Butonlar JSON (base64) taşınır; XML, template doc üzerinde CreateElement
        # ile kurulur (WinRT tip yükleme sorunları yaşanmaz).
        btn_b64 = base64.b64encode(_json.dumps(
            [{"c": _clean(a[0], 40), "args": a[1][:300]} for a in actions[:3]],
            ensure_ascii=False).encode("utf-8")).decode()
        ps = (
            "$t=\"%s\";$m=\"%s\";"
            "$btns=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(\"%s\"))|ConvertFrom-Json;"
            "try{"
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]|Out-Null;"
            "$tpl=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(1);"
            "$_tx=@($tpl.GetElementsByTagName('text'));"
            "$_tx[0].AppendChild($tpl.CreateTextNode($t))|Out-Null;"
            "$_tx[1].AppendChild($tpl.CreateTextNode($m))|Out-Null;"
            "$_root=$tpl.SelectSingleNode('/toast');"
            "$_acts=$tpl.CreateElement('actions');"
            "foreach($_b in $btns){"
            "$_a=$tpl.CreateElement('action');"
            "if($_b.args -eq 'dismiss'){$_a.SetAttribute('activationType','system')}"
            "else{$_a.SetAttribute('activationType','protocol')};"
            "$_a.SetAttribute('arguments',$_b.args);"
            "$_a.SetAttribute('content',$_b.c);"
            "$_acts.AppendChild($_a)|Out-Null};"
            "$_root.AppendChild($_acts)|Out-Null;"
            "$toast=[Windows.UI.Notifications.ToastNotification]::new($tpl);"
            "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('ElfSec').Show($toast);exit 0"
            "}catch{exit 1}" % (safe_t, safe_m, btn_b64)
        )
    else:
        ps = (
            "$t=\"%s\";$m=\"%s\";"
            "try{"
            "if(Get-Module -ListAvailable -Name BurntToast){"
            "Import-Module BurntToast;New-BurntToastNotification -Text $t,$m|Out-Null;exit 0}"
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]|Out-Null;"
            "$tpl=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(1);"
            "$_t0=@($tpl.GetElementsByTagName('text'))[0];"
            "$_t0.AppendChild($tpl.CreateTextNode($t))|Out-Null;"
            "$_t1=@($tpl.GetElementsByTagName('text'))[1];"
            "$_t1.AppendChild($tpl.CreateTextNode($m))|Out-Null;"
            "$toast=[Windows.UI.Notifications.ToastNotification]::new($tpl);"
            "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('ElfSec').Show($toast);exit 0"
            "}catch{exit 1}" % (safe_t, safe_m)
        )
    try:
        flags = 0x08000000 if os.name == "nt" else 0
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            timeout=15,
            creationflags=flags,
        )
        return r.returncode == 0
    except Exception:
        return False


def _notify_history_path() -> Path:
    from app.settings_store import default_user_config_path

    return default_user_config_path().parent / "notify_history.json"


def _allow_notification(
    dedup_key: str = "",
    risk_level: str | None = None,
    bypass_throttle: bool = False,
) -> bool:
    """Süreçler arası bildirim tekilleştirme, eşik ve spam hız sınırını uygular."""
    if os.environ.get("ELFSEC_NO_TOAST") == "1":
        return False

    try:
        from app.services.local_ai import load_ai_settings

        cfg = load_ai_settings()
    except Exception:
        cfg = {}

    if risk_level is not None:
        if not cfg.get("notify_on_ai_alert", True):
            return False
        min_lvl = str(cfg.get("notify_min_level", "CRITICAL")).upper()
        if min_lvl == "OFF":
            return False
        if _LEVEL_ORDER.get(str(risk_level).upper(), 0) < _LEVEL_ORDER.get(min_lvl, 3):
            return False

    if bypass_throttle:
        return True

    try:
        cooldown = max(30, min(3600, int(cfg.get("notify_cooldown_sec", 300) or 300)))
    except Exception:
        cooldown = 300

    now = time.time()
    hp = _notify_history_path()
    keys_map: dict[str, float] = {}
    recent_ts: list[float] = []
    if hp.exists():
        try:
            raw = json.loads(hp.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                km = raw.get("keys")
                if isinstance(km, dict):
                    for k, v in km.items():
                        try:
                            ts = float(v)
                            if now - ts < 86400:
                                keys_map[str(k)] = ts
                        except Exception:
                            pass
                rt = raw.get("recent_ts")
                if isinstance(rt, list):
                    recent_ts = [float(t) for t in rt if now - float(t) < _BURST_WINDOW_SEC]
        except Exception:
            pass

    if len(recent_ts) >= _BURST_MAX_COUNT:
        return False

    key_norm = str(dedup_key or "").strip().lower()[:200]
    if key_norm and (now - float(keys_map.get(key_norm, 0.0))) < cooldown:
        return False

    if key_norm:
        keys_map[key_norm] = now
    recent_ts.append(now)

    # En fazla son 200 tekil anahtarı sakla (şişmeyi önle)
    if len(keys_map) > 200:
        sorted_items = sorted(keys_map.items(), key=lambda kv: kv[1], reverse=True)[:200]
        keys_map = dict(sorted_items)

    try:
        hp.parent.mkdir(parents=True, exist_ok=True)
        tmp = hp.with_suffix(".tmp")
        tmp.write_text(json.dumps({"keys": keys_map, "recent_ts": recent_ts[-10:]}), encoding="utf-8")
        os.replace(tmp, hp)
    except OSError:
        pass
    return True


def toast(
    title: str,
    message: str,
    force_console: bool = False,
    actions: list[tuple[str, str]] | None = None,
    dedup_key: str = "",
    risk_level: str | None = None,
    bypass_throttle: bool = False,
) -> bool:
    """Bildirim gönder (anti-spam + tekilleştirmeli). Başarılıysa True. Asla exception fırlatmaz."""
    title = title or "ElfSec"
    message = message or ""
    if not _allow_notification(
        dedup_key=dedup_key or f"toast:{title}:{message[:60]}",
        risk_level=risk_level,
        bypass_throttle=bypass_throttle,
    ):
        return False
    if not actions and _via_plyer(title, message):
        return True
    try:
        if os.name == "nt" and _via_powershell(title, message, actions):
            return True
    except Exception:
        pass
    if force_console:
        print(f"[BILDIRIM] {title}: {message}", flush=True)
    return False


def notify_alarm(report: dict) -> bool:
    lvl = str(report.get("risk_level", "HIGH")).upper()
    score = report.get("risk_score", "?")
    subj = str(report.get("subject", ""))[:100]
    uid = str(report.get("uid", "") or "")
    actions = [("Karantinaya al", f"elfsec:quarantine?uid={uid}"),
               ("Yoksay", "dismiss")] if uid else None
    key = f"mail:{uid or subj.lower()}:{lvl}"
    return toast(
        f"ElfSec ALARM [{lvl}] {score}/100",
        subj or "Şüpheli e-posta yakalandı",
        force_console=False,
        actions=actions,
        dedup_key=key,
        risk_level=lvl,
    )


def notify_file_alarm(report: dict) -> bool:
    import urllib.parse

    lvl = str(report.get("risk_level", "HIGH")).upper()
    score = report.get("risk_score", "?")
    fname = str(report.get("filename") or report.get("subject") or "Dosya")[:80]
    reasons = report.get("reasons") or []
    detail = f"{fname} — {reasons[0]}" if reasons else fname
    fpath = str(report.get("file", "") or "")
    already_q = bool(report.get("quarantined_to") or report.get("auto_protected"))
    actions = None
    if fpath and not already_q:
        encoded = urllib.parse.quote(fpath, safe="")
        actions = [("Karantinaya al", f"elfsec:quarantine-file?path={encoded}"),
                   ("Yoksay", "dismiss")]
    title = f"ElfSec OTO-KARANTİNA [{lvl}] {score}/100" if already_q else f"ElfSec DOSYA ALARMI [{lvl}] {score}/100"
    digest = str(report.get("sha256") or "")[:16]
    key = f"file:{digest or fname.lower()}:{lvl}"
    return toast(
        title,
        detail[:280],
        force_console=False,
        actions=actions,
        dedup_key=key,
        risk_level=lvl,
    )


def notify_clipboard_alarm(report: dict) -> bool:
    lvl = str(report.get("risk_level", "HIGH")).upper()
    score = report.get("risk_score", "?")
    reasons = report.get("reasons") or []
    detail = reasons[0] if reasons else str(report.get("summary", "Şüpheli içerik"))
    key = f"clip:{detail[:60].lower()}:{lvl}"
    return toast(
        f"ElfSec UYARI [{lvl}] {score}/100",
        detail[:280],
        force_console=False,
        actions=[("Yoksay", "dismiss")],
        dedup_key=key,
        risk_level=lvl,
    )


def notify_error(detail: str) -> bool:
    return toast("ElfSec hatası", detail[:300], force_console=True)
