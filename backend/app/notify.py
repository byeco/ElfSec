"""Windows bildirimleri (toast) — ekstra kütüphane kurmadan yazmaya çalıştım.

Önce plyer varsa onu kullanıyorum, yoksa PowerShell üzerinden
Windows'un kendi bildirim sistemine gidiyorum, o da olmazsa sessizce
konsola yazıp geçiyorum (asla çökmemesi lazım, bildirim yüzünden
program patlarsa çok ayıp olur).

Tehlike ve hata bildirimleri buradan geçiyor.
"""

from __future__ import annotations

import subprocess
import xml.sax.saxutils as _sax


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
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, timeout=15,
        )
        return r.returncode == 0
    except Exception:
        return False


def toast(title: str, message: str, force_console: bool = False,
          actions: list[tuple[str, str]] | None = None) -> bool:
    """Bildirim gönder. Başarılıysa True. Asla exception fırlatmaz."""
    title = title or "ElfSec"
    message = message or ""
    if not actions and _via_plyer(title, message):
        return True
    try:
        import os

        if os.name == "nt" and _via_powershell(title, message, actions):
            return True
    except Exception:
        pass
    if force_console:
        print(f"[BILDIRIM] {title}: {message}", flush=True)
    return False


def notify_alarm(report: dict) -> bool:
    lvl = report.get("risk_level", "?")
    score = report.get("risk_score", "?")
    subj = str(report.get("subject", ""))[:100]
    uid = str(report.get("uid", "") or "")
    actions = [("Karantinaya al", f"elfsec:quarantine?uid={uid}"),
               ("Yoksay", "dismiss")] if uid else None
    return toast(f"ElfSec ALARM [{lvl}] {score}/100", subj or "Şüpheli e-posta yakalandı",
                 force_console=False, actions=actions)


def notify_error(detail: str) -> bool:
    return toast("ElfSec hatası", detail[:300], force_console=True)
