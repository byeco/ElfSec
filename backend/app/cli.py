"""ElfSec TOOL — yazılımcı / güvenlikçi odaklı e-posta analiz aracı.

Pipeline (CLI, API, SDK aynı çekirdek):
    OKU (IMAP / dosya / stdin / argüman) -> TEMİZLE (Bleach+bs4/lxml)
    -> ANALİZ ET (yerel motor, anahtarsız) -> RAPORLA (insan / JSON)

Exit-code sözleşmesi (CI ve otomasyon için):
    0 = temiz / başarılı (risk eşiğin altında)
    1 = şüpheli (risk --fail-on eşiğine ulaştı)
    2 = kullanım / ortam hatası (IMAP yok, dosya yok, bağlantı hatası)

Örnekler:
    cat supheli.eml | python -m app.cli analyze --stdin --json
    python -m app.cli triage --limit 50 --fail-on HIGH --out rapor.jsonl
    python -m app.cli analyze-file --path "ornekler/*.html" --fail-on MEDIUM
    python -m app.cli guard --unseen --interval 10   # PC açıkken sürekli koruma
"""

import argparse
import asyncio
import glob
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
LEVEL_ICON = {"LOW": "[+]", "MEDIUM": "[!]", "HIGH": "[!!]", "CRITICAL": "[XXX]"}


# ---------- yardımcılar ----------

def emit(data, args: argparse.Namespace) -> None:
    """JSON veya metin çıktıyı stdout'a (ve --out dosyasına) yazar."""
    text = json.dumps(data, indent=2, ensure_ascii=False, default=str) if isinstance(data, (dict, list)) else str(data)
    if getattr(args, "json", False) or isinstance(data, (dict, list)):
        print(text)
    else:
        print(text)
    out = getattr(args, "out", "")
    if out:
        Path(out).write_text(text + "\n", encoding="utf-8")


def fail_on_exceeded(level: str, fail_on: str) -> bool:
    return LEVEL_ORDER.get(level, 0) >= LEVEL_ORDER.get(fail_on.upper(), 99)


def _print_report(result: dict, tracking: int, quiet: bool = False) -> None:
    if quiet:
        return
    icon = LEVEL_ICON.get(result.get("risk_level", ""), "[?]")
    print(f"{icon} RISK {result.get('risk_score')}/100 [{result.get('risk_level')}] (motor: {result.get('engine')})")
    print(f"Özet: {result.get('summary')}")
    for r in result.get("reasons", []):
        print(f"  - {r}")
    for u in result.get("suspicious_urls", []):
        print(f"  ! {u}")
    print(f"Phishing: {result.get('phishing_detected')} | Prompt-injection: {result.get('prompt_injection_detected')} | "
          f"takip-piksel: {tracking}")
    print(f"Öneri: {result.get('recommended_action')}")


def _analyze_one(subject: str, body: str, sender: str) -> dict:
    from app.services.ai_analyzer import analyze_threat
    from app.services.sanitizer import sanitize_email

    clean = sanitize_email(body)
    result = asyncio.run(analyze_threat(subject, clean["plain_text"], clean["urls"], sender))
    return {**result, "subject": subject, "sender": sender,
            "tracking_pixels_blocked": clean["tracking_pixels_blocked"],
            "plain_text": clean["plain_text"][:2000]}


# ---------- komutlar ----------

def cmd_health(args: argparse.Namespace) -> int:
    from app.settings_store import current_settings, find_config_file, get_explicit

    s = current_settings()
    data = {"env": s.env, "imap_ready": s.imap_configured, "engine": "elfsec-local/1.0",
            "api": f"{s.api_host}:{s.api_port}",
            "config_file": str(find_config_file(get_explicit()) or "(yok — varsayılanlar)")}
    if args.json:
        emit(data, args)
    else:
        print(f"ENV={data['env']} | IMAP={'HAZIR' if data['imap_ready'] else 'EKSIK'} | "
              f"MOTOR={data['engine']} | API={data['api']}")
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    from app.services.imap_client import FetchParams, fetch_emails
    from app.services.sanitizer import sanitize_email
    from app.settings_store import current_settings

    s = current_settings()
    if not s.imap_configured:
        print("HATA: IMAP yok. backend/.env -> IMAP_USER/IMAP_PASSWORD", file=sys.stderr)
        return 2
    params = FetchParams(host=s.imap_host, user=s.imap_user, password=s.imap_password,
                         port=s.imap_port, folder=args.folder, limit=args.limit, unseen_only=args.unseen)
    try:
        mails = asyncio.run(fetch_emails(params))
    except Exception as e:
        print(f"HATA: IMAP: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    rows = []
    for m in mails:
        clean = sanitize_email(m["body"])
        rows.append({**m, "snippet": clean["plain_text"][:200],
                     "urls": clean["urls"], "tracking_pixels_blocked": clean["tracking_pixels_blocked"]})
    if args.json or args.out:
        emit(rows, args)
    else:
        for i, r in enumerate(rows, 1):
            print(f"{i}. [{r['uid']}] {r['date']} | {r['from']} | {r['subject']}")
            print(f"   {r['snippet'][:120].replace(chr(10), ' ')} | url={len(r['urls'])} track={r['tracking_pixels_blocked']}")
    return 0


def _resolve_bodies(args: argparse.Namespace) -> tuple[str, str, str]:
    """(subject, body, sender) çözümle: stdin > body-file > body."""
    subject, sender = args.subject or "", args.sender or ""
    if getattr(args, "stdin", False):
        body = sys.stdin.read()
    elif getattr(args, "body_file", ""):
        body = Path(args.body_file).read_text(encoding="utf-8", errors="replace")
    else:
        body = args.body or ""
    return subject, body, sender


def cmd_analyze(args: argparse.Namespace) -> int:
    subject, body, sender = _resolve_bodies(args)
    if not body.strip():
        print("HATA: gövde boş. --body, --body-file veya --stdin ile veri verin.", file=sys.stderr)
        return 2
    report = _analyze_one(subject, body, sender)
    if args.json or args.out:
        emit(report, args)
    else:
        _print_report(report, report["tracking_pixels_blocked"], quiet=args.quiet)
    return 1 if fail_on_exceeded(report["risk_level"], args.fail_on) else 0


def cmd_analyze_file(args: argparse.Namespace) -> int:
    paths: list[str] = []
    for pat in args.path if isinstance(args.path, list) else [args.path]:
        paths += glob.glob(pat) or [pat]
    reports = []
    worst = "LOW"
    for p in paths:
        fp = Path(p)
        if not fp.exists():
            print(f"HATA: dosya yok: {p}", file=sys.stderr)
            return 2
        report = _analyze_one(args.subject or fp.name, fp.read_text(encoding="utf-8", errors="replace"), args.sender or "")
        report["file"] = str(fp)
        reports.append(report)
        if LEVEL_ORDER.get(report["risk_level"], 0) > LEVEL_ORDER.get(worst, 0):
            worst = report["risk_level"]
        if not (args.json or args.out) and not args.quiet:
            print(f"--- {fp} ---")
            _print_report(report, report["tracking_pixels_blocked"])
    if args.json or args.out:
        emit(reports if len(reports) != 1 or args.json_list else reports[0], args)
    return 1 if fail_on_exceeded(worst, args.fail_on) else 0


def cmd_triage(args: argparse.Namespace) -> int:
    """Güvenlikçi iş akışı: son N maili çek, hepsini analiz et, riske göre sırala.

    Çıktı en riskli en üstte. --out ile JSONL/SIEM'e gömülebilir.
    """
    from app.services.imap_client import FetchParams, fetch_emails
    from app.settings_store import current_settings

    s = current_settings()
    if not s.imap_configured:
        print("HATA: IMAP yok. `elfsec config init` ile kurun.", file=sys.stderr)
        return 2
    params = FetchParams(host=s.imap_host, user=s.imap_user, password=s.imap_password,
                         port=s.imap_port, folder=args.folder, limit=args.limit, unseen_only=args.unseen)
    try:
        mails = asyncio.run(fetch_emails(params))
    except Exception as e:
        print(f"HATA: IMAP: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    reports = [_analyze_one(m.get("subject", ""), m.get("body", ""), m.get("from", "")) | {"uid": m.get("uid", "")}
               for m in mails]
    if args.min_score:
        reports = [r for r in reports if r["risk_score"] >= args.min_score]
    reports.sort(key=lambda r: (r["risk_score"], LEVEL_ORDER.get(r["risk_level"], 0)), reverse=True)
    reports = reports[:args.top] if args.top else reports
    if args.json or args.out:
        if args.out and args.out.endswith(".jsonl"):
            Path(args.out).write_text("\n".join(json.dumps(r, ensure_ascii=False, default=str) for r in reports) + "\n",
                                       encoding="utf-8")
            print(f"{len(reports)} rapor -> {args.out}")
        else:
            emit(reports, args)
    else:
        for r in reports:
            icon = LEVEL_ICON.get(r["risk_level"], "[?]")
            print(f"{icon} {r['risk_score']:3d} [{r['risk_level']:8s}] uid={r.get('uid')} {r.get('subject','')[:70]}")
    worst = max([r["risk_level"] for r in reports], default="LOW", key=lambda l: LEVEL_ORDER.get(l, 0))
    return 1 if reports and fail_on_exceeded(worst, args.fail_on) else 0


def cmd_serve(args: argparse.Namespace) -> int:
    import os
    import uvicorn

    from app.settings_store import current_settings, get_explicit

    s = current_settings()
    if (cfg := get_explicit()):  # --reload alt süreci aynı dosyayı bulsun diye
        os.environ["ELFSEC_CONFIG"] = cfg
    print(f"ElfSec API: http://{s.api_host}:{args.port or s.api_port} (docs: /docs)")
    uvicorn.run("app.main:app", host=s.api_host, port=args.port or s.api_port, reload=args.reload)
    return 0


# ---------- guard (PC açıkken sürekli koruma) ----------

def should_alert(report: dict, alert_on: str) -> bool:
    """Bu rapor alarm üretmeli mi? (saf fonksiyon — test edilebilir)."""
    return LEVEL_ORDER.get(report.get("risk_level", "LOW"), 0) >= LEVEL_ORDER.get(alert_on.upper(), 99)


def _load_seen(state_file: str) -> set:
    try:
        return set(json.loads(Path(state_file).read_text(encoding="utf-8"))) if state_file and Path(state_file).exists() else set()
    except Exception:
        return set()


def _save_seen(state_file: str, seen: set) -> None:
    if not state_file:
        return
    try:
        Path(state_file).write_text(json.dumps(sorted(seen)[-5000:], ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        print(f"UYARI: state yazılamadı: {e}", file=sys.stderr)


def _notify_webhook(url: str, report: dict) -> None:
    """Opsiyonel alarm kancası (SIEM/Discord/Slack webhook). Standart kütüphane, bağımlılık yok."""
    if not url:
        return
    import urllib.request

    req = urllib.request.Request(url, data=json.dumps(report, ensure_ascii=False, default=str).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def _fetch_and_analyze(folder: str, limit: int, unseen: bool) -> tuple[list[dict], str | None]:
    """Tek tarama turu. Dönüş: (raporlar, hata-mesajı|None)."""
    from app.services.imap_client import FetchParams, fetch_emails
    from app.settings_store import current_settings

    s = current_settings()
    if not s.imap_configured:
        return [], "IMAP yok. `elfsec config init` ile kurun veya config dosyasına IMAP_USER/IMAP_PASSWORD ekleyin."
    params = FetchParams(host=s.imap_host, user=s.imap_user, password=s.imap_password,
                         port=s.imap_port, folder=folder, limit=limit, unseen_only=unseen)
    try:
        mails = asyncio.run(fetch_emails(params))
    except Exception as e:
        return [], f"IMAP: {type(e).__name__}: {e}"
    reports = [_analyze_one(m.get("subject", ""), m.get("body", ""), m.get("from", "")) | {"uid": m.get("uid", "")}
               for m in mails]
    reports.sort(key=lambda r: (r["risk_score"], LEVEL_ORDER.get(r["risk_level"], 0)), reverse=True)
    return reports, None


def _guard_cycle(args: argparse.Namespace, seen: set) -> tuple[int, str, set]:
    """Tek bekçi turu: tara, yenileri alarmla, logla. Dönüş: (alarm-sayısı, en-yüksek-seviye, seen)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    reports, err = _fetch_and_analyze(args.folder, args.limit, args.unseen)
    if err:
        print(f"[{now}] UYARI: {err} — {args.interval} dk sonra tekrar.", file=sys.stderr)
        return 0, "LOW", seen
    fresh = [r for r in reports if r.get("uid") not in seen and should_alert(r, args.alert_on)]
    for r in fresh:
        icon = LEVEL_ICON.get(r["risk_level"], "[?]")
        line = f"[{now}] {icon} ALARM {r['risk_score']}/100 [{r['risk_level']}] uid={r.get('uid')} {r.get('subject','')[:80]}"
        print(line, flush=True)
        if args.alert_log:
            with open(args.alert_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({**r, "alerted_at": now}, ensure_ascii=False, default=str) + "\n")
        if args.webhook:
            try:
                _notify_webhook(args.webhook, {**r, "alerted_at": now})
            except Exception as e:
                print(f"[{now}] UYARI: webhook başarısız: {e}", file=sys.stderr)
        seen.add(str(r.get("uid")))
    if not args.quiet:
        print(f"[{now}] tur tamam: {len(reports)} mail, {len(fresh)} yeni alarm.", flush=True)
    _save_seen(args.state, seen)
    worst = max([r["risk_level"] for r in fresh], default="LOW", key=lambda l: LEVEL_ORDER.get(l, 0))
    return len(fresh), worst, seen


def cmd_guard(args: argparse.Namespace) -> int:
    """PC açıkken sürekli koruma: her --interval dakikada okunmamışları tara, alarm üret.

    --once ile tek tur atıp çıkar (Zamanlanmış Görev ile periyodik çalıştırma için).
    """
    import time

    seen = _load_seen(args.state)
    print(f"ElfSec guard başladı: klasör={args.folder} aralık={args.interval}dk alarm>={args.alert_on} "
          f"(durdurmak için Ctrl+C)", flush=True)
    try:
        alarms, worst, seen = _guard_cycle(args, seen)
        if args.once:
            return 1 if alarms and fail_on_exceeded(worst, args.fail_on) else 0
        while True:
            time.sleep(args.interval * 60)
            _guard_cycle(args, seen)
    except KeyboardInterrupt:
        print("\nGuard durduruldu.", flush=True)
        return 0


# ---------- parser ----------

def _add_common(p: argparse.ArgumentParser, with_fail: bool = False) -> None:
    p.add_argument("--json", action="store_true", help="Makine-dostu JSON çıktı (pipe/SIEM için)")
    p.add_argument("--out", default="", help="Çıktıyı dosyaya yaz (.jsonl triage'da satır-satır)")
    p.add_argument("--quiet", action="store_true", help="Sadece özet/JSON bas")
    if with_fail:
        p.add_argument("--fail-on", default="CRITICAL",
                       choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "NEVER"],
                       help="Bu seviye ve üstünde exit-code 1 (CI kapısı). Varsayılan: CRITICAL")


def cmd_config(args: argparse.Namespace) -> int:
    """Ayar yönetimi: init (sihirbaz) / show / set / get / path / test."""
    import getpass

    from app import secret_vault
    from app.settings_store import (FIELD_BY_KEY, SECRET_KEYS, ConfigError, build_settings,
                                    default_user_config_path, find_config_file, get_explicit,
                                    mask, upsert_kv)

    action = args.config_action

    if action == "path":
        found = find_config_file(get_explicit())
        print(str(found) if found else f"(yok — oluşturulacak: {default_user_config_path()})")
        return 0

    if action == "init":
        target = get_explicit() or str(default_user_config_path())
        print(f"ElfSec kurulum sihirbazı -> {target}")
        host = input("IMAP sunucusu [imap.gmail.com]: ").strip() or "imap.gmail.com"
        user = input("E-posta adresi: ").strip()
        password = getpass.getpass("IMAP şifresi (Gmail'de 'uygulama şifresi'): ").strip()
        p = Path(target)
        if host != "imap.gmail.com":
            upsert_kv(p, "IMAP_HOST", host)
        if user:
            upsert_kv(p, "IMAP_USER", user)
        if password:
            upsert_kv(p, "IMAP_PASSWORD", password, secret=True)
        ok, why = secret_vault.available()
        print(f"Kaydedildi: {p} (şifre kasası: {why})")
        return 0

    if action == "show":
        s, found, _w = build_settings(get_explicit())
        if not found:
            print("(config dosyası yok — varsayılanlar + ortam değişkenleri)")
        data = {}
        for key, field in sorted(FIELD_BY_KEY.items()):
            val = str(getattr(s, field, ""))
            data[key] = "***" if (key in SECRET_KEYS and val and not args.reveal) else val
        if args.json:
            print(json.dumps(data, indent=2, ensure_ascii=False))
        else:
            for k, v in data.items():
                print(f"{k}={mask(v, secret=(k in SECRET_KEYS and not args.reveal))}")
        return 0

    if action == "set":
        target = Path(get_explicit() or str(default_user_config_path()))
        secret = args.secret or args.key.upper() in SECRET_KEYS
        value = args.value
        if secret and not value:
            import getpass as _gp
            value = _gp.getpass(f"{args.key.upper()} (gizli giriş): ").strip()
        if not value:
            print("HATA: değer boş.", file=sys.stderr)
            return 2
        upsert_kv(target, args.key, value, secret=secret)
        print(f"OK: {args.key.upper()} -> {target}{' (şifreli)' if secret else ''}")
        return 0

    if action == "get":
        s, _found, _w = build_settings(get_explicit())
        key = args.key.upper()
        if key not in FIELD_BY_KEY:
            raise ConfigError([f"Bilinmeyen ayar: {key}"])
        val = str(getattr(s, FIELD_BY_KEY[key], ""))
        print(val if args.reveal or key not in SECRET_KEYS else mask(val, secret=True))
        return 0

    if action == "test":
        s, found, _w = build_settings(get_explicit())
        print(f"Config: {found or '(dosya yok)'}")
        print(f"IMAP: {'HAZIR' if s.imap_configured else 'EKSİK'} | MOTOR: elfsec-local/1.0 (anahtarsız)")
        if s.imap_configured:
            from app.services.imap_client import list_folders
            try:
                folders = asyncio.run(list_folders(s.imap_host, s.imap_user, s.imap_password, s.imap_port))
                print(f"IMAP bağlantısı OK — {len(folders)} klasör: {', '.join(folders[:5])}")
            except Exception as e:
                print(f"IMAP bağlantısı BAŞARISIZ: {type(e).__name__}: {e}", file=sys.stderr)
                return 1
        return 0

    return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="elfsec", description="ElfSec: e-posta güvenlik analiz tool'u (dev/security)")
    p.add_argument("--config", default="", help="Ayar dosyası yolu (varsayılan: %%APPDATA%%/ElfSec/elfsec.env)")
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("health", help="Ortam durumunu göster")
    h.add_argument("--json", action="store_true")
    h.add_argument("--out", default="")
    h.set_defaults(func=cmd_health)

    f = sub.add_parser("fetch", help="IMAP'tan çek (analizsiz hızlı listeleme)")
    f.add_argument("--folder", default="INBOX")
    f.add_argument("--limit", type=int, default=10)
    f.add_argument("--unseen", action="store_true")
    _add_common(f)
    f.set_defaults(func=cmd_fetch)

    a = sub.add_parser("analyze", help="Tek e-postayı analiz et (stdin destekli)")
    a.add_argument("--subject", default="")
    a.add_argument("--sender", default="")
    a.add_argument("--body", default="")
    a.add_argument("--body-file", default="")
    a.add_argument("--stdin", action="store_true", help="Gövdeyi stdin'den oku (pipe)")
    _add_common(a, with_fail=True)
    a.set_defaults(func=cmd_analyze)

    af = sub.add_parser("analyze-file", help="Dosya/glob analizi: --path 'mails/*.eml'")
    af.add_argument("--path", nargs="+", required=True)
    af.add_argument("--subject", default="")
    af.add_argument("--sender", default="")
    af.add_argument("--json-list", action="store_true", help="Tek dosya bile olsa liste bas")
    _add_common(af, with_fail=True)
    af.set_defaults(func=cmd_analyze_file)

    t = sub.add_parser("triage", help="Son N maili çek+analiz et, riske göre sırala")
    t.add_argument("--folder", default="INBOX")
    t.add_argument("--limit", type=int, default=20)
    t.add_argument("--unseen", action="store_true")
    t.add_argument("--top", type=int, default=0, help="En riskli ilk K (0=tümü)")
    t.add_argument("--min-score", type=int, default=0, help="Bu skorun altını ele")
    _add_common(t, with_fail=True)
    t.set_defaults(func=cmd_triage)

    sv = sub.add_parser("serve", help="API sunucusunu başlat")
    sv.add_argument("--port", type=int, default=0)
    sv.add_argument("--reload", action="store_true")
    sv.set_defaults(func=cmd_serve)

    g = sub.add_parser("guard", help="PC açıkken sürekli koruma (periyodik tarama + alarm)")
    g.add_argument("--folder", default="INBOX")
    g.add_argument("--limit", type=int, default=20, help="Tur başına en fazla mail")
    g.add_argument("--unseen", action="store_true", help="Sadece okunmamışları tara (önerilir)")
    g.add_argument("--interval", type=int, default=10, help="Tur aralığı (dakika)")
    g.add_argument("--alert-on", default="HIGH", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="Bu seviye ve üstü alarm üretir. Varsayılan: HIGH")
    g.add_argument("--alert-log", default="guard_alerts.jsonl", help="Alarmların ekleneceği JSONL dosyası")
    g.add_argument("--state", default=".guard_seen.json", help="Alarmı verilen UID'lerin tutulduğu dosya")
    g.add_argument("--webhook", default="", help="Alarm POST edilecek URL (SIEM/Discord/Slack)")
    g.add_argument("--once", action="store_true", help="Tek tur atıp çık (zamanlanmış görev için)")
    g.add_argument("--quiet", action="store_true")
    g.add_argument("--fail-on", default="NEVER", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "NEVER"],
                   help="--once ile: bu seviye ve üstünde exit-code 1")
    g.set_defaults(func=cmd_guard)

    c = sub.add_parser("config", help="Ayar yönetimi (init/show/set/get/path/test)")
    csub = c.add_subparsers(dest="config_action", required=True)
    ci = csub.add_parser("init", help="Etkileşimli kurulum sihirbazı")
    ci.set_defaults(func=cmd_config)
    cs = csub.add_parser("show", help="Etkin ayarları göster (şifreler maskeli)")
    cs.add_argument("--json", action="store_true")
    cs.add_argument("--reveal", action="store_true", help="Şifreleri açık göster (dikkat!)")
    cs.set_defaults(func=cmd_config)
    cg = csub.add_parser("get", help="Tek ayar değerini bas (scriptler için)")
    cg.add_argument("key")
    cg.add_argument("--reveal", action="store_true")
    cg.set_defaults(func=cmd_config)
    ct = csub.add_parser("set", help="Ayar yaz (hassaslar şifreli saklanır)")
    ct.add_argument("key")
    ct.add_argument("value", nargs="?", default="")
    ct.add_argument("--secret", action="store_true", help="Gizli girişle sor + şifreli sakla")
    ct.set_defaults(func=cmd_config)
    cp = csub.add_parser("path", help="Kullanılan config dosyasının yolunu bas")
    cp.set_defaults(func=cmd_config)
    cte = csub.add_parser("test", help="Ayarları + IMAP bağlantısını test et")
    cte.set_defaults(func=cmd_config)
    return p


def main(argv: list[str] | None = None) -> int:
    from app.settings_store import ConfigError, set_explicit

    args = build_parser().parse_args(argv)
    set_explicit(args.config or None)
    if getattr(args, "fail_on", "NEVER") == "NEVER":
        args.fail_on = "NEVER"
    try:
        return int(args.func(args) or 0)
    except ConfigError as e:
        print("CONFIG HATASI:", file=sys.stderr)
        for h in e.hints:
            print(f"  ! {h}", file=sys.stderr)
        if e.source:
            print(f"  (kaynak: {e.source})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
