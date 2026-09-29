"""ElfSec TOOL — benim bitirme projesi niyetine yazdığım e-posta analiz aracım.

Nasıl çalışıyor (kafamdaki sırayla):
    OKU (IMAP / dosya / stdin / argüman) -> TEMİZLE (Bleach+bs4/lxml)
    -> ANALİZ ET (kendi yazdığım yerel motor, API anahtarı yok) -> RAPORLA (insan / JSON)

Başta server'lı yapmıştım, sonra "tek exe olsun, kurması kolay olsun" diye
server'ı komple söküp TOOL-only bıraktım. CLI, SDK ve guard hep aynı
çekirdeği kullanıyor, o yüzden birini düzeltince hepsi düzeliyor.

Çıkış kodları (hocam otomasyon için istedi, ben de standart yaptım):
    0 = temiz / başarılı (risk eşiğin altında)
    1 = şüpheli (risk --fail-on eşiğine ulaştı)
    2 = kullanım / ortam hatası (IMAP yok, dosya yok, bağlantı hatası,
        guard --once tur hatası, config test bağlantı hatası dahil)

Denemek için:
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
    """JSON veya metin çıktıyı stdout'a (ve --out dosyasına) yazar.

    --out yazılamazsa (disk/izin) traceback yerine stderr uyarısı verir;
    exit-code'u çağıran komut belirler.
    """
    text = json.dumps(data, indent=2, ensure_ascii=False, default=str) if isinstance(data, (dict, list)) else str(data)
    if getattr(args, "json", False) or isinstance(data, (dict, list)):
        print(text)
    else:
        print(text)
    out = getattr(args, "out", "")
    if out:
        try:
            Path(out).write_text(text + "\n", encoding="utf-8")
        except Exception as e:
            print(f"UYARI: --out dosyasına yazılamadı ({out}): {e}", file=sys.stderr)


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


def validate_folder(folder: str) -> str:
    """TOOL-only IMAP klasör doğrulaması: uzunluk + `..` yasak.

    İzinli: harf/rakam + boşluk, `[ ] / - _ .` (Gmail etiketleri için).
    Hatalıysa ValueError (çağıran exit-code 2 verir).
    """
    import re

    f = (folder or "").strip()
    if not f or len(f) > 128 or ".." in f or "\x00" in f or "\n" in f or "\r" in f:
        raise ValueError(f"Geçersiz klasör: {folder!r} (max 128, '..' yasak).")
    if not re.fullmatch(r"[A-Za-z0-9 _\-\.\/\[\]]+", f):
        raise ValueError(f"Geçersiz klasör karakteri: {folder!r}.")
    return f


def clamp_limit(v: int, lo: int = 1, hi: int = 100) -> int:
    try:
        n = int(v)
    except Exception:
        raise ValueError(f"Geçersiz limit: {v!r}.")
    if n < lo or n > hi:
        raise ValueError(f"Limit {lo}-{hi} arası olmalı (verilen: {v!r}).")
    return n


def _imap_auth(s) -> tuple[str, str, str]:
    """(password, oauth_token, yöntem) — OAuth ayarlıysa token yeniler, yoksa şifre.

    Dönüş yöntemi: "oauth:provider" | "sifre" | "yok".
    """
    try:
        from app.oauth import resolve_access_token

        provider, token = resolve_access_token(s)
        if token:
            return "", token, f"oauth:{provider}"
    except OSError:
        # Refresh patladıysa üst katman exit-2 + yeniden-login önerisi verir.
        raise
    if s.imap_password:
        return s.imap_password, "", "sifre"
    return "", "", "yok"


def parse_header_args(items: list[str] | None) -> dict:
    """--header 'Reply-To: x@y' girdilerini analizör başlık dict'ine çevirir."""
    hdrs = {"reply_to": "", "return_path": "", "auth_results": "", "message_id": ""}
    for it in items or []:
        if ":" not in it:
            continue
        k, v = it.split(":", 1)
        k = k.strip().lower().replace("_", "-")
        v = v.strip()
        if k in ("reply-to", "reply_to"):
            hdrs["reply_to"] = v[:500]
        elif k == "return-path":
            hdrs["return_path"] = v[:500]
        elif k == "authentication-results":
            hdrs["auth_results"] = v[:2000]
        elif k == "message-id":
            hdrs["message_id"] = v[:500]
    return hdrs


def _analyze_one(subject: str, body: str, sender: str, headers: dict | None = None,
                 attachments: list[dict] | None = None, expand_urls: bool = False) -> dict:
    from app.services.ai_analyzer import analyze_threat
    from app.services.sanitizer import sanitize_email
    from app.urlintel import maybe_expand

    # TOOL iç doğrulama (eski schemas.AnalyzeRequest limitleri, serversiz)
    subject = (subject or "")[:1000]
    sender = (sender or "")[:500]
    body = (body or "")[:30000]
    clean = sanitize_email(body)
    urls, mapping = maybe_expand(clean["urls"], expand_urls)
    result = asyncio.run(analyze_threat(subject, clean["plain_text"], urls, sender,
                                        headers, attachments))
    if mapping:
        result["expanded_urls"] = mapping
    return {**result, "subject": subject, "sender": sender,
            "tracking_pixels_blocked": clean["tracking_pixels_blocked"],
            "plain_text": clean["plain_text"][:2000]}


# ---------- komutlar ----------

def cmd_health(args: argparse.Namespace) -> int:
    from app.settings_store import current_settings, find_config_file, get_explicit

    s = current_settings()
    try:
        _pw, _tok, yontem = _imap_auth(s)
    except OSError:
        yontem = "oauth-bozuk"
    data = {"env": s.env, "imap_ready": s.imap_configured or yontem.startswith("oauth"),
            "imap_auth": yontem, "engine": "elfsec-local/1.0",
            "mode": "tool",
            "config_file": str(find_config_file(get_explicit()) or "(yok — varsayılanlar)")}
    if args.json:
        emit(data, args)
    else:
        from app.table import panel, sev, use_table

        if use_table(args):
            print(panel("ELFSEC DURUM", [
                ("Ortam", data["env"]),
                ("IMAP", f"{sev('HAZIR' if data['imap_ready'] else 'EKSIK')} ({data['imap_auth']})"),
                ("Motor", data["engine"]),
                ("Mod", data["mode"]),
                ("Ayar dosyası", data["config_file"]),
            ]))
        else:
            print(f"ENV={data['env']} | IMAP={'HAZIR' if data['imap_ready'] else 'EKSIK'} "
                  f"({data['imap_auth']}) | MOTOR={data['engine']} | MOD=tool")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Tek ekran: durum paneli + son alarmlar tablosu (cmd karışıklığına son)."""
    from app.settings_store import current_settings, find_config_file, get_explicit
    from app.table import panel, render, sev, use_table

    s = current_settings()
    try:
        _pw, _tok, yontem = _imap_auth(s)
    except OSError:
        yontem = "oauth-bozuk"
    ready = s.imap_configured or yontem.startswith("oauth")
    try:
        limit = max(1, min(50, int(getattr(args, "limit", 10) or 10)))
    except Exception:
        print("HATA: --limit sayı olmalı.", file=sys.stderr)
        return 2
    log_path = getattr(args, "alert_log", "") or "guard_alerts.jsonl"
    alarms: list[dict] = []
    try:
        if Path(log_path).exists():
            lines = Path(log_path).read_text(encoding="utf-8").splitlines()
            for line in lines[-200:]:
                try:
                    row = json.loads(line)
                    if isinstance(row, dict):
                        alarms.append(row)
                except Exception:
                    continue
            alarms = alarms[-limit:]
    except Exception as e:
        print(f"UYARI: alarm günlüğü okunamadı ({log_path}): {e}", file=sys.stderr)
    if getattr(args, "json", False) or getattr(args, "out", ""):
        emit({"health": {"env": s.env, "imap_ready": ready, "imap_auth": yontem,
                         "engine": "elfsec-local/1.0"},
              "alarms": alarms}, args)
        return 0
    if use_table(args):
        print(panel("ELFSEC PANEL", [
            ("Ortam", s.env),
            ("IMAP", f"{sev('HAZIR' if ready else 'EKSIK')} ({yontem})"),
            ("Motor", "elfsec-local/1.0"),
            ("Ayar", str(find_config_file(get_explicit()) or "(yok — varsayılanlar)")),
            ("Alarm günlüğü", f"{log_path} ({len(alarms)} gösteriliyor)"),
        ]))
        if alarms:
            print(render(["Zaman", "Skor", "Seviye", "Konu"],
                         [[str(a.get("alerted_at", a.get("date", "-"))),
                           str(a.get("risk_score", "-")),
                           sev(a.get("risk_level", "-")),
                           str(a.get("subject", "(konu yok)"))]
                          for a in reversed(alarms)],
                         title=f"SON ALARMLAR ({len(alarms)})",
                         aligns=["l", "r", "l", "l"]))
        else:
            print("(henüz alarm yok — `guard --once` ile ilk taramayı yapın)")
        print("Komutlar: tara `triage` · koru `guard` · denetle `kontrol` · kurallar `rules show`")
    else:
        print(f"ENV={s.env} | IMAP={'HAZIR' if ready else 'EKSIK'} ({yontem}) | alarm={len(alarms)}")
        if not alarms:
            print("(henüz alarm yok — `guard --once` ile ilk taramayı yapın)")
        for a in reversed(alarms):
            print(f"  [{a.get('risk_level', '-')}] {a.get('risk_score', '-')}/100 "
                  f"uid={a.get('uid', '-')} {str(a.get('subject', ''))[:70]}")
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    from app.services.imap_client import FetchParams, fetch_emails
    from app.services.sanitizer import sanitize_email
    from app.settings_store import current_settings

    s = current_settings()
    try:
        password, oauth_token, _yontem = _imap_auth(s)
    except OSError as e:
        print(f"HATA: {e}", file=sys.stderr)
        return 2
    if not password and not oauth_token:
        print("HATA: IMAP yok. `elfsec config login --provider outlook|gmail` "
              "ya da IMAP_USER/IMAP_PASSWORD kurun.", file=sys.stderr)
        return 2
    try:
        folder = validate_folder(args.folder)
        limit = clamp_limit(args.limit)
    except ValueError as e:
        print(f"HATA: {e}", file=sys.stderr)
        return 2
    params = FetchParams(host=s.imap_host, user=s.imap_user, password=password,
                         port=s.imap_port, folder=folder, limit=limit, unseen_only=args.unseen,
                         oauth_token=oauth_token)
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
        from app.table import render, use_table

        if use_table(args):
            print(render(["#", "UID", "Tarih", "Gönderici", "Konu", "URL", "Takip"],
                         [[str(i), r["uid"], r["date"], r["from"], r["subject"],
                           str(len(r["urls"])), str(r["tracking_pixels_blocked"])]
                          for i, r in enumerate(rows, 1)],
                         title=f"E-POSTALAR ({len(rows)})", aligns=["r", "l", "l", "l", "l", "r", "r"]))
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
    headers = parse_header_args(getattr(args, "header", None))
    report = _analyze_one(subject, body, sender, headers if any(headers.values()) else None,
                          None, getattr(args, "expand_urls", False))
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
        headers = parse_header_args(getattr(args, "header", None))
        report = _analyze_one(args.subject or fp.name, fp.read_text(encoding="utf-8", errors="replace"), args.sender or "",
                              headers if any(headers.values()) else None,
                              None, getattr(args, "expand_urls", False))
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
    try:
        password, oauth_token, _yontem = _imap_auth(s)
    except OSError as e:
        print(f"HATA: {e}", file=sys.stderr)
        return 2
    if not password and not oauth_token:
        print("HATA: IMAP yok. `elfsec config login --provider outlook|gmail` "
              "ya da `elfsec config init` ile kurun.", file=sys.stderr)
        return 2
    try:
        folder = validate_folder(args.folder)
        limit = clamp_limit(args.limit)
    except ValueError as e:
        print(f"HATA: {e}", file=sys.stderr)
        return 2
    params = FetchParams(host=s.imap_host, user=s.imap_user, password=password,
                         port=s.imap_port, folder=folder, limit=limit, unseen_only=args.unseen,
                         oauth_token=oauth_token)
    try:
        mails = asyncio.run(fetch_emails(params))
    except Exception as e:
        print(f"HATA: IMAP: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    reports = [_analyze_one(m.get("subject", ""), m.get("body", ""), m.get("from", ""),
                               m.get("headers"), m.get("attachments"),
                               getattr(args, "expand_urls", False)) | {"uid": m.get("uid", "")}
               for m in mails]
    if args.min_score:
        reports = [r for r in reports if r["risk_score"] >= args.min_score]
    reports.sort(key=lambda r: (r["risk_score"], LEVEL_ORDER.get(r["risk_level"], 0)), reverse=True)
    reports = reports[:args.top] if args.top else reports
    if getattr(args, "cef", ""):
        try:
            from app.cef import to_cef
            Path(args.cef).write_text("\n".join(to_cef(r) for r in reports) + "\n", encoding="utf-8")
            print(f"{len(reports)} CEF satırı -> {args.cef}")
        except Exception as e:
            print(f"UYARI: CEF yazılamadı: {e}", file=sys.stderr)
    if args.json or args.out:
        if args.out and args.out.endswith(".jsonl"):
            Path(args.out).write_text("\n".join(json.dumps(r, ensure_ascii=False, default=str) for r in reports) + "\n",
                                       encoding="utf-8")
            print(f"{len(reports)} rapor -> {args.out}")
        else:
            emit(reports, args)
    else:
        from app.table import render, sev, use_table

        if use_table(args):
            print(render(["#", "Skor", "Seviye", "UID", "Gönderici", "Konu"],
                         [[str(i), str(r["risk_score"]), sev(r["risk_level"]),
                           str(r.get("uid", "")), str(r.get("from", r.get("sender", ""))),
                           str(r.get("subject", ""))]
                          for i, r in enumerate(reports, 1)],
                         title=f"TRIAGE ({len(reports)} mail, risk sırasına göre)",
                         aligns=["r", "r", "l", "l", "l", "l"]))
        else:
            for r in reports:
                icon = LEVEL_ICON.get(r["risk_level"], "[?]")
                print(f"{icon} {r['risk_score']:3d} [{r['risk_level']:8s}] uid={r.get('uid')} {r.get('subject','')[:70]}")
    worst = max([r["risk_level"] for r in reports], default="LOW", key=lambda l: LEVEL_ORDER.get(l, 0))
    return 1 if reports and fail_on_exceeded(worst, args.fail_on) else 0


# ---------- guard (PC açıkken sürekli koruma) ----------

def should_alert(report: dict, alert_on: str) -> bool:
    """Bu rapor alarm üretmeli mi? (saf fonksiyon — test edilebilir)."""
    return LEVEL_ORDER.get(report.get("risk_level", "LOW"), 0) >= LEVEL_ORDER.get(alert_on.upper(), 99)


def _load_seen(state_file: str) -> set:
    if not state_file or not Path(state_file).exists():
        return set()
    try:
        return set(json.loads(Path(state_file).read_text(encoding="utf-8")))
    except Exception as e:
        # Bozuk state sessizce silinmez: yedeğe alınır, yoksa aynı maillere tekrar alarm yağar.
        try:
            bak = f"{state_file}.bozuk-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
            Path(state_file).rename(bak)
            print(f"UYARI: state dosyası bozuk, yedeğe alındı ({bak}): {e}", file=sys.stderr)
        except Exception as e2:
            print(f"UYARI: bozuk state okunamadı/yedeklenemedi: {e2}", file=sys.stderr)
        return set()


def _log_guard_error(state_file: str, kind: str, detail: object) -> None:
    """Guard hata günlüğü — loop'ta yutulan hata buraya düşer, sessizlik olmaz."""
    try:
        base = Path(state_file).parent if state_file else Path(".")
        log = base / "guard_errors.jsonl"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"at": now, "kind": kind, "detail": str(detail)[:500]},
                                ensure_ascii=False) + "\n")
        try:
            from app.log import close_logger, get_logger
            get_logger("guard", str(base / "elfsec.log")).warning("%s: %s", kind, str(detail)[:300])
            close_logger("guard")  # dosya kilidi kalmasın (temp-dizin temizliği)
        except Exception:
            pass
    except Exception as e:
        print(f"UYARI: hata günlüğü yazılamadı: {e}", file=sys.stderr)


def _safe_notify(kind: str, report_or_msg: dict | str, state_file: str = "") -> bool:
    """Bildirim gönder, başarısızsa yutma: stderr + guard_errors.jsonl. Dönüş: gönderildi-mi."""
    try:
        from app.notify import notify_alarm, notify_error

        if kind == "alarm":
            ok = notify_alarm(report_or_msg)  # type: ignore[arg-type]
        else:
            ok = notify_error(str(report_or_msg))
        if not ok:
            print(f"UYARI: bildirim gönderilemedi ({kind}) — toast altyapısı yok.", file=sys.stderr)
            _log_guard_error(state_file, f"notify-{kind}-failed", report_or_msg)
        return bool(ok)
    except Exception as e:
        print(f"UYARI: bildirim hatası ({kind}): {e}", file=sys.stderr)
        _log_guard_error(state_file, f"notify-{kind}-crash", e)
        return False


def _save_seen(state_file: str, seen: set) -> None:
    if not state_file:
        return
    try:
        Path(state_file).write_text(json.dumps(sorted(seen)[-5000:], ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        print(f"UYARI: state yazılamadı: {e}", file=sys.stderr)


def _parse_extra_headers(items: list[str] | None) -> dict:
    """--webhook-header 'Ad: değer' girdilerini sözlüğe çevirir (auth için)."""
    out: dict[str, str] = {}
    for it in items or []:
        if ":" not in it:
            continue
        k, v = it.split(":", 1)
        k, v = k.strip(), v.strip()
        if k and v:
            out[k] = v
    return out


def _notify_webhook(url: str, report: dict, extra_headers: dict | None = None,
                    retries: int = 3) -> None:
    """Opsiyonel alarm kancası (SIEM/Discord/Slack webhook). Standart kütüphane, bağımlılık yok.

    Başarısızlıkta üstel beklemeli yeniden dener (1s, 2s, 4s); hepsi patlarsa
    son hatayı fırlatır (çağıran loglar, tur ölmez).
    """
    if not url:
        return
    import time
    import urllib.request

    headers = {"Content-Type": "application/json", **(extra_headers or {})}
    payload = json.dumps(report, ensure_ascii=False, default=str).encode("utf-8")
    last: Exception | None = None
    for attempt in range(max(1, retries)):
        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
            return
        except Exception as e:
            last = e
            time.sleep(2 ** attempt)
    if last:
        raise last


def _fetch_and_analyze(folder: str, limit: int, unseen: bool,
                       expand_urls: bool = False) -> tuple[list[dict], str | None, str, int]:
    """Tek tarama turu.

    Dönüş: (raporlar, hata-mesajı|None, err_kind, atlanan-mail-sayısı).
    err_kind: "" | "config" | "imap" | "transient".
    Tek bozuk mail tüm turu öldürmez — atlanır ve sayılır.
    """
    from app.services.imap_client import FetchParams, fetch_emails
    from app.settings_store import current_settings

    s = current_settings()
    try:
        password, oauth_token, _yontem = _imap_auth(s)
    except OSError as e:
        return [], str(e), "config", 0
    if not password and not oauth_token:
        return [], ("IMAP yok. `elfsec config login --provider outlook|gmail` "
                    "ya da IMAP_USER/IMAP_PASSWORD kurun."), "config", 0
    try:
        folder = validate_folder(folder)
        limit = clamp_limit(limit)
    except ValueError as e:
        return [], str(e), "config", 0
    params = FetchParams(host=s.imap_host, user=s.imap_user, password=password,
                         port=s.imap_port, folder=folder, limit=limit, unseen_only=unseen,
                         oauth_token=oauth_token)
    try:
        mails = asyncio.run(fetch_emails(params))
    except Exception as e:
        name = type(e).__name__
        # Auth/şifre hatası config sınıfıdır (tekrar denemek sonuç vermez, toast spam'i anlamsız).
        kind = "config" if "Auth" in name or "Login" in name or "Credential" in name else "imap"
        return [], f"IMAP: {name}: {e}", kind, 0
    reports: list[dict] = []
    skipped = 0
    for m in mails:
        try:
            reports.append(_analyze_one(m.get("subject", ""), m.get("body", ""), m.get("from", ""),
                                        m.get("headers"), m.get("attachments"), expand_urls)
                           | {"uid": m.get("uid", "")})
        except Exception as e:
            skipped += 1
            print(f"UYARI: bozuk mail atlandı uid={m.get('uid', '?')}: {type(e).__name__}: {e}",
                  file=sys.stderr)
    reports.sort(key=lambda r: (r["risk_score"], LEVEL_ORDER.get(r["risk_level"], 0)), reverse=True)
    return reports, None, "", skipped


def _guard_cycle(args: argparse.Namespace, seen: set) -> tuple[int, str, set, str]:
    """Tek bekçi turu: tara, yenileri alarmla, logla, toast at, gerekirse karantinaya al.

    Dönüş: (alarm-sayısı, en-yüksek-seviye, seen, status).
    status: "ok" | "error-config" | "error-imap". Hata artık (0, "LOW") arkasına
    gizlenmez — çağıran exit-code ve ardışık-hata sayacı için status'e bakar.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    reports, err, err_kind, skipped = _fetch_and_analyze(
        args.folder, args.limit, args.unseen, getattr(args, "expand_urls", False))
    if err:
        print(f"[{now}] HATA ({err_kind}): {err}", file=sys.stderr)
        _log_guard_error(getattr(args, "state", ""), f"cycle-{err_kind}", err)
        if getattr(args, "notify", "on") == "on":
            # Auth/config hatası her turda toast spam'i yapmaz — ilk turda bir kez.
            if err_kind == "config" and len(seen) >= 0 and getattr(args, "_err_notified", False):
                pass
            else:
                _safe_notify("error", f"{err} — {args.interval} dk sonra tekrar denenecek.",
                             getattr(args, "state", ""))
                args._err_notified = True
        return 0, "LOW", seen, f"error-{err_kind}"
    webhooks_failed = 0
    quarantines_failed = 0
    fresh = [r for r in reports if r.get("uid") not in seen and should_alert(r, args.alert_on)]
    notify_on = getattr(args, "notify", "on") == "on"
    action = getattr(args, "action", "notify-only")
    redact_on = bool(getattr(args, "redact", False))
    if redact_on:
        from app.redact import redact_report

        fresh = [redact_report(r) for r in fresh]
        if not args.quiet:
            print(f"[{now}] PII redaksiyonu açık — log/webhook/toast maskeli.", flush=True)
    for r in fresh:
        icon = LEVEL_ICON.get(r["risk_level"], "[?]")
        line = f"[{now}] {icon} ALARM {r['risk_score']}/100 [{r['risk_level']}] uid={r.get('uid')} {r.get('subject','')[:80]}"
        print(line, flush=True)
        if args.alert_log:
            try:
                with open(args.alert_log, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({**r, "alerted_at": now}, ensure_ascii=False, default=str) + "\n")
            except Exception as e:
                print(f"[{now}] UYARI: alarm günlüğü yazılamadı: {e}", file=sys.stderr)
                _log_guard_error(getattr(args, "state", ""), "alert-log", e)
        if getattr(args, "cef_log", ""):
            try:
                from app.cef import to_cef
                with open(args.cef_log, "a", encoding="utf-8") as fh:
                    fh.write(to_cef({**r, "alerted_at": now}) + "\n")
            except Exception as e:
                print(f"[{now}] UYARI: CEF günlüğü yazılamadı: {e}", file=sys.stderr)
                _log_guard_error(getattr(args, "state", ""), "cef-log", e)
        if args.webhook:
            # https-only: http webhooklar PII sızdırır
            if not str(args.webhook).lower().startswith("https://"):
                print(f"[{now}] UYARI: webhook https değil, atlandı (güvenlik).", file=sys.stderr)
            else:
                try:
                    _notify_webhook(args.webhook, {**r, "alerted_at": now},
                                    _parse_extra_headers(getattr(args, "webhook_header", None)))
                except Exception as e:
                    webhooks_failed += 1
                    print(f"[{now}] UYARI: webhook başarısız (3 deneme): {e}", file=sys.stderr)
                    _log_guard_error(getattr(args, "state", ""), "webhook", e)
        if notify_on:
            _safe_notify("alarm", r, getattr(args, "state", ""))
        # Tehlikeyi durdur/yok et — default notify-only (dokunma). quarantine/delete onaylı.
        if action in ("quarantine", "delete") and r.get("uid"):
            try:
                from app.services.imap_client import quarantine_email
                from app.settings_store import current_settings

                s = current_settings()
                try:
                    _pw, _tok, _m = _imap_auth(s)
                except OSError as e:
                    print(f"[{now}] UYARI: karantina atlandı (OAuth): {e}", file=sys.stderr)
                    _log_guard_error(getattr(args, "state", ""), "quarantine-auth", e)
                    seen.add(str(r.get("uid")))
                    continue
                qfolder = getattr(args, "quarantine_folder", "Junk")
                detail = asyncio.run(quarantine_email(
                    s.imap_host, s.imap_user, _pw, s.imap_port,
                    args.folder, str(r.get("uid")), action, qfolder,
                    oauth_token=_tok,
                ))
                qlog = getattr(args, "quarantine_log", "quarantine.jsonl")
                if qlog:
                    with open(qlog, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps({"uid": r.get("uid"), "subject": r.get("subject", "")[:120],
                                             "level": r.get("risk_level"), "action": action,
                                             "detail": detail, "at": now}, ensure_ascii=False, default=str) + "\n")
                print(f"[{now}] AKSIYON: {detail}", flush=True)
            except Exception as e:
                quarantines_failed += 1
                print(f"[{now}] UYARI: karantina başarısız uid={r.get('uid')}: {e}", file=sys.stderr)
                _log_guard_error(getattr(args, "state", ""), "quarantine", e)
                _safe_notify("error", f"Karantina başarısız uid={r.get('uid')}: {e}",
                             getattr(args, "state", ""))
        seen.add(str(r.get("uid")))
    extras = []
    if skipped:
        extras.append(f"{skipped} bozuk mail atlandı")
    if webhooks_failed:
        extras.append(f"{webhooks_failed} webhook hatası")
    if quarantines_failed:
        extras.append(f"{quarantines_failed} karantina hatası")
    if not args.quiet:
        suffix = f" ({', '.join(extras)})" if extras else ""
        print(f"[{now}] tur tamam: {len(reports)} mail, {len(fresh)} yeni alarm{suffix}.", flush=True)
    _save_seen(args.state, seen)
    worst = max([r["risk_level"] for r in fresh], default="LOW", key=lambda l: LEVEL_ORDER.get(l, 0))
    return len(fresh), worst, seen, "ok"


def cmd_guard(args: argparse.Namespace) -> int:
    """PC açıkken sürekli koruma: her --interval dakikada okunmamışları tara, alarm üret.

    --once ile tek tur atıp çıkar. --tray/--background ile konsolu gizle + toast.
    """
    import time

    try:
        _iv = int(getattr(args, "interval", 10))
    except Exception:
        print("HATA: --interval sayı olmalı.", file=sys.stderr)
        return 2
    if _iv < 1:
        print("HATA: --interval en az 1 dakika olmalı.", file=sys.stderr)
        return 2
    try:
        validate_folder(getattr(args, "folder", "INBOX"))
        clamp_limit(getattr(args, "limit", 20))
    except ValueError as e:
        print(f"HATA: {e}", file=sys.stderr)
        return 2

    if getattr(args, "tray", False) or getattr(args, "background", False):
        try:
            from app.tray import hide_console

            hide_console()
        except Exception:
            pass
        # Tray ikonu varsa ayrı thread'de başlat (yoksa sessiz devam)
        try:
            import threading

            from app.tray import run_tray_loop

            threading.Thread(target=run_tray_loop, daemon=True).start()
        except Exception:
            pass

    seen = _load_seen(args.state)
    # Retention: eski log satırlarını buda (PII birikimini sınırla).
    try:
        keep = int(getattr(args, "retention_days", 0) or 0)
    except Exception:
        keep = 0
    if keep > 0:
        from app.redact import prune_jsonl

        for _lf in (args.alert_log, getattr(args, "cef_log", ""),
                    getattr(args, "quarantine_log", "")):
            if _lf:
                try:
                    n = prune_jsonl(_lf, keep)
                    if n:
                        print(f"Eski log budandı: {_lf} ({n} satır, >{keep} gün).", flush=True)
                except Exception as e:
                    print(f"UYARI: retention budama başarısız ({_lf}): {e}", file=sys.stderr)
    print(f"ElfSec guard başladı: klasör={args.folder} aralık={args.interval}dk alarm>={args.alert_on} "
          f"aksiyon={getattr(args, 'action', 'notify-only')} (durdurmak için Ctrl+C)", flush=True)
    consecutive_errors = 0
    try:
        alarms, worst, seen, status = _guard_cycle(args, seen)
        if args.once:
            # Ortam hatası "temiz" gibi raporlanmaz: exit-code 2 (sözleşme).
            if status != "ok":
                return 2
            return 1 if alarms and fail_on_exceeded(worst, args.fail_on) else 0
        if status != "ok":
            consecutive_errors += 1
        while True:
            time.sleep(args.interval * 60)
            try:
                _alarms, _worst, seen, status = _guard_cycle(args, seen)
            except Exception as e:
                status = "error-transient"
                print(f"UYARI: tur hatası: {type(e).__name__}: {e} — devam ediliyor.", file=sys.stderr)
                _log_guard_error(getattr(args, "state", ""), "cycle-crash", e)
                _safe_notify("error", f"Tur hatası: {e}. Koruma devam ediyor.",
                             getattr(args, "state", ""))
            if status != "ok":
                consecutive_errors += 1
                # 3 üst üste hata = kalıcı sorun (örn. yanlış şifre): tek toast + log, spam yok.
                if consecutive_errors == 3:
                    msg = (f"Guard {consecutive_errors} turdur hata veriyor ({status}). "
                           f"IMAP ayarlarını `elfsec config test` ile kontrol edin.")
                    print(f"UYARI: {msg}", file=sys.stderr)
                    _safe_notify("error", msg, getattr(args, "state", ""))
            else:
                consecutive_errors = 0
    except KeyboardInterrupt:
        print("\nGuard durduruldu.", flush=True)
        return 0


def parse_protocol_uri(raw: str) -> tuple[str, dict] | None:
    """Toast butonundan gelen `elfsec:aksiyon?uid=..` URI'sini çöz.

    Dönüş: (aksiyon, {uid}) ya da None (normal CLI argümanı).
    """
    s = (raw or "").strip().strip("\"'")
    if not s.lower().startswith("elfsec:"):
        return None
    import urllib.parse

    try:
        u = urllib.parse.urlparse(s)
        action = (u.path or u.netloc or "").strip("/").lower()
        qs = urllib.parse.parse_qs(u.query)
        uid = (qs.get("uid") or [""])[0]
        if action not in ("quarantine", "delete") or not uid:
            return None
        return action, {"uid": uid}
    except Exception:
        return None


def cmd_serve(args: argparse.Namespace) -> int:
    """Web API'yi başlat: siten bu adresten skor çeker.

    Token bayrağı YOKTUR (process listesinde görünür) — token sadece
    ELFSEC_API_TOKEN ortam değişkeninden okunur. Ağa açık + tokensuz
    başlama reddedilir (serve.py fail-closed).
    """
    from app.serve import run_forever

    try:
        rate = int(getattr(args, "rate_limit", 60))
    except Exception:
        print("HATA: --rate-limit sayı olmalı.", file=sys.stderr)
        return 2
    if rate < 1 or rate > 10000:
        print("HATA: --rate-limit 1-10000 arası olmalı.", file=sys.stderr)
        return 2
    try:
        port = int(getattr(args, "port", 8765))
    except Exception:
        print("HATA: --port sayı olmalı.", file=sys.stderr)
        return 2
    origins = tuple(o.strip() for o in str(getattr(args, "cors_origins", "") or "").split(",") if o.strip())
    for o in origins:
        if not (o.startswith("https://") or o == "http://localhost" or o.startswith("http://localhost:")):
            print(f"HATA: CORS origin https olmalı (verilen: {o}). "
                  "Yerel deneme için http://localhost[:port] kabul edilir.", file=sys.stderr)
            return 2
    return run_forever(str(getattr(args, "host", "127.0.0.1") or "127.0.0.1"),
                       port, rate, origins)


def cmd_quarantine(args: argparse.Namespace) -> int:
    """Tek maili karantinaya al/sil (toast butonu veya elle).

    Kullanım: elfsec quarantine UID [--folder INBOX] [--action quarantine|delete]
    """
    from app.services.imap_client import quarantine_email
    from app.settings_store import current_settings

    uid = str(getattr(args, "uid", "") or "")
    if not uid:
        print("HATA: UID boş. Kullanım: elfsec quarantine UID", file=sys.stderr)
        return 2
    action = getattr(args, "action", "quarantine") or "quarantine"
    if action not in ("quarantine", "delete"):
        print(f"HATA: aksiyon quarantine|delete olmalı (verilen: {action}).", file=sys.stderr)
        return 2
    if action == "delete" and not getattr(args, "yes", False):
        print("HATA: kalıcı silme için --yes gerekli (geri alınamaz).", file=sys.stderr)
        return 2
    s = current_settings()
    try:
        password, oauth_token, _yontem = _imap_auth(s)
    except OSError as e:
        print(f"HATA: {e}", file=sys.stderr)
        return 2
    if not password and not oauth_token:
        print("HATA: IMAP yok. Önce `elfsec config login` ya da IMAP_PASSWORD.", file=sys.stderr)
        return 2
    try:
        folder = validate_folder(getattr(args, "folder", "INBOX"))
    except ValueError as e:
        print(f"HATA: {e}", file=sys.stderr)
        return 2
    qfolder = getattr(args, "quarantine_folder", "Junk")
    try:
        detail = asyncio.run(quarantine_email(
            s.imap_host, s.imap_user, password, s.imap_port,
            folder, uid, action, qfolder, oauth_token=oauth_token,
        ))
    except Exception as e:
        print(f"HATA: karantina başarısız uid={uid}: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    print(f"OK: {detail}")
    qlog = getattr(args, "quarantine_log", "quarantine.jsonl")
    if qlog:
        try:
            with open(qlog, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"uid": uid, "action": action, "detail": detail,
                                     "at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")},
                                    ensure_ascii=False, default=str) + "\n")
        except Exception as e:
            print(f"UYARI: karantina günlüğü yazılamadı: {e}", file=sys.stderr)
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
    """Ayar yönetimi: setup (kolay kurulum) / init / show / set / get / path / test / login / logout."""
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

    if action == "setup":
        from app.setup_wizard import IO, run_setup

        target = Path(get_explicit() or str(default_user_config_path()))

        def _save(key: str, value: str, secret: bool) -> None:
            upsert_kv(target, key, value, secret=secret)

        out = run_setup(
            email=(getattr(args, "email", "") or "") or None,
            method=(getattr(args, "method", "") or "") or None,
            provider=(getattr(args, "provider", "") or "") or None,
            no_browser=bool(getattr(args, "no_browser", False)),
            io=IO(),
            do_save=_save,
        )
        if isinstance(out, str) and out.startswith("OAUTH:"):
            prov = out.split(":", 1)[1]
            return cmd_config(argparse.Namespace(config_action="login", provider=prov))
        return int(out)

    if action == "init":
        target = get_explicit() or str(default_user_config_path())
        print(f"ElfSec kurulum sihirbazı -> {target}")
        print("Giriş yöntemi: [1] OAuth (önerilir: outlook/gmail, bir kez tarayıcı onayı)")
        print("                [2] Uygulama şifresi (IMAP_PASSWORD)")
        yontem = input("Seçim [1/2, varsayılan 1]: ").strip() or "1"
        if yontem == "1":
            sag = (input("Sağlayıcı [outlook/gmail]: ").strip() or "").lower()
            if sag not in ("outlook", "gmail"):
                print("HATA: sağlayıcı outlook|gmail olmalı.", file=sys.stderr)
                return 2
            return cmd_config(argparse.Namespace(config_action="login", provider=sag))
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

    if action == "login":
        from app.oauth import PROVIDERS, active_provider, login_flow

        provider_arg = getattr(args, "provider", "") or ""
        target = Path(get_explicit() or str(default_user_config_path()))
        if provider_arg:
            provider = provider_arg.lower()
        else:
            s0, _, _ = build_settings(get_explicit())
            provider = active_provider(s0)
        if provider not in PROVIDERS:
            print("HATA: sağlayıcı bulunamadı. `--provider outlook|gmail` verin.", file=sys.stderr)
            return 2
        s0, _, _ = build_settings(get_explicit())
        client_id = (s0.ms_client_id if provider == "outlook" else s0.google_client_id) or ""
        if not client_id:
            key = "MS_CLIENT_ID" if provider == "outlook" else "GOOGLE_CLIENT_ID"
            client_id = input(f"{key} (kendi uygulama kaydınız, README'ye bakın): ").strip()
            if not client_id:
                print(f"HATA: {key} boş.", file=sys.stderr)
                return 2
            upsert_kv(target, key, client_id)
        upsert_kv(target, "OAUTH_PROVIDER", provider)
        try:
            tokens = login_flow(provider, client_id)
        except Exception as e:
            print(f"GİRİŞ BAŞARISIZ: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
        rkey = "OAUTH_REFRESH_OUTLOOK" if provider == "outlook" else "OAUTH_REFRESH_GMAIL"
        upsert_kv(target, rkey, tokens["refresh_token"], secret=True)
        print(f"OK: {PROVIDERS[provider]['label']} girişi kaydedildi (şifreli refresh-token).")
        print("Test: elfsec config test")
        return 0

    if action == "logout":
        target = Path(get_explicit() or str(default_user_config_path()))
        provider = (getattr(args, "provider", "") or "").lower()
        keys = []
        if provider in ("outlook", ""):
            keys.append("OAUTH_REFRESH_OUTLOOK")
        if provider in ("gmail", ""):
            keys.append("OAUTH_REFRESH_GMAIL")
        for k in keys:
            upsert_kv(target, k, "")
        if not provider:
            upsert_kv(target, "OAUTH_PROVIDER", "")
        print(f"OK: çıkış yapıldı ({', '.join(keys)} temizlendi). Şifreli girişe dönüldü.")
        return 0

    if action == "show":
        import os as _os

        from app.settings_store import _lock_down, _windows_acl_tight, config_mode

        s, found, _w = build_settings(get_explicit())
        if not found:
            print("(config dosyası yok — varsayılanlar + ortam değişkenleri)")
        elif _os.name == "nt":
            # Windows'ta st_mode anlamsız (hep 0o666); gerçek ölçü ACL'dir.
            tight = _windows_acl_tight(found)
            if tight is False:
                _lock_down(found)  # otomatik sıkılaştırmayı dene
                if _windows_acl_tight(found) is False:
                    print(f"UYARI: {found} herkesçe okunabilir — "
                          f"`icacls \"{found}\" /inheritance:r /grant:r \"%USERNAME%:F\"` ile kısıtlayın.",
                          file=sys.stderr)
        else:
            mode = config_mode(found)
            if mode != -1 and mode & 0o077:
                print(f"UYARI: {found} herkesçe okunabilir (mode {oct(mode)}) — "
                      f"`chmod 600 \"{found}\"` ile kısıtlayın.",
                      file=sys.stderr)
        if args.reveal:
            print("DİKKAT: gizli değerler açık basılıyor — ekranı/bel Belleği kimseyle paylaşmayın.",
                  file=sys.stderr)
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
        try:
            _pw, _tok, yontem = _imap_auth(s)
        except OSError as e:
            print(f"IMAP: HAZIR DEĞİL — {e}", file=sys.stderr)
            return 2
        hazir = bool(_pw or _tok)
        print(f"IMAP: {'HAZIR' if hazir else 'EKSİK'} ({yontem}) | MOTOR: elfsec-local/1.0 (anahtarsız)")
        if hazir:
            from app.services.imap_client import list_folders
            try:
                folders = asyncio.run(list_folders(s.imap_host, s.imap_user, _pw, s.imap_port,
                                                   oauth_token=_tok))
                print(f"IMAP bağlantısı OK — {len(folders)} klasör: {', '.join(folders[:5])}")
            except Exception as e:
                print(f"IMAP bağlantısı BAŞARISIZ: {type(e).__name__}: {e}", file=sys.stderr)
                return 2  # ortam hatası (sözleşme: 2), şüpheli-mail kodu 1 değil
        return 0

    if action in ("login", "logout"):
        # login/logout gövdeleri yukarıda; buraya düşerse parser eksiktir.
        print("HATA: login/logout alt komutu tanımlı değil.", file=sys.stderr)
        return 2

    return 2


def cmd_rules(args: argparse.Namespace) -> int:
    """v0.6.0 motor kural ağırlıkları: show | set ID W | enable ID | disable ID | reset."""
    from app.rules import DEFAULT_RULES, load_rules, rules_path, save_rules

    op = getattr(args, "rules_op", "show")
    if op == "show":
        rules = load_rules()
        if getattr(args, "json", False):
            emit(rules, args)
        else:
            from app.table import render, sev, use_table

            rows = [[rid, str(r.get("weight")), sev("açık" if r.get("enabled") else "KAPALI")]
                    for rid, r in sorted(rules.items())]
            if use_table(args):
                print(render(["Kural", "Ağırlık", "Durum"], rows,
                             title=f"MOTOR KURALLARI ({len(rows)})",
                             aligns=["l", "r", "l"]))
            else:
                for rid, w, flag in rows:
                    print(f"{rid:18s} ağırlık={w:>3s} {flag}")
            print(f"(kaynak: {rules_path()})")
        return 0
    if op == "reset":
        save_rules({k: dict(v) for k, v in DEFAULT_RULES.items()})
        print(f"OK: kurallar sıfırlandı -> {rules_path()}")
        return 0
    rid = (getattr(args, "rule_id", "") or "").lower()
    if rid not in DEFAULT_RULES:
        print(f"HATA: bilinmeyen kural: {rid}. Geçerli: {', '.join(sorted(DEFAULT_RULES))}",
              file=sys.stderr)
        return 2
    rules = load_rules()
    if op == "set":
        try:
            w = int(getattr(args, "weight", -1))
        except Exception:
            print("HATA: ağırlık 0-100 sayı olmalı.", file=sys.stderr)
            return 2
        if w < 0 or w > 100:
            print("HATA: ağırlık 0-100 arası olmalı.", file=sys.stderr)
            return 2
        rules[rid]["weight"] = w
        rules[rid]["enabled"] = True
    elif op == "enable":
        rules[rid]["enabled"] = True
    elif op == "disable":
        rules[rid]["enabled"] = False
    save_rules(rules)
    print(f"OK: {rid} -> ağırlık={rules[rid]['weight']} "
          f"{'açık' if rules[rid]['enabled'] else 'kapalı'}")
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    """v0.6.0 güncelleme kontrolü: GitHub Releases'teki son tag ile karşılaştır.

    Çevrimdışı/ulaşılamazsa exit 2 değil 0 + uyarı (bilgi komutu, kapı değil).
    """
    import urllib.request

    from app.__version__ import __version__

    repo = (getattr(args, "repo", "") or "").strip() or "ElfSec/ElfSec"
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ElfSec",
                                                   "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        latest = str(data.get("tag_name", "")).lstrip("v")
        cur = __version__.lstrip("v")
        if not latest:
            print("UYARI: sürüm bilgisi alınamadı.", file=sys.stderr)
            return 0
        if latest == cur:
            print(f"Güncel: v{cur} (son sürüm).")
        else:
            print(f"Yeni sürüm var: v{latest} (sizde v{cur}). "
                  f"Releases'ten elfsec.exe'yi indirin.")
            if getattr(args, "json", False):
                emit({"current": cur, "latest": latest}, args)
        return 0
    except Exception as e:
        print(f"UYARI: güncelleme kontrolü yapılamadı (çevrimdışı?): {e}", file=sys.stderr)
        return 0


def cmd_kontrol(args: argparse.Namespace) -> int:
    """Sürümlü güvenlik denetimi + hacker-gözü sızma testleri.

    Çıktı FAIL önce, sürüm sırasına göre optimize edilir.
    Exit: 0 temiz, 1 açık var (--fail-on), 2 hata.
    """
    from app.kontrol import run_kontrol

    kats = [k.strip() for k in str(getattr(args, "kategori", "") or "").split(",") if k.strip()]
    try:
        rapor = run_kontrol(kats or None)
    except Exception as e:
        print(f"KONTROL HATASI: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    if not getattr(args, "quiet", False):
        from app.table import panel, render, sev, use_table

        rows = [b for b in rapor["bulgular"]
                if not (getattr(args, "fail_only", False) and b["durum"] in ("PASS", "SKIP"))]
        if use_table(args):
            print(panel(f"KONTROL {rapor['version']}", [
                ("Sonuç", sev(rapor["worst"])),
                ("Toplam", str(rapor["toplam"])),
                ("FAIL", sev("FAIL") + f" {rapor['fail']}" if rapor["fail"] else "0"),
                ("WARN", sev("WARN") + f" {rapor['warn']}" if rapor["warn"] else "0"),
                ("Atlanan", str(rapor.get("skipped", 0))),
            ]))
            if rapor.get("exe_modu"):
                print("(exe-içi: repo-dosya kontrolleri SKIP — davranış testleri geçerli)")
            if rapor.get("yol_haritasi"):
                print(render(["Sürüm", "Açıklar"],
                             [[sv, ", ".join(ids)] for sv, ids in rapor["yol_haritasi"].items()],
                             title="YOL HARİTASI"))
            if rows:
                print(render(["Durum", "ID", "Sürüm", "Ad", "Detay"],
                             [[sev(b["durum"]), b["id"], b["surum"], b["ad"], b["detay"]]
                              for b in rows],
                             title=f"BULGULAR ({len(rows)})"))
            else:
                # --fail-only ile açık yoksa boş tablo basma, kullanıcı "bozuk mu" sanıyor.
                print(f"{sev('PASS')} Açık bulunamadı — her şey temiz.")
        else:
            print(f"KONTROL {rapor['version']} worst={rapor['worst']} "
                  f"toplam={rapor['toplam']} fail={rapor['fail']} warn={rapor['warn']} "
                  f"skipped={rapor.get('skipped', 0)}")
            if rapor.get("exe_modu"):
                print("(exe-içi: repo-dosya kontrolleri SKIP — davranış testleri geçerli)")
            if rapor.get("yol_haritasi"):
                print("Yol haritası (açık -> sürüm):")
                for sv, ids in rapor["yol_haritasi"].items():
                    print(f"  {sv}: {', '.join(ids)}")
            if rows:
                for b in rows:
                    print(f"  [{b['durum']:4s}] {b['id']:10s} ({b['surum']}) {b['ad']} — {b['detay']} | Öneri: {b['oneri']}")
            else:
                print("Açık bulunamadı — her şey temiz.")
    # JSON raporu yalnız istenirse bas: menü/terminal kullanıcısı tabloyu
    # görsün, 60 bulguluk JSON seline boğulmasın (--json/--out boru hattı için).
    if getattr(args, "json", False) or getattr(args, "out", ""):
        emit(rapor, args)
    esik = getattr(args, "fail_on", "HIGH")
    if esik == "NEVER":
        return 0
    # fail-on: FAIL her zaman 1; WARN sadece LOW eşiğinde 1
    if rapor["fail"] > 0 and esik in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return 1
    if rapor["warn"] > 0 and esik == "LOW":
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="elfsec", description="ElfSec: e-posta güvenlik analiz tool'u (dev/security)")
    p.add_argument("--config", default="", help="Ayar dosyası yolu (varsayılan: %%APPDATA%%/ElfSec/elfsec.env)")
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("health", help="Ortam durumunu göster")
    h.add_argument("--json", action="store_true")
    h.add_argument("--out", default="")
    h.set_defaults(func=cmd_health)

    d = sub.add_parser("dashboard", help="Tek ekran: durum + son alarmlar tablosu")
    d.add_argument("--alert-log", default="guard_alerts.jsonl", help="Alarm günlüğü")
    d.add_argument("--limit", type=int, default=10, help="Gösterilecek alarm sayısı (1-50)")
    d.add_argument("--json", action="store_true")
    d.add_argument("--out", default="")
    d.set_defaults(func=cmd_dashboard)

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
    a.add_argument("--header", action="append", default=[], metavar="'Reply-To: x@y'",
                   help="Başlık doğrulaması için tekrarlanabilir (Reply-To/Return-Path/Authentication-Results/Message-ID)")
    a.add_argument("--expand-urls", action="store_true",
                   help="Kısaltılmış linkleri çevrimiçi genişlet (varsayılan kapalı: çevrimdışı)")
    _add_common(a, with_fail=True)
    a.set_defaults(func=cmd_analyze)

    af = sub.add_parser("analyze-file", help="Dosya/glob analizi: --path 'mails/*.eml'")
    af.add_argument("--path", nargs="+", required=True)
    af.add_argument("--subject", default="")
    af.add_argument("--sender", default="")
    af.add_argument("--header", action="append", default=[], metavar="'Reply-To: x@y'")
    af.add_argument("--expand-urls", action="store_true",
                    help="Kısaltılmış linkleri çevrimiçi genişlet (varsayılan kapalı)")
    af.add_argument("--json-list", action="store_true", help="Tek dosya bile olsa liste bas")
    _add_common(af, with_fail=True)
    af.set_defaults(func=cmd_analyze_file)

    t = sub.add_parser("triage", help="Son N maili çek+analiz et, riske göre sırala")
    t.add_argument("--folder", default="INBOX")
    t.add_argument("--limit", type=int, default=20)
    t.add_argument("--unseen", action="store_true")
    t.add_argument("--top", type=int, default=0, help="En riskli ilk K (0=tümü)")
    t.add_argument("--min-score", type=int, default=0, help="Bu skorun altını ele")
    t.add_argument("--expand-urls", action="store_true",
                   help="Kısaltılmış linkleri çevrimiçi genişlet (varsayılan kapalı)")
    t.add_argument("--cef", default="", help="SIEM için CEF satırları dosyası (v0.6.0)")
    _add_common(t, with_fail=True)
    t.set_defaults(func=cmd_triage)

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
    g.add_argument("--webhook-header", action="append", default=[], metavar="'Authorization: Bearer X'",
                   help="Webhook ek başlığı, tekrarlanabilir (3 deneme + üstel bekleme)")
    g.add_argument("--once", action="store_true", help="Tek tur atıp çık (zamanlanmış görev için)")
    g.add_argument("--quiet", action="store_true")
    g.add_argument("--fail-on", default="NEVER", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "NEVER"],
                   help="--once ile: bu seviye ve üstünde exit-code 1")
    g.add_argument("--tray", action="store_true", help="Tepsi/sessiz arka plan modu (konsolu gizle, toast at)")
    g.add_argument("--background", action="store_true", help="--tray ile aynı (tek exe arka plan)")
    g.add_argument("--notify", default="on", choices=["on", "off"], help="Windows Toast bildirimi (varsayılan: on)")
    g.add_argument("--action", default="notify-only", choices=["notify-only", "quarantine", "delete"],
                   help="Tehlike aksiyonu. Varsayılan dokunmaz; quarantine taşı, delete kalıcı sil (onaylı).")
    g.add_argument("--quarantine-folder", default="Junk", help="Karantina hedef klasörü (varsayılan: Junk)")
    g.add_argument("--quarantine-log", default="quarantine.jsonl", help="Karantina işlem günlüğü")
    g.add_argument("--expand-urls", action="store_true",
                   help="Kısaltılmış linkleri çevrimiçi genişlet (varsayılan kapalı)")
    g.add_argument("--cef-log", default="", help="Alarmların CEF olarak ekleneceği dosya (SIEM)")
    g.add_argument("--redact", action="store_true", help="Log/webhook/toast'ta PII maskele (e-posta, IBAN, TC, kart)")
    g.add_argument("--retention-days", type=int, default=0, help="0=kapalı, N>0 ise N günden eski log satırlarını buda")
    g.set_defaults(func=cmd_guard)

    c = sub.add_parser("config", help="Ayar yönetimi (setup/init/show/set/get/path/test/login/logout)")
    csub = c.add_subparsers(dest="config_action", required=True)
    ci = csub.add_parser("init", help="Etkileşimli kurulum sihirbazı (OAuth önerilir)")
    ci.set_defaults(func=cmd_config)
    clogin = csub.add_parser("login", help="OAuth girişi: tarayıcıda bir kez onayla")
    clogin.add_argument("--provider", default="", help="outlook|gmail (boşsa ayardan tahmin)")
    clogin.set_defaults(func=cmd_config)
    cl = csub.add_parser("logout", help="OAuth çıkış: refresh-token temizle")
    cl.add_argument("--provider", default="", help="outlook|gmail (boşsa hepsi)")
    cl.set_defaults(func=cmd_config)
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
    csu = csub.add_parser("setup", help="Kolay kurulum: e-postanı yaz, gerisini sihirbaz halleder")
    csu.add_argument("--email", default="", help="E-posta adresi (verilmezse sorulur)")
    csu.add_argument("--method", default="", choices=["app-password", "oauth"],
                     help="Giriş yöntemi (verilmezse sorulur)")
    csu.add_argument("--provider", default="", help="Sağlayıcı ön-seçimi (çoğunlukla gerekmez)")
    csu.add_argument("--no-browser", action="store_true", help="Tarayıcıyı otomatik açma")
    csu.set_defaults(func=cmd_config)

    k = sub.add_parser("kontrol", help="Sürümlü güvenlik denetimi + sızma testleri")
    k.add_argument("--kategori", default="", help="Virgüllü filtre: SURUM,TEMIZLE,ANALIZ,TOOL,IMAP,OPS,SERVE")
    k.add_argument("--fail-only", action="store_true", help="Sadece FAIL/WARN bas")
    _add_common(k, with_fail=True)
    k.set_defaults(func=cmd_kontrol)

    r = sub.add_parser("rules", help="Motor kural ağırlıkları (show/set/enable/disable/reset)")
    rsub = r.add_subparsers(dest="rules_op")
    rsub.add_parser("show", help="Ağırlıkları listele").set_defaults(func=cmd_rules)
    _rs = rsub.add_parser("set", help="Ağırlık ata: rules set phishing_pattern 40")
    _rs.add_argument("rule_id")
    _rs.add_argument("weight")
    _rs.set_defaults(func=cmd_rules, rules_op="set")
    _re = rsub.add_parser("enable", help="Kuralı aç")
    _re.add_argument("rule_id")
    _re.set_defaults(func=cmd_rules, rules_op="enable")
    _rd = rsub.add_parser("disable", help="Kuralı kapat")
    _rd.add_argument("rule_id")
    _rd.set_defaults(func=cmd_rules, rules_op="disable")
    rsub.add_parser("reset", help="Varsayılanlara dön").set_defaults(func=cmd_rules, rules_op="reset")
    r.set_defaults(func=cmd_rules, rules_op="show")

    u = sub.add_parser("update", help="Güncelleme kontrolü (GitHub Releases)")
    u.add_argument("--check", action="store_true", help="Son sürümü kontrol et")
    u.add_argument("--repo", default="", help="Sahip/Repo (varsayılan: ElfSec/ElfSec)")
    u.add_argument("--json", action="store_true")
    u.set_defaults(func=cmd_update)

    q = sub.add_parser("quarantine", help="Tek maili karantinaya al/sil (toast butonu veya elle)")
    q.add_argument("uid", help="IMAP UID")
    q.add_argument("--folder", default="INBOX")
    q.add_argument("--action", default="quarantine", choices=["quarantine", "delete"],
                   help="quarantine=taşı (geri alınabilir), delete=kalıcı sil (--yes gerekli)")
    q.add_argument("--yes", action="store_true", help="Kalıcı silmeyi onayla")
    q.add_argument("--quarantine-folder", default="Junk")
    q.add_argument("--quarantine-log", default="quarantine.jsonl")
    q.set_defaults(func=cmd_quarantine)

    s = sub.add_parser("serve", help="Web API: site bu adresten skor çeker (stdlib, ek bağımlılık yok)")
    s.add_argument("--host", default="127.0.0.1", help="Dinleme adresi (varsayılan localhost)")
    s.add_argument("--port", type=int, default=8765, help="Dinleme portu")
    s.add_argument("--rate-limit", type=int, default=60, help="IP başına dakikada istek")
    s.add_argument("--cors-origins", default="",
                   help="Virgüllü origin allowlist, örn: https://benimsitem.com")
    s.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    try:
        from app.table import ensure_utf8

        ensure_utf8()
    except Exception:
        pass
    from app.settings_store import ConfigError, set_explicit

    # Toast butonundan gelen protokol URI'si: elfsec:quarantine?uid=123
    # → normal CLI çağrısına çevir (Windows protocol activation).
    if argv is None:
        argv = sys.argv[1:]
    else:
        argv = list(argv)
    if len(argv) == 1:
        parsed = parse_protocol_uri(argv[0])
        if parsed:
            action, kw = parsed
            argv = ["quarantine", kw["uid"], "--action", action]
    # argparse hatasında (bilinmeyen komut/argüman) SystemExit kodu aynen geçer.
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
    except KeyboardInterrupt:
        print("\nİptal edildi.", file=sys.stderr)
        return 2
    except BrokenPipeError:
        # Pipe kapanması (örn. `... | head`): hata değil, sessiz çık.
        try:
            sys.stderr.close()
        except Exception:
            pass
        return 0
    except Exception as e:
        # Beklenmeyen crash: traceback değil, tek satır + tür. Debug için --config yok.
        print(f"HATA: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
