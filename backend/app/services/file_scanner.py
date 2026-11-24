"""Çevrimdışı Windows dosya, script ve .eml güvenlik tarayıcısı.

Hiçbir dosyayı çalıştırmadan (statik inceleme + imza/sihirli bayt + Mark-of-the-Web
+ LOLBin script analizi + .eml/.html ayrıştırma) risk skoru üretir ve gerekirse
dosyayı güvenli karantina kasasına (.quarantined uzantısı ile) taşır.
"""

from __future__ import annotations

import asyncio
import email
import email.policy
import hashlib
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from app.rules import load_rules
from app.services.ai_analyzer import (
    ENGINE,
    MACRO_EXT,
    _W,
    _attachments_score,
    _check_url,
    local_analyze,
)
from app.services.sanitizer import extract_urls, sanitize_email
from app.urlintel import maybe_expand

SCRIPT_EXT = (
    ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".hta", ".reg", ".lnk",
)
EXEC_EXT = (
    ".exe", ".msi", ".scr", ".com", ".pif", ".cpl",
    ".dll", ".sys", ".iso", ".img", ".jar",
)
DOC_MEDIA_EXT = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".txt", ".rtf",
)
EMAIL_EXT = (".eml", ".msg")
HTML_EXT = (".html", ".htm", ".xhtml", ".svg", ".mht", ".mhtml")
RLO_CHARS = ("\u202e", "\u202d", "\u2066", "\u2067", "\u2068", "\u2069")

MAX_READ_BYTES = 262_144
MAX_HASH_BYTES = 20_000_000

LOLBIN_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"powershell(?:\.exe)?\b[^\n]*(?:-enc\b|-encodedcommand\b|-w\s+hidden|-windowstyle\s+hidden)",
     "Gizli veya kodlanmış PowerShell çalıştırma kalıbı"),
    (r"\b(?:invoke-expression|iex)\s*\(",
     "Dinamik kod çalıştırma (Invoke-Expression / IEX)"),
    (r"(?:downloadstring|downloadfile|invoke-webrequest|\biwr\b|\birm\b)[^\n]*https?://",
     "İnternetten uzaktan yük indirme komutu"),
    (r"\bmshta(?:\.exe)?\s+(?:https?://|javascript:|vbscript:)",
     "MSHTA ile uzaktan veya betik çalıştırma (LOLBin)"),
    (r"\bcertutil(?:\.exe)?\b[^\n]*(?:-urlcache|-decode)",
     "Certutil ile dosya indirme/çözme (LOLBin)"),
    (r"\bbitsadmin(?:\.exe)?\b[^\n]*/transfer\b",
     "Bitsadmin ile arka plan indirme (LOLBin)"),
    (r"\bregsvr32(?:\.exe)?\b[^\n]*/i:https?://",
     "Regsvr32 ile uzaktan scriptlet yükleme (Squiblydoo)"),
    (r"add-mppreference\b[^\n]*-exclusion",
     "Windows Defender tarama dışı bırakma girişimi"),
    (r"\b(?:curl|wget)(?:\.exe)?\b[^\n]*\|\s*(?:sh|bash|powershell|cmd)",
     "İndirilen içeriği doğrudan kabuğa yönlendirme"),
)


def sha256_file(path: Path, max_bytes: int = MAX_HASH_BYTES) -> str:
    """Dosyanın SHA-256 özetini 64KB bloklarla hesaplar (DoS korumalı)."""
    h = hashlib.sha256()
    read_total = 0
    try:
        with open(path, "rb") as fh:
            while read_total < max_bytes:
                chunk = fh.read(min(65536, max_bytes - read_total))
                if not chunk:
                    break
                h.update(chunk)
                read_total += len(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def parse_motw_text(text: str) -> dict:
    """Zone.Identifier içeriğini ayrıştır (saf fonksiyon — test edilebilir)."""
    out: dict = {"zone_id": None, "referrer_url": "", "host_url": ""}
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        kl = k.strip().lower()
        val = v.strip()
        if kl == "zoneid":
            try:
                out["zone_id"] = int(val)
            except ValueError:
                pass
        elif kl == "referrerurl":
            out["referrer_url"] = val[:500]
        elif kl == "hosturl":
            out["host_url"] = val[:500]
    return out


def read_motw(path: Path) -> dict:
    """Windows NTFS Alternate Data Stream (Zone.Identifier) okur."""
    if os.name != "nt":
        return {}
    ads = f"{path}:Zone.Identifier"
    try:
        with open(ads, "r", encoding="utf-8", errors="replace") as fh:
            parsed = parse_motw_text(fh.read(8192))
        return parsed if parsed.get("zone_id") is not None else {}
    except OSError:
        return {}


def _extract_email_header_addr(msg, key: str) -> str:
    try:
        val = msg.get(key, "")
        return str(val or "")[:500]
    except Exception:
        return ""


def parse_eml_bytes(raw: bytes) -> dict:
    """Ham .eml baytlarını konu, gönderici, başlık, gövde ve eklere ayrıştır."""
    msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(raw)
    headers = {
        "reply_to": _extract_email_header_addr(msg, "Reply-To"),
        "return_path": _extract_email_header_addr(msg, "Return-Path"),
        "auth_results": str(msg.get("Authentication-Results", "") or "")[:2000],
        "message_id": _extract_email_header_addr(msg, "Message-ID"),
    }
    html_parts: list[str] = []
    text_parts: list[str] = []
    attachments: list[dict] = []

    if msg.is_multipart():
        for part in msg.walk():
            disp = str(part.get_content_disposition() or "").lower()
            fname = part.get_filename()
            ctype = str(part.get_content_type() or "").lower()
            if disp == "attachment" or fname:
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": str(fname or "attachment"),
                    "size": len(payload),
                    "content_type": ctype,
                })
                continue
            if ctype in ("text/html", "text/plain"):
                try:
                    content = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    content = payload.decode("utf-8", errors="replace")
                if isinstance(content, bytes):
                    content = content.decode("utf-8", errors="replace")
                (html_parts if ctype == "text/html" else text_parts).append(str(content))
    else:
        try:
            content = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        if str(msg.get_content_type() or "").lower() == "text/html":
            html_parts.append(str(content))
        else:
            text_parts.append(str(content))

    body = "\n".join(html_parts) if html_parts else "\n".join(text_parts)
    if html_parts and text_parts:
        body = "\n".join(html_parts) + "\n" + "\n".join(text_parts)

    return {
        "subject": str(msg.get("Subject", "") or "")[:1000],
        "sender": str(msg.get("From", "") or "")[:500],
        "headers": headers,
        "body": body[:30000],
        "attachments": attachments,
    }


def inspect_lnk_bytes(raw: bytes) -> list[str]:
    """Windows .lnk kısayol dosyasından ASCII ve UTF-16LE komut dizelerini güvenli çıkar."""
    sample = raw[:524_288]
    strings: list[str] = []
    for m in re.finditer(rb"[\x20-\x7e]{6,}", sample):
        strings.append(m.group(0).decode("ascii", errors="ignore"))
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", sample):
        strings.append(m.group(0).decode("utf-16-le", errors="ignore"))
    return strings


def _add_score(score: int, reasons: list[str], rules: dict, rule_id: str, default: int, reason: str) -> int:
    w = _W(rules, rule_id, default)
    if w:
        reasons.append(reason)
        return score + w
    return score


def _check_script_text(text: str, rules: dict, score: int, reasons: list[str], sus_urls: list[str]) -> int:
    """Script veya kısayol içeriğinde LOLBin / uzaktan kod çalıştırma kalıplarını arar."""
    for pat, desc in LOLBIN_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            score = _add_score(score, reasons, rules, "script_lolbin", 35, f"Zararlı script/komut kalıbı: {desc}.")
            break
    if (re.search(r"(?:frombase64string|fromcharcode)", text, re.IGNORECASE)
            and re.search(r"\b(?:eval|execute|iex|shell|wscript)\b", text, re.IGNORECASE)):
        score = _add_score(score, reasons, rules, "script_lolbin", 35,
                           "Gizlenmiş (Base64/CharCode) dinamik script çalıştırma.")
    for u in extract_urls(text):
        pts, why = _check_url(u, rules)
        if pts and u not in sus_urls:
            score += pts
            sus_urls.append(u)
            if why:
                reasons.append(why)
    return score


def _level_from_score(score: int) -> str:
    return "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"


def scan_file_security(
    path: str | Path,
    expand_urls: bool = False,
    rules: dict | None = None,
    motw_override: dict | None = None,
) -> dict:
    """Tek dosyayı tüm Windows + e-posta güvenlik katmanlarıyla tarar."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"Dosya bulunamadı: {p}")

    R = rules if rules is not None else load_rules()
    name = p.name
    ext = p.suffix.lower()
    size = p.stat().st_size

    score = 0
    reasons: list[str] = []
    sus_urls: list[str] = []
    phishing_detected = False
    prompt_injection_detected = False

    # 1) Unicode RLO (sağdan-sola karakter ile uzantı gizleme)
    if any(ch in name for ch in RLO_CHARS):
        score = _add_score(score, reasons, R, "file_rlo", 35,
                           "Unicode RLO sahteciliği: dosya adında gizli yönlendirme karakteri var.")

    # 2) Dosya adı / çift uzantı / riskli uzantı puanı (özel script uzantıları dahil)
    att_score, att_reasons = _attachments_score([{"filename": name, "size": size, "content_type": ""}], R)
    score += att_score
    reasons.extend(att_reasons)
    if not att_score and ext in SCRIPT_EXT:
        score = _add_score(score, reasons, R, "attach_risky", 20,
                           f"Riskli betik/kısayol dosyası: {name} ({ext}).")

    # 3) İlk blok okuma + PE MZ sihirli bayt uyumsuzluğu
    with open(p, "rb") as fh:
        head_bytes = fh.read(MAX_READ_BYTES)

    is_pe = head_bytes.startswith(b"MZ")
    if is_pe and ext in DOC_MEDIA_EXT:
        score = _add_score(score, reasons, R, "file_magic_mismatch", 50,
                           f"Dosya türü sahteciliği: '{ext}' uzantılı dosya çalıştırılabilir PE/EXE (MZ) başlığı taşıyor!")

    # 4) Mark-of-the-Web (Zone.Identifier)
    motw = motw_override if motw_override is not None else read_motw(p)
    zone_id = motw.get("zone_id") if isinstance(motw, dict) else None
    if zone_id in (3, 4):
        if ext in EXEC_EXT or ext in SCRIPT_EXT or ext in MACRO_EXT or att_score > 0 or is_pe:
            score = _add_score(score, reasons, R, "file_motw", 15,
                               f"İnternetten indirilmiş çalıştırılabilir/riskli dosya (ZoneId={zone_id}).")
        for murl in (motw.get("host_url", ""), motw.get("referrer_url", "")):
            if murl:
                pts, why = _check_url(murl, R)
                if pts and murl not in sus_urls:
                    score += pts
                    sus_urls.append(murl)
                    if why:
                        reasons.append(f"İndirme kaynağı şüpheli: {why}")

    # 5) İçerik türüne göre derin tarama
    if ext == ".eml":
        parsed = parse_eml_bytes(head_bytes)
        clean = sanitize_email(parsed["body"])
        urls, mapping = maybe_expand(clean["urls"], expand_urls)
        rep = asyncio.run(local_analyze_async(
            parsed["subject"], clean["plain_text"], urls,
            parsed["sender"], parsed["headers"], parsed["attachments"], R,
        ))
        score += rep["risk_score"]
        for r in rep["reasons"]:
            if r != "Bilinen oltalama / injection kalıbı eşleşmedi." and r not in reasons:
                reasons.append(r)
        for u in rep.get("suspicious_urls", []):
            if u not in sus_urls:
                sus_urls.append(u)
        phishing_detected = bool(rep.get("phishing_detected"))
        prompt_injection_detected = bool(rep.get("prompt_injection_detected"))
    elif ext in HTML_EXT:
        text = head_bytes.decode("utf-8", errors="replace")
        clean = sanitize_email(text)
        urls, _ = maybe_expand(clean["urls"], expand_urls)
        rep = asyncio.run(local_analyze_async(name, clean["plain_text"], urls, "", None, None, R))
        score += rep["risk_score"]
        for r in rep["reasons"]:
            if r != "Bilinen oltalama / injection kalıbı eşleşmedi." and r not in reasons:
                reasons.append(r)
        for u in rep.get("suspicious_urls", []):
            if u not in sus_urls:
                sus_urls.append(u)
        phishing_detected = bool(rep.get("phishing_detected"))
        prompt_injection_detected = bool(rep.get("prompt_injection_detected"))
        if re.search(r"<input[^>]+type=[\"']?password", text, re.IGNORECASE) and re.search(
                r"<form|action=", text, re.IGNORECASE):
            score = _add_score(score, reasons, R, "phishing_pattern", 25,
                               "Yerel HTML dosyasında şifre toplama formu tespit edildi.")
            phishing_detected = True
    elif ext == ".lnk":
        extracted = "\n".join(inspect_lnk_bytes(head_bytes))
        if extracted:
            score = _check_script_text(extracted, R, score, reasons, sus_urls)
    elif ext in SCRIPT_EXT or (ext in (".txt", ".log", ".url", ".csv") and not is_pe):
        text = head_bytes.decode("utf-8", errors="replace")
        score = _check_script_text(text, R, score, reasons, sus_urls)
        if ext == ".url":
            for u in extract_urls(text):
                pts, why = _check_url(u, R)
                if pts and u not in sus_urls:
                    score += pts
                    sus_urls.append(u)
                    if why:
                        reasons.append(why)

    score = max(0, min(100, score))
    level = _level_from_score(score)
    phishing_detected = phishing_detected or any(
        ("Oltalama" in r or "taklidi" in r or "Kimlik-avı" in r) for r in reasons
    )

    return {
        "source": "file_scan",
        "file": str(p),
        "filename": name,
        "subject": name,
        "size": size,
        "sha256": sha256_file(p),
        "motw": motw,
        "risk_score": score,
        "risk_level": level,
        "summary": (
            f"Dosya güvenlik analizi: {len(reasons)} bulgu, skor {score}/100."
            if reasons else "Dosyada belirgin güvenlik tehdidi bulunamadı."
        ),
        "reasons": reasons or ["Bilinen tehdit imzası veya şüpheli kalıp eşleşmedi."],
        "suspicious_urls": sus_urls,
        "phishing_detected": phishing_detected,
        "prompt_injection_detected": prompt_injection_detected,
        "tracking_pixels_blocked": 0,
        "recommended_action": (
            "Dosyayı çalıştırmayın/açmayın, karantinaya alın veya kaynağını doğrulayın."
            if score >= 50 else "Belirgin risk yok, normal dikkat yeterli."
        ),
        "engine": ENGINE,
        "analyzed_at": datetime.now(timezone.utc),
    }


async def local_analyze_async(subject: str, plain_text: str, urls: list[str], sender: str = "",
                              headers: dict | None = None, attachments: list[dict] | None = None,
                              rules: dict | None = None) -> dict:
    return local_analyze(subject, plain_text, urls, sender, headers, attachments, rules)


def scan_path(
    path: str | Path,
    recursive: bool = True,
    max_files: int = 200,
    expand_urls: bool = False,
) -> list[dict]:
    """Tek dosya veya klasörü tarar, risk skoruna göre azalan sırada döndürür."""
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"Hedef bulunamadı: {target}")
    if target.is_file():
        return [scan_file_security(target, expand_urls=expand_urls)]

    files: list[Path] = []
    iterator = target.rglob("*") if recursive else target.glob("*")
    for item in iterator:
        if len(files) >= max_files:
            break
        if item.is_file() and not item.name.lower().endswith(".quarantined"):
            files.append(item)

    reports = []
    for f in files:
        try:
            reports.append(scan_file_security(f, expand_urls=expand_urls))
        except Exception:
            continue
    reports.sort(key=lambda r: r.get("risk_score", 0), reverse=True)
    return reports


def default_quarantine_dir() -> Path:
    from app.settings_store import default_user_config_path, machine_data_dir

    cand = machine_data_dir() / "quarantine"
    try:
        cand.mkdir(parents=True, exist_ok=True)
        probe = cand / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return cand
    except OSError:
        fallback = default_user_config_path().parent / "quarantine"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def quarantine_file(
    path: str | Path,
    quarantine_dir: str | Path | None = None,
    report: dict | None = None,
) -> dict:
    """Şüpheli dosyayı çalıştırılamaz (.quarantined) biçimde karantina kasasına taşır."""
    src = Path(path)
    if not src.exists() or not src.is_file():
        raise FileNotFoundError(f"Karantinaya alınacak dosya yok: {src}")

    qdir = Path(quarantine_dir) if quarantine_dir else default_quarantine_dir()
    qdir.mkdir(parents=True, exist_ok=True)

    digest = (report or {}).get("sha256") or sha256_file(src)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", src.name)[:80] or "file"
    dest = qdir / f"{stamp}_{digest[:12]}_{safe_name}.quarantined"
    counter = 1
    while dest.exists():
        dest = qdir / f"{stamp}_{digest[:12]}_{counter}_{safe_name}.quarantined"
        counter += 1

    shutil.move(str(src), str(dest))
    record = {
        "original_path": str(src),
        "quarantine_path": str(dest),
        "sha256": digest,
        "risk_score": (report or {}).get("risk_score", 0),
        "risk_level": (report or {}).get("risk_level", "UNKNOWN"),
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    }
    log_file = qdir / "file_quarantine.jsonl"
    with open(log_file, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def restore_quarantined_file(quarantine_path: str | Path, dest_path: str | Path) -> Path:
    """Karantinadaki .quarantined dosyayı güvenli şekilde hedef yola geri taşır."""
    src = Path(quarantine_path)
    if not src.exists() or not src.is_file():
        raise FileNotFoundError(f"Karantina dosyası bulunamadı: {src}")
    if src.suffix.lower() != ".quarantined":
        raise ValueError("Yalnızca .quarantined uzantılı dosyalar geri yüklenebilir.")
    dst = Path(dest_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return dst
