"""Gerçek zamanlı Windows İndirilenler klasörü güvenlik izleyicisi.

Tarayıcıdan inen yeni dosyaları (geçici .crdownload/.part uzantıları bittikten sonra)
çevrimdışı file_scanner ile tarar; HIGH/CRITICAL bulgularda alarm üretir ve
istenirse otomatik karantinaya alır.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from app.services.file_scanner import quarantine_file, scan_file_security

LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
TEMP_DOWNLOAD_SUFFIXES = (
    ".crdownload", ".part", ".tmp", ".opdownload",
    ".download", ".partial", ".quarantined",
)


def _iter_user_homes(all_users: bool = False) -> list[Path]:
    if all_users and os.name == "nt":
        users_root = Path(os.environ.get("SystemDrive", "C:") + "\\Users")
        skip = {"public", "default", "default user", "all users"}
        homes: list[Path] = []
        if users_root.exists():
            for udir in users_root.iterdir():
                if udir.is_dir() and udir.name.lower() not in skip:
                    homes.append(udir)
        if homes:
            return homes
    return [Path.home()]


def default_mail_app_dirs(all_users: bool = False) -> list[Path]:
    """Outlook Classic/New ve Windows Mail ek önbellek klasörlerini bul."""
    if os.name != "nt":
        return []
    found: list[Path] = []
    seen: set[str] = set()

    def _add(p: Path) -> None:
        key = str(p).lower()
        if p.is_dir() and key not in seen:
            seen.add(key)
            found.append(p)

    for home in _iter_user_homes(all_users=all_users):
        local_app = home / "AppData" / "Local"
        # Classic Outlook güvenli/geçici ek önbelleği
        co = local_app / "Microsoft" / "Windows" / "INetCache" / "Content.Outlook"
        if co.is_dir():
            for sub in co.iterdir():
                _add(sub)
        # Windows Mail & Yeni Outlook (UWP/Store paketleri)
        pkgs = local_app / "Packages"
        if pkgs.is_dir():
            for pdir in pkgs.iterdir():
                pname = pdir.name.lower()
                if pname.startswith("microsoft.windowscommunicationsapps_"):
                    _add(pdir / "LocalState" / "Files")
                elif pname.startswith("microsoft.outlookforwindows_"):
                    _add(pdir / "LocalCache" / "Local")
                    att_dir = pdir / "LocalCache" / "Local" / "Microsoft" / "Olk" / "Attachments"
                    _add(att_dir)
    return found


def default_watch_dirs(all_users: bool = False, include_mail_apps: bool = False) -> list[Path]:
    """İzlenecek İndirilenler (ve istenirse masaüstü mail ek önbelleği) klasörlerini döndür."""
    dirs: list[Path] = []
    for home in _iter_user_homes(all_users=all_users):
        dl = home / "Downloads"
        if dl.is_dir():
            dirs.append(dl)
    if include_mail_apps:
        for md in default_mail_app_dirs(all_users=all_users):
            if md not in dirs:
                dirs.append(md)
    return dirs


class FileWatchState:
    """Daha önce taranmış dosyaları (mtime_ns, size) ile takip eder."""

    def __init__(self, state_path: str | Path = ""):
        self.path = Path(state_path) if state_path else None
        self.entries: dict[str, dict] = {}
        if self.path:
            self.load()

    def load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self.entries = data
        except Exception:
            try:
                bak = Path(f"{self.path}.bozuk-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
                self.path.rename(bak)
            except Exception:
                pass
            self.entries = {}

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        items = list(self.entries.items())[-5000:]
        self.path.write_text(json.dumps(dict(items), ensure_ascii=False), encoding="utf-8")

    def is_seen(self, fp: Path) -> bool:
        try:
            st = fp.stat()
        except OSError:
            return True
        prev = self.entries.get(str(fp))
        return bool(prev and prev.get("mtime_ns") == st.st_mtime_ns and prev.get("size") == st.st_size)

    def mark(self, fp: Path) -> None:
        try:
            st = fp.stat()
            self.entries[str(fp)] = {"mtime_ns": st.st_mtime_ns, "size": st.st_size}
        except OSError:
            pass


def _should_alert(report: dict, alert_on: str) -> bool:
    return LEVEL_ORDER.get(report.get("risk_level", "LOW"), 0) >= LEVEL_ORDER.get(alert_on.upper(), 99)


def _is_passive_note_exempt_from_auto_quarantine(fp: Path, rep: dict) -> bool:
    """Düz metin/not (.txt/.md/.log) dosyalarında çalıştırılabilir tehdit yoksa oto-karantinayı engeller."""
    if fp.suffix.lower() not in (".txt", ".md", ".log"):
        return False
    if rep.get("pe_analysis"):
        return False
    reasons_text = " ".join(str(r) for r in (rep.get("reasons") or []))
    for marker in ("MZ", "RLO", "script", "LOLBin", "Windows Defender"):
        if marker.lower() in reasons_text.lower():
            return False
    return True


def scan_watch_dirs_once(
    dirs: list[Path],
    state: FileWatchState,
    alert_on: str = "HIGH",
    action: str = "notify-only",
    quarantine_dir: Path | None = None,
    alert_log: str = "",
    cef_log: str = "",
    webhook: str = "",
    webhook_headers: dict | None = None,
    notify: bool = True,
    redact: bool = False,
    expand_urls: bool = False,
    auto_protect: bool = False,
) -> tuple[list[dict], list[dict]]:
    """Verilen klasörlerdeki yeni/değişmiş dosyaları tek tur tarar.

    Dönüş: (tüm taranan raporlar, eşik üstü yeni alarmlar).
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    scanned: list[dict] = []
    alerts: list[dict] = []

    ai_cfg: dict = {}
    if auto_protect:
        try:
            from app.services.local_ai import load_ai_settings

            ai_cfg = load_ai_settings()
        except Exception:
            ai_cfg = {}
    ai_auto_on = bool(
        auto_protect
        and ai_cfg.get("enabled", True)
        and ai_cfg.get("auto_protect", False)
        and str(ai_cfg.get("auto_quarantine_level", "OFF")).upper() != "OFF"
    )
    ai_q_level = str(ai_cfg.get("auto_quarantine_level", "OFF")).upper()

    for d in dirs:
        if not d.exists() or not d.is_dir():
            continue
        try:
            candidates = sorted(d.iterdir())
        except OSError:
            continue
        for fp in candidates:
            if not fp.is_file():
                continue
            low = fp.name.lower()
            if low.endswith(TEMP_DOWNLOAD_SUFFIXES) or low == "desktop.ini":
                continue
            if state.is_seen(fp):
                continue
            try:
                rep = scan_file_security(fp, expand_urls=expand_urls)
            except Exception:
                continue
            state.mark(fp)
            scanned.append(rep)

            should_auto_q = bool(
                ai_auto_on
                and LEVEL_ORDER.get(rep.get("risk_level", "LOW"), 0) >= LEVEL_ORDER.get(ai_q_level, 99)
                and not _is_passive_note_exempt_from_auto_quarantine(fp, rep)
            )
            if not _should_alert(rep, alert_on) and not should_auto_q:
                continue

            entry = dict(rep)
            if redact:
                from app.redact import redact_report

                entry = redact_report(entry)
            entry["alerted_at"] = now
            entry["source"] = "file_watcher"

            if action == "quarantine" or should_auto_q:
                try:
                    qrec = quarantine_file(fp, quarantine_dir=quarantine_dir, report=rep)
                    entry["quarantined_to"] = qrec["quarantine_path"]
                    if should_auto_q and action != "quarantine":
                        entry["auto_protected"] = True
                except Exception as e:
                    entry["quarantine_error"] = str(e)

            if alert_log:
                try:
                    lp = Path(alert_log)
                    lp.parent.mkdir(parents=True, exist_ok=True)
                    with open(lp, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
                except Exception:
                    pass
            if cef_log:
                try:
                    from app.cef import to_cef

                    cp = Path(cef_log)
                    cp.parent.mkdir(parents=True, exist_ok=True)
                    with open(cp, "a", encoding="utf-8") as fh:
                        fh.write(to_cef(entry) + "\n")
                except Exception:
                    pass
            if webhook and str(webhook).lower().startswith("https://"):
                try:
                    from app.cli import _notify_webhook

                    _notify_webhook(webhook, entry, webhook_headers)
                except Exception:
                    pass
            if notify:
                try:
                    from app.notify import notify_file_alarm

                    notify_file_alarm(entry)
                except Exception:
                    pass
            alerts.append(entry)

    state.save()
    return scanned, alerts


def run_file_watcher(
    dirs: list[Path],
    state: FileWatchState,
    interval_sec: int = 10,
    stop_event: threading.Event | None = None,
    **kwargs,
) -> None:
    """Klasörleri belirli aralıkla sürekli izle."""
    ev = stop_event or threading.Event()
    iv = max(1, int(interval_sec))
    while not ev.is_set():
        scan_watch_dirs_once(dirs, state, **kwargs)
        for _ in range(iv):
            if ev.is_set():
                break
            time.sleep(1)
