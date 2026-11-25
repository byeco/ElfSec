"""Oyun Modu (düşük kaynak motoru) ve Modern Masaüstü Güvenlik Paneli testleri."""

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from app.cli import main as cli_main
from app.desktop_ui import DesktopPanelServer
from app.game_mode import (
    GameModeController,
    classify_game_process,
    read_shared_game_mode,
    write_shared_game_mode,
)
from app.services.file_scanner import quarantine_file
from app.win_service import ServiceRunner


def _http_call(url: str, method: str = "GET", headers: dict | None = None, body: dict | None = None):
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8")


def test_classify_game_process_variants():
    assert classify_game_process("customapp.exe", quns_state=3) == (True, "d3d_fullscreen")
    assert classify_game_process("cs2.exe") == (True, "known_game_exe")
    assert classify_game_process("VALORANT-Win64-Shipping.exe") == (True, "known_game_exe")
    assert classify_game_process("MyGame-Win64-Shipping.exe") == (True, "known_game_exe")
    assert classify_game_process(
        "game.exe",
        exe_path=r"D:\SteamLibrary\steamapps\common\Hades\game.exe",
    ) == (True, "game_library_path")
    assert classify_game_process("steam.exe") == (False, "ignored")
    assert classify_game_process("chrome.exe", is_fullscreen=True, quns_state=3) == (False, "ignored")
    assert classify_game_process("code.exe") == (False, "ignored")
    assert classify_game_process("mygame.exe", custom_processes={"mygame.exe"}) == (True, "custom_process")


def test_game_mode_controller_hysteresis_and_modes(tmp_path):
    cfg = tmp_path / "game_mode_config.json"
    shared = tmp_path / "game_mode.json"
    state_box = {"detected": False, "process": "", "reason": "idle"}

    ctrl = GameModeController(
        config_path=cfg,
        shared_paths=[shared],
        cooldown_sec=10.0,
        detector=lambda _custom: dict(state_box),
    )

    s0 = ctrl.evaluate(now=100.0)
    assert s0["active"] is False and s0["mode"] == "auto"

    state_box.update({"detected": True, "process": "cs2.exe", "reason": "known_game_exe"})
    s1 = ctrl.evaluate(now=105.0)
    assert s1["active"] is True and s1["process"] == "cs2.exe" and s1["cpu_priority"] == "IDLE"

    # Oyun kapandı / alt-tab — cooldown bitmeden aktif kalmalı
    state_box.update({"detected": False, "process": "", "reason": "idle"})
    s2 = ctrl.evaluate(now=110.0)
    assert s2["active"] is True and s2["reason"] == "cooldown"

    # Cooldown dolunca normal moda dönmeli
    s3 = ctrl.evaluate(now=116.0)
    assert s3["active"] is False and s3["cpu_priority"] == "NORMAL"

    # Manuel ON / OFF ve özel oyun listesi
    s_on = ctrl.set_mode("on")
    assert s_on["active"] is True and s_on["mode"] == "on"

    s_off = ctrl.set_mode("off")
    assert s_off["active"] is False and s_off["mode"] == "off"

    s_add = ctrl.add_custom_game("MyIndieGame")
    assert "myindiegame.exe" in s_add["custom_games"]
    s_rm = ctrl.remove_custom_game("myindiegame.exe")
    assert "myindiegame.exe" not in s_rm["custom_games"]


def test_shared_game_mode_expiry_and_service_throttling(monkeypatch, tmp_path):
    from app import settings_store

    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "cfg"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "pd"))
    settings_store.set_explicit(None)

    try:
        pd_dir = tmp_path / "pd" / "ElfSec"
        pd_dir.mkdir(parents=True, exist_ok=True)
        gm_file = pd_dir / "game_mode.json"

        # Eski zaman damgalı auto durumu stale sayılmalı
        write_shared_game_mode(
            {"mode": "auto", "active": True, "process": "cs2.exe", "updated_ts": time.time() - 120.0},
            target_paths=[gm_file],
        )
        stale = read_shared_game_mode(extra_paths=[gm_file], max_age_sec=30.0)
        assert stale["active"] is False

        # Taze aktif oyun modu -> ServiceRunner IMAP turunu ertelemeli
        write_shared_game_mode(
            {"mode": "auto", "active": True, "process": "eldenring.exe", "updated_ts": time.time()},
            target_paths=[gm_file],
        )
        dl = tmp_path / "dl"
        dl.mkdir()
        runner = ServiceRunner(
            data_dir=pd_dir,
            watch_dirs=[dl],
            alert_on="HIGH",
            notify=False,
            enable_mail=True,
        )
        snap = runner.run_once()
        assert snap["game_mode_active"] is True
        assert snap["imap_status"] == "deferred-game-mode"
    finally:
        settings_store.set_explicit(None)


def test_desktop_panel_server_security_and_endpoints(monkeypatch, tmp_path):
    from app import settings_store

    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "cfg"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "pd"))
    settings_store.set_explicit(None)

    ctrl = GameModeController(
        config_path=tmp_path / "cfg" / "game_mode_config.json",
        shared_paths=[tmp_path / "pd" / "game_mode.json"],
        detector=lambda _custom: {"detected": False, "process": "", "reason": "idle"},
    )
    srv = DesktopPanelServer(port=0, controller=ctrl, token="test-secret-token-123")
    srv.start()
    base = f"http://127.0.0.1:{srv.port}"
    hdr = {"X-ElfSec-Token": "test-secret-token-123"}

    try:
        # 1) Token olmadan erişim reddedilmeli
        st_no_tok, _, _ = _http_call(f"{base}/")
        assert st_no_tok == 403
        st_api_no_tok, _, _ = _http_call(f"{base}/api/status")
        assert st_api_no_tok == 403

        # 2) Doğru token ile ana sayfa + güvenlik başlıkları + gerçek ElfSec logosu + özel pencere kabuğu
        st_home, h_home, body_home = _http_call(f"{base}/?token=test-secret-token-123")
        assert st_home == 200
        assert "ElfSec" in body_home
        assert "byeco" in body_home
        assert "data:image/png;base64," in body_home
        assert "titlebar" in body_home
        assert "titlebarDrag" in body_home
        assert "data-win-drag" in body_home
        assert "btnWinMin" in body_home
        assert "btnWinMax" in body_home
        assert "btnWinClose" in body_home
        assert "statusbar" in body_home
        assert "\U0001f6e1" not in body_home
        assert "\U0001f3ae" not in body_home
        assert h_home.get("X-Frame-Options") == "DENY"

        # 2b) Pencere kontrol endpointleri (tarayıcı / yedek mod: window_controller=None)
        st_ws, _, raw_ws = _http_call(f"{base}/api/window/state", headers=hdr)
        assert st_ws == 200 and json.loads(raw_ws)["native"] is False
        st_wmin, _, raw_wmin = _http_call(f"{base}/api/window/minimize", method="POST", headers=hdr, body={})
        assert st_wmin == 200 and json.loads(raw_wmin)["native"] is False

        # 2c) Pencere kontrol endpointleri (sahte native denetleyici ile)
        class _FakeWindowCtrl:
            def __init__(self):
                self.minimized = False
                self.maximized = False
                self.pinned = False
                self.closed = False

            def get_state(self):
                return {"native": True, "maximized": self.maximized, "pinned": self.pinned}

            def minimize(self):
                self.minimized = True
                return self.get_state()

            def toggle_maximize(self):
                self.maximized = not self.maximized
                return self.get_state()

            def toggle_pin(self):
                self.pinned = not self.pinned
                return self.get_state()

            def begin_drag(self):
                return {"started": True, **self.get_state()}

            def move_by(self, dx, dy):
                self.last_move = (dx, dy)
                return self.get_state()

            def close(self):
                self.closed = True
                return {"closed": True}

        fake_ctrl = _FakeWindowCtrl()
        srv.window_controller = fake_ctrl
        assert json.loads(_http_call(f"{base}/api/window/state", headers=hdr)[2])["native"] is True
        assert json.loads(_http_call(f"{base}/api/window/toggle-maximize", method="POST", headers=hdr, body={})[2])["maximized"] is True
        assert json.loads(_http_call(f"{base}/api/window/pin", method="POST", headers=hdr, body={})[2])["pinned"] is True
        assert json.loads(_http_call(f"{base}/api/window/drag-start", method="POST", headers=hdr, body={})[2])["started"] is True
        assert json.loads(_http_call(f"{base}/api/window/move", method="POST", headers=hdr, body={"dx": 25, "dy": -10})[2])["native"] is True
        assert fake_ctrl.last_move == (25, -10)
        assert json.loads(_http_call(f"{base}/api/window/minimize", method="POST", headers=hdr, body={})[2])["native"] is True
        assert fake_ctrl.minimized is True
        st_wcls, _, raw_wcls = _http_call(f"{base}/api/window/close", method="POST", headers=hdr, body={})
        assert st_wcls == 200 and json.loads(raw_wcls)["closed"] is True
        time.sleep(0.12)
        assert fake_ctrl.closed is True
        srv.window_controller = None
        srv.stop_event.clear()

        # 3) Durum endpoint'i
        st_status, _, raw_status = _http_call(f"{base}/api/status", headers=hdr)
        assert st_status == 200
        d_status = json.loads(raw_status)
        assert d_status["ok"] is True and "service" in d_status and "game_mode" in d_status

        # 4) Metin / ClickFix taraması
        st_txt, _, raw_txt = _http_call(
            f"{base}/api/scan/text",
            method="POST",
            headers=hdr,
            body={"text": "powershell -w hidden -enc JAB4"},
        )
        assert st_txt == 200
        d_txt = json.loads(raw_txt)
        assert d_txt["report"]["clickfix_detected"] is True
        assert d_txt["report"]["risk_score"] >= 40

        # 5) Dosya taraması (sahte PDF MZ)
        evil = tmp_path / "fatura.pdf"
        evil.write_bytes(b"MZ\x90\x00\x03\x00fake-pe")
        st_path, _, raw_path = _http_call(
            f"{base}/api/scan/path",
            method="POST",
            headers=hdr,
            body={"path": str(evil)},
        )
        assert st_path == 200
        d_path = json.loads(raw_path)
        assert d_path["reports"][0]["risk_score"] >= 50

        # 6) Oyun modu API kontrolü
        st_gm, _, raw_gm = _http_call(
            f"{base}/api/game-mode",
            method="POST",
            headers=hdr,
            body={"action": "set_mode", "mode": "on"},
        )
        assert st_gm == 200 and json.loads(raw_gm)["game_mode"]["active"] is True

        st_gm2, _, raw_gm2 = _http_call(
            f"{base}/api/game-mode",
            method="POST",
            headers=hdr,
            body={"action": "add_game", "exe": "eldenring"},
        )
        assert st_gm2 == 200 and "eldenring.exe" in json.loads(raw_gm2)["game_mode"]["custom_games"]

        # 7) Alarmlar & Karantina listeleri + path traversal koruması
        assert _http_call(f"{base}/api/alerts", headers=hdr)[0] == 200
        assert _http_call(f"{base}/api/quarantine", headers=hdr)[0] == 200

        outside = tmp_path / "normal.txt"
        outside.write_text("dokunma", encoding="utf-8")
        st_trav, _, _ = _http_call(
            f"{base}/api/quarantine/action",
            method="POST",
            headers=hdr,
            body={"action": "delete", "path": str(outside)},
        )
        assert st_trav == 403 and outside.exists()

        # Gerçek karantinaya al + sil
        qrec = quarantine_file(evil, quarantine_dir=tmp_path / "cfg" / "quarantine")
        qpath = Path(qrec["quarantine_path"])
        assert qpath.exists()
        st_del, _, _ = _http_call(
            f"{base}/api/quarantine/action",
            method="POST",
            headers=hdr,
            body={"action": "delete", "path": str(qpath)},
        )
        assert st_del == 200 and not qpath.exists()
    finally:
        srv.stop()
        settings_store.set_explicit(None)


def test_cli_game_mode_status_json(monkeypatch, tmp_path, capsys):
    from app import settings_store

    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "cfg"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "pd"))
    settings_store.set_explicit(None)

    try:
        assert cli_main(["game-mode", "status", "--json"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["mode"] in ("auto", "on", "off")
        assert "cpu_priority" in out
    finally:
        settings_store.set_explicit(None)


def test_make_ico_and_installer_helpers(tmp_path):
    import struct
    import sys

    repo_root = Path(__file__).resolve().parents[2]
    scripts_dir = repo_root / "backend" / "scripts"
    installer_dir = repo_root / "installer"
    for d in (str(scripts_dir), str(installer_dir)):
        if d not in sys.path:
            sys.path.insert(0, d)

    from make_ico import build_ico
    from setup_wizard_gui import (
        APP_PUBLISHER,
        UNINSTALL_REG_PATH,
        build_uninstall_cmd,
        build_uninstall_reg_values,
    )

    icons_dir = repo_root / "extension" / "icons"
    pngs = [icons_dir / f"icon{sz}.png" for sz in (16, 32, 48, 128)]
    ico_out = tmp_path / "elfsec.ico"
    build_ico(pngs, ico_out)
    raw = ico_out.read_bytes()
    reserved, img_type, count = struct.unpack("<HHH", raw[:6])
    assert (reserved, img_type, count) == (0, 1, 4)

    vals = build_uninstall_reg_values(r"C:\Program Files\ElfSec")
    assert vals["Publisher"] == APP_PUBLISHER
    assert vals["DisplayIcon"].endswith("elfsec.ico")
    assert "uninstall.cmd" in vals["UninstallString"]

    cmd_txt = build_uninstall_cmd(r"C:\Program Files\ElfSec")
    assert "plugin uninstall" in cmd_txt
    assert UNINSTALL_REG_PATH in cmd_txt


def test_native_window_controller_state_transitions():
    import inspect

    from app.window_host import NativeWindowController, launch_native_window

    sig = inspect.signature(launch_native_window)
    assert sig.parameters["width"].default == 860
    assert sig.parameters["height"].default == 580
    assert sig.parameters["min_size"].default == (720, 500)

    class _MockWin:
        def __init__(self):
            self.on_top = False
            self.actions = []

        def minimize(self):
            self.actions.append("minimize")

        def maximize(self):
            self.actions.append("maximize")

        def restore(self):
            self.actions.append("restore")

        def destroy(self):
            self.actions.append("destroy")

    closed_flag = {"done": False}
    mw = _MockWin()
    ctrl = NativeWindowController(mw, on_close_cb=lambda: closed_flag.__setitem__("done", True))

    assert ctrl.get_state() == {"native": True, "maximized": False, "pinned": False}
    assert ctrl.toggle_maximize() == {"native": True, "maximized": True, "pinned": False}
    assert ctrl.toggle_maximize() == {"native": True, "maximized": False, "pinned": False}
    assert ctrl.toggle_pin() == {"native": True, "maximized": False, "pinned": True}
    assert mw.on_top is True
    assert ctrl.minimize() == {"native": True, "maximized": False, "pinned": True}
    assert ctrl.close() == {"closed": True}
    assert closed_flag["done"] is True
    assert mw.actions == ["maximize", "restore", "minimize", "destroy"]


def test_native_window_controller_work_area_preserves_taskbar(monkeypatch):
    from app import window_host

    class _FakeNative:
        Handle = 123456
        WindowState = "Normal"

    class _MockWin:
        native = _FakeNative()
        on_top = False

        def maximize(self):
            raise AssertionError("Win32 work-area kullanilmalidir")

        def restore(self):
            raise AssertionError("Win32 restore_rect kullanilmalidir")

    calls = []
    monkeypatch.setattr(window_host.os, "name", "nt")
    monkeypatch.setattr(window_host, "_get_window_rect", lambda hwnd: (100, 80, 860, 580))
    monkeypatch.setattr(window_host, "_get_monitor_work_area", lambda hwnd: (0, 0, 1920, 1032))
    monkeypatch.setattr(window_host, "_set_window_rect", lambda hwnd, rect: calls.append((hwnd, rect)) or True)
    monkeypatch.setattr(window_host, "_set_dwm_corner_round", lambda hwnd, rnd: calls.append(("corner", rnd)))

    ctrl = window_host.NativeWindowController(_MockWin())
    s1 = ctrl.toggle_maximize()
    assert s1["maximized"] is True
    assert calls[0] == (123456, (0, 0, 1920, 1032))
    assert calls[1] == ("corner", False)

    s2 = ctrl.toggle_maximize()
    assert s2["maximized"] is False
    assert calls[2] == (123456, (100, 80, 860, 580))
    assert calls[3] == ("corner", True)


def test_native_window_controller_drag_and_move_by(monkeypatch):
    from app import window_host

    class _FakeNative:
        Handle = 654321
        WindowState = "Normal"

    class _MockWin:
        native = _FakeNative()
        on_top = False

    events = []
    monkeypatch.setattr(window_host.os, "name", "nt")
    monkeypatch.setattr(window_host, "_get_window_rect", lambda hwnd: (200, 150, 860, 580))
    monkeypatch.setattr(window_host, "_get_monitor_work_area", lambda hwnd: (0, 0, 1920, 1032))
    monkeypatch.setattr(window_host, "_set_window_rect", lambda hwnd, rect: events.append(("rect", hwnd, rect)) or True)
    monkeypatch.setattr(window_host, "_set_dwm_corner_round", lambda hwnd, rnd: events.append(("corner", rnd)))
    monkeypatch.setattr(window_host, "_get_cursor_pos", lambda: (700, 12))
    monkeypatch.setattr(window_host, "_start_win32_drag", lambda hwnd, nf=None: events.append(("drag", hwnd)) or True)
    monkeypatch.setattr(window_host, "_move_window_to", lambda hwnd, x, y: events.append(("move", hwnd, x, y)) or True)

    ctrl = window_host.NativeWindowController(_MockWin())
    # Normal modda sürükleme doğrudan Win32 drag başlatır
    res1 = ctrl.begin_drag()
    assert res1["started"] is True and res1["maximized"] is False
    assert ("drag", 654321) in events

    # Büyütülmüşken sürüklenince önce eski boyuta döner sonra sürükler
    events.clear()
    ctrl.toggle_maximize()
    assert ctrl.is_maximized() is True
    res2 = ctrl.begin_drag()
    assert res2["started"] is True and res2["maximized"] is False
    assert any(e[0] == "rect" and e[2] == (270, 0, 860, 580) for e in events)
    assert ("drag", 654321) in events

    # Yedek move_by
    events.clear()
    ctrl.move_by(40, -20)
    assert ("move", 654321, 240, 130) in events


def test_kvkk_privacy_clipboard_and_kontrol_no_leak(monkeypatch, tmp_path):
    from app import settings_store
    from app.kontrol import run_kontrol
    from app.privacy import clear_alert_logs, load_privacy_settings, sanitize_alert_for_storage, save_privacy_settings
    from app.watchers.clipboard_guard import ClipboardGuard, analyze_clipboard_text

    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "cfg"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "pd"))
    settings_store.set_explicit(None)

    try:
        # 1) Arka plan pano izleme varsayılan kapalı, KVKK maskeleme açık
        pr = load_privacy_settings()
        assert pr["clipboard_auto_watch"] is False
        assert pr["kvkk_mask_logs"] is True

        pr2 = save_privacy_settings({"clipboard_auto_watch": True, "log_retention_days": 7})
        assert pr2["clipboard_auto_watch"] is True and pr2["log_retention_days"] == 7

        # 2) strict_kvkk=True ile normal/kişisel metinler taranmaz ve ham içerik saklanmaz
        g_def = ClipboardGuard()
        assert g_def.enabled is False and g_def.strict_kvkk is True

        normal_rep = analyze_clipboard_text("Hesabiniz kapanacak! IBAN TR120006200000000001234567", strict_kvkk=True)
        assert normal_rep["risk_score"] == 0 and normal_rep["risk_level"] == "LOW"
        assert "TR12" not in normal_rep["preview"] and "Hesabiniz" not in normal_rep["preview"]

        cf_rep = analyze_clipboard_text("powershell -w hidden -enc JAB4", strict_kvkk=True)
        assert cf_rep["clickfix_detected"] is True
        assert "powershell" not in cf_rep["preview"]

        # 3) Diske yazım öncesi KVKK veri minimizasyonu ve maskeleme
        safe = sanitize_alert_for_storage(
            {
                "source": "browser_webmail",
                "subject": "Hesap TR120006200000000001234567 ali@ornek.com",
                "sender": "Destek <ali@ornek.com>",
                "plain_text": "Gizli icerik 12345678901",
                "reasons": ["Gönderen ali@ornek.com"],
            },
            mask=True,
        )
        assert "plain_text" not in safe
        assert "ali@ornek.com" not in json.dumps(safe)
        assert "TR120006200000000001234567" not in json.dumps(safe)

        # 4) KONTROL WIN-09 artık gerçek guard_alerts.jsonl dosyasına test kaydı sızdırmamalı
        pd_log = settings_store.machine_data_dir() / "guard_alerts.jsonl"
        rep_k = run_kontrol(["WIN"])
        assert rep_k["fail"] == 0
        assert not pd_log.exists() or "Hesabiniz kapanacak!" not in pd_log.read_text(encoding="utf-8")

        # 5) Panel /api/privacy ve /api/alerts/clear endpointleri
        pd_log.parent.mkdir(parents=True, exist_ok=True)
        pd_log.write_text('{"risk_level":"HIGH","risk_score":80}\n', encoding="utf-8")
        ctrl = GameModeController(
            config_path=tmp_path / "cfg" / "gm.json",
            shared_paths=[tmp_path / "pd" / "gm.json"],
            detector=lambda _c: {"detected": False, "process": "", "reason": "idle"},
        )
        srv = DesktopPanelServer(port=0, controller=ctrl, token="kvkk-tok")
        srv.start()
        try:
            base = f"http://127.0.0.1:{srv.port}"
            hdr = {"X-ElfSec-Token": "kvkk-tok"}
            st_g, _, raw_g = _http_call(f"{base}/api/privacy", headers=hdr)
            assert st_g == 200 and json.loads(raw_g)["privacy"]["clipboard_auto_watch"] is True
            st_p, _, raw_p = _http_call(
                f"{base}/api/privacy", method="POST", headers=hdr, body={"clipboard_auto_watch": False}
            )
            assert st_p == 200 and json.loads(raw_p)["privacy"]["clipboard_auto_watch"] is False
            st_c, _, _ = _http_call(f"{base}/api/alerts/clear", method="POST", headers=hdr, body={})
            assert st_c == 200 and pd_log.read_text(encoding="utf-8") == ""
        finally:
            srv.stop()
            assert clear_alert_logs([pd_log]) >= 0
    finally:
        settings_store.set_explicit(None)


def test_desktop_ui_error_paths_kontrol_and_quarantine_restore(monkeypatch, tmp_path):
    from app import settings_store
    from app.privacy import load_privacy_settings, sanitize_alert_for_storage, save_privacy_settings

    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "cfg"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "pd"))
    settings_store.set_explicit(None)

    # Privacy edge-case'leri: bozuk JSON, retention sınırları, mask=False
    pfile = tmp_path / "cfg" / "ElfSec" / "privacy_settings.json"
    pfile.parent.mkdir(parents=True, exist_ok=True)
    pfile.write_text("{bozuk", encoding="utf-8")
    assert load_privacy_settings(pfile)["kvkk_mask_logs"] is True
    clamped = save_privacy_settings({"log_retention_days": 999}, path=pfile)
    assert clamped["log_retention_days"] == 90
    clamped_low = save_privacy_settings({"log_retention_days": -5}, path=pfile)
    assert clamped_low["log_retention_days"] == 1
    raw_clip = sanitize_alert_for_storage({"source": "clipboard", "preview": "gizli"}, mask=False)
    assert raw_clip["preview"] == "[KVKK: Ham pano içeriği saklanmadı]"

    ctrl = GameModeController(
        config_path=tmp_path / "cfg" / "gm.json",
        shared_paths=[tmp_path / "pd" / "gm.json"],
        detector=lambda _c: {"detected": False, "process": "", "reason": "idle"},
    )
    srv = DesktopPanelServer(port=0, controller=ctrl, token="edge-tok")
    srv.start()
    base = f"http://127.0.0.1:{srv.port}"
    hdr = {"X-ElfSec-Token": "edge-tok"}
    try:
        # 400 / 404 hata yolları
        assert _http_call(f"{base}/api/bilinmeyen", headers=hdr)[0] == 404
        assert _http_call(f"{base}/api/bilinmeyen", method="POST", headers=hdr, body={})[0] == 404
        assert _http_call(f"{base}/api/scan/text", method="POST", headers=hdr, body={"text": "   "})[0] == 400
        assert _http_call(f"{base}/api/scan/path", method="POST", headers=hdr, body={"path": ""})[0] == 400
        assert _http_call(f"{base}/api/scan/path", method="POST", headers=hdr, body={"path": str(tmp_path / "yok.txt")})[0] == 404
        assert _http_call(f"{base}/api/game-mode", method="POST", headers=hdr, body={"action": "bad"})[0] == 400
        assert _http_call(f"{base}/api/quarantine/action", method="POST", headers=hdr, body={"action": "bad", "path": "x"})[0] == 400
        assert _http_call(f"{base}/api/quarantine/action", method="POST", headers=hdr, body={"action": "quarantine", "path": ""})[0] == 400
        assert _http_call(f"{base}/api/quarantine/action", method="POST", headers=hdr, body={"action": "quarantine", "path": str(tmp_path / "yok.bin")})[0] == 404

        # Kontrol, downloads, clipboard tarama
        st_k, _, raw_k = _http_call(f"{base}/api/kontrol", headers=hdr)
        assert st_k == 200 and json.loads(raw_k)["ok"] is True
        st_dl, _, raw_dl = _http_call(f"{base}/api/scan/downloads", method="POST", headers=hdr, body={})
        assert st_dl == 200 and "scanned_count" in json.loads(raw_dl)
        st_cb, _, raw_cb = _http_call(f"{base}/api/scan/clipboard", method="POST", headers=hdr, body={})
        assert st_cb == 200 and json.loads(raw_cb)["ok"] is True

        # Karantina + geri yükleme
        sample = tmp_path / "rapor.ps1"
        sample.write_text("powershell -w hidden -enc JAB4", encoding="utf-8")
        st_q, _, raw_q = _http_call(
            f"{base}/api/quarantine/action",
            method="POST",
            headers=hdr,
            body={"action": "quarantine", "path": str(sample)},
        )
        assert st_q == 200
        qpath = json.loads(raw_q)["record"]["quarantine_path"]
        assert Path(qpath).exists() and not sample.exists()

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        st_res, _, raw_res = _http_call(
            f"{base}/api/quarantine/action",
            method="POST",
            headers=hdr,
            body={"action": "restore", "path": qpath},
        )
        assert st_res == 200 and Path(json.loads(raw_res)["restored_to"]).exists()

        # Shutdown
        st_sd, _, raw_sd = _http_call(f"{base}/api/shutdown", method="POST", headers=hdr, body={})
        assert st_sd == 200 and json.loads(raw_sd)["ok"] is True
        assert srv.stop_event.is_set()
    finally:
        srv.stop()
        settings_store.set_explicit(None)


def test_window_host_helpers_and_fallbacks(monkeypatch, tmp_path):
    import threading

    from app import window_host

    ico = window_host._find_elfsec_ico()
    assert ico is None or ico.name == "elfsec.ico"

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    st_dir = window_host._webview_storage_dir()
    assert st_dir.exists() and st_dir.name == "webview2"

    class _DummySrv:
        url = "http://127.0.0.1:1234/?token=x"
        stop_event = threading.Event()
        window_controller = None

    # Fallback env aktifken False dönmeli
    monkeypatch.setenv("ELFSEC_UI_BROWSER_FALLBACK", "1")
    assert window_host.launch_native_window(_DummySrv()) is False
    monkeypatch.delenv("ELFSEC_UI_BROWSER_FALLBACK", raising=False)

    # Main thread dışında False dönmeli
    box = {"res": None}
    t = threading.Thread(target=lambda: box.__setitem__("res", window_host.launch_native_window(_DummySrv())))
    t.start()
    t.join()
    assert box["res"] is False

    # Non-Windows koruma yolları
    monkeypatch.setattr(window_host.os, "name", "posix")
    assert window_host._get_cursor_pos() is None
    assert window_host._get_window_rect(1) is None
    assert window_host._get_monitor_work_area(1) is None
    assert window_host._set_window_rect(1, (0, 0, 100, 100)) is False
    assert window_host._move_window_to(1, 10, 10) is False
    assert window_host._start_win32_drag(1) is False

