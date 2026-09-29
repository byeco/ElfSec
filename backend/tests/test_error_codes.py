"""Exit-code sözleşmesi + loop-hata testleri (hata yutma yasak).

Sözleşme: 0 = temiz, 1 = şüpheli (--fail-on), 2 = kullanım/ortam hatası.
"""

import argparse
import json

from app import cli as cli_mod
from app.cli import _load_seen, _log_guard_error, _safe_notify, main as cli_main


def _guard_args(**kw):
    base = dict(folder="INBOX", limit=5, unseen=True, interval=10, alert_on="HIGH",
                alert_log="", state="", webhook="", once=True, quiet=True,
                fail_on="NEVER", tray=False, background=False, notify="off",
                action="notify-only", quarantine_folder="Junk", quarantine_log="")
    base.update(kw)
    return argparse.Namespace(**base)


def test_guard_once_imap_hatasi_exit_2(monkeypatch, tmp_path):
    """Loop hatası 'temiz' gibi raporlanmaz: guard --once + IMAP çökerse exit 2."""
    async def _boom(*a, **k):
        raise OSError("baglanti koptu")
    # _fetch_and_analyze her çağrıda `from ... import fetch_emails` yapar — modül yaması etkili.
    import app.services.imap_client as im
    monkeypatch.setattr(im, "fetch_emails", _boom)
    code = cli_main(["guard", "--once", "--quiet", "--notify", "off",
                     "--state", str(tmp_path / "seen.json")])
    assert code == 2


def test_config_test_baglanti_hatasi_exit_2(monkeypatch, tmp_path):
    """config test IMAP bağlanamazsa exit 2 (ortam hatası), 1 değil."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("IMAP_USER=a@b.com\nIMAP_PASSWORD=x\n", encoding="utf-8")
    import app.services.imap_client as im
    async def _boom(*a, **k):
        raise OSError("auth failed")
    monkeypatch.setattr(im, "list_folders", _boom)
    code = cli_main(["config", "test"])
    assert code == 2


def test_bos_analyze_exit_2():
    assert cli_main(["analyze", "--body", "   ", "--quiet"]) == 2


def test_kayip_dosya_exit_2():
    assert cli_main(["analyze-file", "--path", "yok-boyle-dosya-999.eml", "--quiet"]) == 2


def test_gecersiz_folder_exit_2():
    assert cli_main(["fetch", "--folder", "../INBOX", "--quiet"]) == 2
    assert cli_main(["triage", "--folder", "../INBOX", "--quiet"]) == 2


def test_limit_araligi_exit_2():
    assert cli_main(["fetch", "--limit", "0", "--quiet"]) == 2
    assert cli_main(["fetch", "--limit", "9999", "--quiet"]) == 2


def test_interval_min_exit_2():
    assert cli_main(["guard", "--interval", "0", "--once", "--quiet"]) == 2


def test_bozuk_state_yedeklenir(tmp_path):
    f = tmp_path / "seen.json"
    f.write_text("{bozuk json", encoding="utf-8")
    assert _load_seen(str(f)) == set()
    assert not f.exists()  # yedeğe taşındı
    yedekler = list(tmp_path.glob("seen.json.bozuk-*"))
    assert len(yedekler) == 1
    assert yedekler[0].read_text(encoding="utf-8") == "{bozuk json"


def test_safe_notify_yutmaz(tmp_path, capsys):
    """Bildirim altyapısı ölse bile stderr + guard_errors.jsonl iz bırakır."""
    import app.notify as n
    def _boom(*a, **k):
        raise RuntimeError("toast öldü")
    import unittest.mock as mock
    with mock.patch.object(n, "toast", side_effect=_boom):
        ok = _safe_notify("error", "deneme", str(tmp_path / "seen.json"))
    assert ok is False
    err = capsys.readouterr().err
    assert "bildirim hatası" in err
    log = tmp_path / "guard_errors.jsonl"
    assert log.exists()
    assert "toast öldü" in log.read_text(encoding="utf-8")


def test_log_guard_error_yazar(tmp_path):
    _log_guard_error(str(tmp_path / "s.json"), "cycle-imap", "test hatası")
    log = tmp_path / "guard_errors.jsonl"
    assert log.exists()
    row = json.loads(log.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert row["kind"] == "cycle-imap"


def _config_izole(monkeypatch, tmp_path):
    """Gerçek kimlik sızmasın: tüm config katmanları boşa al (deterministik)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.delenv("ELFSEC_CONFIG", raising=False)
    from app import settings_store
    settings_store.set_explicit(None)
    return settings_store


def test_fetch_and_analyze_tur_donusumu(monkeypatch, tmp_path):
    _config_izole(monkeypatch, tmp_path)
    reports, err, kind, skipped = cli_mod._fetch_and_analyze("INBOX", 5, True)
    assert isinstance(reports, list) and isinstance(skipped, int)
    assert kind in ("", "config", "imap")
    if err:
        assert kind in ("config", "imap")


def test_guard_cycle_status_dondurur(monkeypatch, tmp_path):
    _config_izole(monkeypatch, tmp_path)
    args = _guard_args()
    alarms, worst, seen, status = cli_mod._guard_cycle(args, set())
    assert status in ("ok", "error-config", "error-imap")
    if status != "ok":
        assert alarms == 0 and worst == "LOW"
