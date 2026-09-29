"""v0.7.0: butonlu toast + quarantine komutu + webhook retry + PII + 0600."""

import argparse
import urllib.request

from app import cli as C
from app.cli import main as cli_main
from app.notify import build_toast_xml


def _guard_args(**kw):
    base = dict(folder="INBOX", limit=5, unseen=True, interval=10, alert_on="HIGH",
                alert_log="", state="", webhook="", webhook_header=[], once=True, quiet=True,
                fail_on="NEVER", tray=False, background=False, notify="off",
                action="notify-only", quarantine_folder="Junk", quarantine_log="",
                expand_urls=False, cef_log="", redact=False, retention_days=0)
    base.update(kw)
    return argparse.Namespace(**base)


def test_toast_xml_butonlu():
    xml = build_toast_xml("ALARM", "konu", [("Karantinaya al", "elfsec:quarantine?uid=9"),
                                            ("Yoksay", "dismiss")])
    assert "activationType=\"protocol\"" in xml
    assert "elfsec:quarantine?uid=9" in xml
    assert "activationType=\"system\"" in xml
    assert xml.startswith("<toast>") and xml.endswith("</toast>")


def test_toast_xml_butonsuz():
    xml = build_toast_xml("T", "M")
    assert "<actions>" not in xml


def test_toast_xml_enjeksiyon():
    xml = build_toast_xml("A", "<script>", [("X\"y", "elfsec:quarantine?uid=1\"on")])
    assert "<script>" not in xml


def test_protocol_parse():
    assert C.parse_protocol_uri("elfsec:quarantine?uid=123") == ("quarantine", {"uid": "123"})
    assert C.parse_protocol_uri("elfsec:delete?uid=7") == ("delete", {"uid": "7"})
    assert C.parse_protocol_uri("guard") is None
    assert C.parse_protocol_uri("elfsec:quarantine") is None  # uid yok
    assert C.parse_protocol_uri("elfsec:reboot?uid=1") is None  # bilinmeyen aksiyon


def test_quarantine_uid_bos():
    assert cli_main(["quarantine", ""]) == 2


def test_quarantine_delete_yes_gerekli():
    assert cli_main(["quarantine", "5", "--action", "delete"]) == 2


def test_quarantine_imapsiz_exit_2(monkeypatch, tmp_path):
    # Tüm config katmanlarını izole et (gerçek ~/.env/APPDATA sızmasın).
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.delenv("ELFSEC_CONFIG", raising=False)
    from app import settings_store
    settings_store.set_explicit(None)
    try:
        assert cli_main(["quarantine", "5", "--folder", "INBOX"]) == 2
    finally:
        settings_store.set_explicit(None)


def test_webhook_retry_sonunda_basarili(monkeypatch):
    calls = {"n": 0}

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"ok"

    def _fake_open(req, timeout=10):
        calls["n"] += 1
        if calls["n"] < 3:
            raise OSError("ağ koptu")
        assert req.get_header("Authorization") == "Bearer X"
        return FakeResp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_open)
    monkeypatch.setattr("time.sleep", lambda s: None)
    C._notify_webhook("https://ornek/kanca", {"a": 1},
                      {"Authorization": "Bearer X"}, retries=3)
    assert calls["n"] == 3


def test_webhook_retry_tukenirse_firlatir(monkeypatch):
    def _boom(req, timeout=10):
        raise OSError("sürekli kopuk")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    monkeypatch.setattr("time.sleep", lambda s: None)
    try:
        C._notify_webhook("https://ornek/kanca", {"a": 1}, None, retries=2)
        assert False, "hata bekleniyordu"
    except OSError:
        pass


def test_parse_extra_headers():
    assert C._parse_extra_headers(["Authorization: Bearer X", "bozuk-satır", "  : "]) == {
        "Authorization": "Bearer X"}


def test_redact_email():
    from app.redact import mask_email, mask_secrets, redact_report

    assert mask_email("ad.soyad@gmail.com") == "a***@g***l.com"
    assert mask_email("x") == "x"
    t = mask_secrets("iban TR12 3456 7890 1234 5678 9012 34 ve 10000000000")
    assert "TR12" not in t and "10000000000" not in t
    r = redact_report({"from": "a@b.com", "subject": "s", "snippet": "a@b.com selam"})
    assert r["from"] == "a@b***.com" or "@" in r["from"] and "***" in r["from"]
    assert "a@b.com" not in r["snippet"]


def test_prune_jsonl(tmp_path):
    from app.redact import prune_jsonl

    f = tmp_path / "a.jsonl"
    f.write_text('{"alerted_at": "2000-01-01 00:00:00", "x": 1}\n'
                 '{"alerted_at": "2999-01-01 00:00:00", "x": 2}\n'
                 'bozuk-satır\n', encoding="utf-8")
    assert prune_jsonl(str(f), 30) == 1
    assert len(f.read_text(encoding="utf-8").splitlines()) == 2


def test_upsert_kv_cokmez_0600(tmp_path):
    from app.settings_store import config_mode, upsert_kv

    p = tmp_path / "t.env"
    upsert_kv(p, "IMAP_HOST", "imap.gmail.com")
    upsert_kv(p, "IMAP_HOST", "imap.gmail.com")  # güncelleme yolu
    assert p.exists()
    assert config_mode(p) != -1


def test_exe_modu_skip(monkeypatch):
    import app.kontrol as K

    monkeypatch.setattr(K, "EXE_MODU", True)
    r = K.run_kontrol(["SURUM"])
    by_id = {b["id"]: b for b in r["bulgular"]}
    assert by_id["SURUM-02"]["durum"] == "SKIP"
    assert by_id["SURUM-03"]["durum"] == "SKIP"
    assert by_id["SURUM-04"]["durum"] == "SKIP"
    assert r["worst"] == "PASS"  # SKIP worst'e katılmaz
    assert r["skipped"] >= 3
    assert r["yol_haritasi"] == {}
