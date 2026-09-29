"""KONTROL sözleşmesi: sızma testleri çökmez, rapor şeması sabittir."""

from app.cli import main as cli_main
from app.kontrol import run_kontrol


def test_kontrol_sema():
    r = run_kontrol(["TEMIZLE", "ANALIZ"])
    assert set(r) >= {"worst", "toplam", "fail", "warn", "bulgular", "yol_haritasi", "version"}
    assert r["toplam"] > 10
    for b in r["bulgular"]:
        assert set(b) >= {"id", "kategori", "durum", "surum", "oneri"}
        assert b["durum"] in ("PASS", "WARN", "FAIL")


def test_kontrol_xss_kapali():
    r = run_kontrol(["TEMIZLE"])
    by_id = {b["id"]: b for b in r["bulgular"]}
    for pid in ("XSS-01 script", "XSS-02 img-onerror", "XSS-03 javascript:", "XSS-04 data:"):
        assert by_id[pid]["durum"] == "PASS", pid


def test_cli_kontrol_exit():
    code = cli_main(["kontrol", "--kategori", "TEMIZLE,ANALIZ", "--quiet", "--fail-on", "NEVER"])
    assert code == 0
