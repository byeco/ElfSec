"""v0.5.0 ek analizi + URL istihbaratı testleri (çevrimdışı)."""

from app.cli import main as cli_main
from app.services.ai_analyzer import _attachments_score, _mixed_script, local_analyze
from app.urlintel import expand_url, maybe_expand


def test_cift_uzanti():
    s, r = _attachments_score([{"filename": "fatura.pdf.exe", "size": 100, "content_type": "x"}])
    assert s >= 25 and any("Çift uzantı" in x for x in r)


def test_riskli_ek():
    s, r = _attachments_score([{"filename": "kurulum.exe", "size": 204800, "content_type": "x"}])
    assert s >= 20


def test_makro_ek():
    s, r = _attachments_score([{"filename": "bordro.docm", "size": 5000, "content_type": "x"}])
    assert s >= 15 and any("Makro" in x for x in r)


def test_arsiv_ek():
    s, _ = _attachments_score([{"filename": "belgeler.zip", "size": 1000, "content_type": "x"}])
    assert s >= 8


def test_temiz_ek_cezasiz():
    s, _ = _attachments_score([{"filename": "foto.jpg", "size": 1000, "content_type": "x"}])
    assert s == 0
    s2, _ = _attachments_score(None)
    assert s2 == 0


def test_mixed_script():
    assert _mixed_script("pаypal.com") is True  # a Kiril
    assert _mixed_script("paypal.com") is False
    assert _mixed_script("") is False


def test_mixed_script_skor():
    r = local_analyze("t", "b", ["http://pаypal.com/login"], "a@b.com")
    assert r["risk_score"] >= 25
    assert any("homoglif" in x for x in r["reasons"])


def test_url_anahtar_kelime():
    r = local_analyze("t", "b", ["https://ornek.com/bank-login"], "a@b.com")
    assert any("anahtar kelime" in x for x in r["reasons"])


def test_maybe_expand_kapali():
    urls, mapping = maybe_expand(["https://bit.ly/x"], False)
    assert urls == ["https://bit.ly/x"] and mapping == {}


def test_maybe_expand_kisa_degilse_dokunmaz():
    urls, mapping = maybe_expand(["https://ornek.com/a"], True)
    assert urls == ["https://ornek.com/a"] and mapping == {}


def test_expand_url_hatada_girdi():
    assert expand_url("http://127.0.0.1:9/yok", timeout=1) == "http://127.0.0.1:9/yok"


def test_ek_uctan_uca():
    r = local_analyze("fatura", "ekte", [], "a@b.com", None,
                      [{"filename": "fatura.pdf.exe", "size": 10, "content_type": "x"}])
    assert r["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_cli_expand_bayragi():
    code = cli_main(["analyze", "--subject", "t", "--sender", "a@b.com",
                     "--body", "merhaba", "--quiet"])
    assert code == 0
