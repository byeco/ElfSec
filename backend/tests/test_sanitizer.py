"""Güvenlik testleri: temizlik katmanı delinmemeli."""

from app.services.sanitizer import sanitize_email


def test_script_ve_img_atilir():
    r = sanitize_email('<script>alert(1)</script><p>selam</p><img src="http://x/track" width="1" height="1">')
    assert "<script" not in r["safe_html"]
    assert "<img" not in r["safe_html"]
    assert "selam" in r["plain_text"]
    assert r["tracking_pixels_blocked"] >= 1


def test_javascript_url_kesilir():
    r = sanitize_email('<a href="javascript:alert(1)">tikla</a>')
    assert "javascript:" not in r["safe_html"]


def test_takip_linki_tiklanamaz_yapilir():
    r = sanitize_email('<a href="http://evil.com/open-track">t</a>')
    assert "open-track" not in r["safe_html"] or "<a" not in r["safe_html"]
    assert "http://evil.com/open-track" in r["urls"]  # analiz için korunur


def test_duz_metin_cikarimi():
    r = sanitize_email("<h1>Baslik</h1><p>Govde <b>kalin</b></p>")
    assert "Baslik" in r["plain_text"] and "kalin" in r["plain_text"]


def test_safe_html_govde_parcasi_tam_belge_degil():
    r = sanitize_email("<p>selam <a href='https://ornek.com'>link</a></p>")
    assert "<html" not in r["safe_html"].lower()
    assert 'rel="noopener noreferrer nofollow"' in r["safe_html"]


def test_dev_girdi_kirpilir():
    from app.services.sanitizer import MAX_INPUT

    r = sanitize_email("x" * (MAX_INPUT + 1000))
    assert len(r["plain_text"]) <= MAX_INPUT
