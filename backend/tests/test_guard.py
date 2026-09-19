"""Guard (sürekli koruma) yardımcılarının testi — IMAP'siz, saf fonksiyonlar."""

from app.cli import _load_seen, _save_seen, should_alert


def test_should_alert_esigi():
    assert should_alert({"risk_level": "HIGH"}, "HIGH") is True
    assert should_alert({"risk_level": "CRITICAL"}, "HIGH") is True
    assert should_alert({"risk_level": "MEDIUM"}, "HIGH") is False
    assert should_alert({"risk_level": "LOW"}, "LOW") is True


def test_seen_state_dosyasi(tmp_path):
    f = tmp_path / "seen.json"
    assert _load_seen(str(f)) == set()
    _save_seen(str(f), {"100", "101"})
    assert _load_seen(str(f)) == {"100", "101"}
    _save_seen(str(f), {"102"})
    assert _load_seen(str(f)) == {"102"}
