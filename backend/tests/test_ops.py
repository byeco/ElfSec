"""v0.6.0 kurumsal operasyon: kurallar + CEF + log + update."""

import json

from app import rules as R
from app.cef import to_cef
from app.cli import main as cli_main
from app.services.ai_analyzer import local_analyze


def _izole_tmp(monkeypatch, tmp_path):
    # APPDATA yalnız Windows'ta okunur; Linux'ta gerçek ~/.config'e yazılırdı.
    # ELFSEC_CONFIG_DIR her platformda geçerli (rules.py + settings_store.py).
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path))
    R._CACHE.update(mtime=0.0, rules={})


def test_rules_path_izolasyon(monkeypatch, tmp_path):
    """ELFSEC_CONFIG_DIR her platformda rules.json yolunu belirler (CI/Linux regresyonu)."""
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path / "cfg"))
    assert R.rules_path() == tmp_path / "cfg" / "rules.json"


def test_rules_varsayilan():
    r = R.load_rules()
    assert r["phishing_pattern"]["weight"] == 25
    assert len(r) >= 20


def test_rules_disable_sifirlar():
    rules = {k: dict(v) for k, v in R.DEFAULT_RULES.items()}
    rules["urgency"]["enabled"] = False
    out = local_analyze("hemen şimdi son gün", "bilgi", [], "a@b.com", None, None, rules)
    assert not any("Aciliyet" in x for x in out["reasons"])


def test_rules_agirlik_gecerli():
    rules = {k: dict(v) for k, v in R.DEFAULT_RULES.items()}
    rules["urgency"]["weight"] = 40
    out = local_analyze("hemen şimdi", "bilgi", [], "a@b.com", None, None, rules)
    assert out["risk_score"] >= 40


def test_rules_cli_show_set_reset(monkeypatch, tmp_path, capsys):
    _izole_tmp(monkeypatch, tmp_path)
    assert cli_main(["rules", "show"]) == 0
    assert "phishing_pattern" in capsys.readouterr().out
    assert cli_main(["rules", "set", "urgency", "33"]) == 0
    assert cli_main(["rules", "disable", "urgency"]) == 0
    data = json.loads((tmp_path / "rules.json").read_text(encoding="utf-8"))
    assert data["urgency"] == {"weight": 33, "enabled": False}
    assert cli_main(["rules", "enable", "urgency"]) == 0
    assert cli_main(["rules", "reset"]) == 0
    assert cli_main(["rules", "set", "yok-boyle-kural", "5"]) == 2


def test_cef_formati():
    line = to_cef({"risk_level": "HIGH", "risk_score": 70, "sender": "a@b|com",
                   "subject": "fatura", "summary": "x", "uid": "5",
                   "phishing_detected": True})
    assert line.startswith("CEF:0|ElfSec|elfsec|")
    assert "|8|" in line and "elfsec-phish" in line
    assert "a@b\\|com" in line


def test_log_dosyasi(tmp_path):
    from app.log import close_logger, get_logger
    lg = get_logger("testguard", str(tmp_path / "elfsec.log"))
    lg.warning("deneme %s", 1)
    for h in lg.handlers:
        h.flush()
    assert "deneme 1" in (tmp_path / "elfsec.log").read_text(encoding="utf-8")
    close_logger("testguard")


def test_update_cevrimdisi_guvenli(monkeypatch):
    import urllib.request

    def _boom(*a, **k):
        raise OSError("ağ yok")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    assert cli_main(["update", "--check"]) == 0  # bilgi komutu, kapı değil


def test_guard_redact_mock(monkeypatch, tmp_path):
    import json as _json

    import app.cli as C
    import app.services.imap_client as im

    monkeypatch.setattr(C, "_imap_auth", lambda s: ("pw", "", "sifre"))

    async def _fake_fetch(p):
        return [{"uid": "9", "subject": "Hesabiniz kapanacak",
                 "from": "destek@evil.tk", "to": "ben@ornek.com", "date": "",
                 "body": "<p>hemen tikla http://evil.tk/verify sifrenizi gonderin</p>",
                 "headers": {}, "attachments": []}]

    monkeypatch.setattr(im, "fetch_emails", _fake_fetch)
    log = tmp_path / "alerts.jsonl"
    code = cli_main(["guard", "--once", "--quiet", "--notify", "off",
                     "--alert-log", str(log), "--fail-on", "HIGH",
                     "--state", str(tmp_path / "seen.json"),
                     "--redact", "--retention-days", "30"])
    assert code == 1
    text = log.read_text(encoding="utf-8")
    assert "destek@evil.tk" not in text and "***" in text


def test_triage_cef_mock(monkeypatch, tmp_path):
    import app.cli as C
    import app.services.imap_client as im

    monkeypatch.setattr(C, "_imap_auth", lambda s: ("pw", "", "sifre"))

    async def _fake_fetch(p):
        return [{"uid": "7", "subject": "Hesabiniz kapanacak",
                 "from": "x@evil.tk", "to": "", "date": "",
                 "body": "<p>hemen tikla http://evil.tk/verify sifrenizi gonderin</p>",
                 "headers": {}, "attachments": []}]

    monkeypatch.setattr(im, "fetch_emails", _fake_fetch)
    cef = tmp_path / "out.cef"
    code = cli_main(["triage", "--limit", "5", "--quiet", "--cef", str(cef),
                     "--fail-on", "MEDIUM"])
    assert code == 1
    text = cef.read_text(encoding="utf-8")
    assert text.startswith("CEF:0|ElfSec|") and "|7|" not in text  # şiddet alanı
    assert "elfsec-phish" in text
