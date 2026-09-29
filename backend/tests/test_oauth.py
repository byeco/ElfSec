"""OAuth2 (outlook+gmail) sözleşme testleri — ağ yok, her şey mock."""

import argparse
import types
import urllib.request

from app import oauth as O
from app.cli import _imap_auth, main as cli_main
from app.config import Settings


def _s(**kw):
    base = dict(imap_host="imap.gmail.com", imap_user="a@b.com", imap_password="",
                oauth_provider="", ms_client_id="", google_client_id="",
                oauth_refresh_outlook="", oauth_refresh_gmail="")
    base.update(kw)
    return Settings(**base)


def test_detect_provider():
    assert O.detect_provider("outlook.office365.com") == "outlook"
    assert O.detect_provider("imap.gmail.com") == "gmail"
    assert O.detect_provider("imap.ornek.com") == ""


def test_auth_url_icerigi():
    u = O.build_auth_url("gmail", "cid123", 8080, "st")
    assert "cid123" in u and "access_type=offline" in u and "127.0.0.1" in u
    u2 = O.build_auth_url("outlook", "cid9", 8081, "st")
    assert "cid9" in u2 and "IMAP.AccessAsUser.All" in u2


def test_resolve_bos():
    assert O.resolve_access_token(_s()) == ("", "")


def test_resolve_refresh_ok(monkeypatch):
    monkeypatch.setattr(O, "refresh_access_token", lambda *a: {"access_token": "AT123"})
    p, t = O.resolve_access_token(_s(oauth_provider="gmail", google_client_id="c",
                                     oauth_refresh_gmail="R"))
    assert (p, t) == ("gmail", "AT123")


def test_resolve_refresh_bozuk(monkeypatch):
    def _boom(*a):
        raise OSError("invalid_grant")
    monkeypatch.setattr(O, "refresh_access_token", _boom)
    try:
        O.resolve_access_token(_s(oauth_provider="outlook", ms_client_id="c",
                                  oauth_refresh_outlook="R"))
        assert False, "OSError bekleniyordu"
    except OSError as e:
        assert "config login" in str(e)


def test_imap_auth_oauth_oncelikli(monkeypatch):
    monkeypatch.setattr(O, "resolve_access_token", lambda s: ("outlook", "AT"))
    import app.cli as C
    monkeypatch.setattr(C, "resolve_access_token", lambda s: ("outlook", "AT"), raising=False)
    pw, tok, y = _imap_auth(_s())
    assert (pw, tok, y) == ("", "AT", "oauth:outlook")


def test_imap_auth_sifre_yolu():
    pw, tok, y = _imap_auth(_s(imap_password="gizli"))
    assert (pw, tok, y) == ("gizli", "", "sifre")


def test_xoauth2_kullanilir(monkeypatch):
    """oauth_token doluysa login değil xoauth2 çağrılmalı."""
    import app.services.imap_client as im
    calls = {}

    class FakeBox:
        def __init__(self, *a, **k):
            pass

        def xoauth2(self, user, token, initial_folder="INBOX"):
            calls["xoauth2"] = (user, token, initial_folder)
            return self

        def login(self, *a, **k):
            calls["login"] = True
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def fetch(self, *a, **k):
            m = types.SimpleNamespace(uid=1, subject="s", from_="a@b.com", to=[],
                                      date=None, html="", text="merhaba")
            return [m]

    monkeypatch.setattr(im, "MailBox", FakeBox)
    out = im._fetch_sync(im.FetchParams(host="h", user="u", oauth_token="AT"))
    assert calls.get("xoauth2") == ("u", "AT", "INBOX")
    assert "login" not in calls
    assert out[0]["uid"] == "1"


def test_exchange_post_formu(monkeypatch):
    seen = {}

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"access_token": "A", "refresh_token": "R"}'

    def _fake_open(req, timeout=30):
        seen["url"] = req.full_url
        seen["body"] = req.data.decode()
        return FakeResp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_open)
    r = O.exchange_code("gmail", "cid", 9999, "kod123")
    assert r["refresh_token"] == "R"
    assert "kod123" in seen["body"] and "127.0.0.1" in seen["body"]


def test_cli_logout_tmp_config(tmp_path):
    cfg = str(tmp_path / "test.env")
    assert cli_main(["--config", cfg, "config", "logout", "--provider", "gmail"]) == 0
    text = open(cfg, encoding="utf-8").read()
    assert "OAUTH_REFRESH_GMAIL=" in text
