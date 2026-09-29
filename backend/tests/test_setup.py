"""Kolay kurulum sihirbazı testleri — ağ yok, IO/test/kayıt sahtesi."""

from app import setup_wizard as W
from app.cli import main as cli_main


class FakeIO(W.IO):
    def __init__(self, answers=None, secrets=None):
        self._answers = list(answers or [])
        self._secrets = list(secrets or [])
        self.shown = []
        self.browsed = []
        super().__init__(ask=self._ask, tell=self.shown.append,
                         ask_secret=self._secret, open_browser=self._browse)

    def _ask(self, prompt):
        self.shown.append(prompt)
        assert self._answers, f"beklenmeyen soru: {prompt}"
        return self._answers.pop(0)

    def _secret(self, prompt):
        self.shown.append(prompt)
        assert self._secrets, f"beklenmeyen gizli soru: {prompt}"
        return self._secrets.pop(0)

    def _browse(self, url):
        self.browsed.append(url)
        return True


def _saver(store):
    def _save(key, value, secret):
        store[key] = (value, secret)
    return _save


def test_provider_tespiti():
    assert W.detect_provider_by_email("a@gmail.com") == "gmail"
    assert W.detect_provider_by_email("a@googlemail.com") == "gmail"
    assert W.detect_provider_by_email("a@hotmail.com") == "outlook"
    assert W.detect_provider_by_email("a@live.com") == "outlook"
    assert W.detect_provider_by_email("a@yahoo.com.tr") == "yahoo"
    assert W.detect_provider_by_email("a@yandex.com.tr") == "yandex"
    assert W.detect_provider_by_email("a@icloud.com") == "icloud"
    assert W.detect_provider_by_email("a@sirket.com") == ""
    assert W.detect_provider_by_email("gecersiz") == ""


def test_preset_butunlugu():
    for key, p in W.PRESETS.items():
        assert p["imap_host"] and p["imap_port"] == 993
        assert p["app_password_url"].startswith("https://")
        assert len(p["steps"]) >= 2 and p["notes"]


def test_hata_siniflandirma():
    assert W.classify_error(OSError("MailboxLoginError: AUTHENTICATIONFAILED"))[0] == "auth"
    assert W.classify_error(OSError("Username and password not accepted"))[0] == "auth"
    assert W.classify_error(TimeoutError("timed out"))[0] == "network"
    assert W.classify_error(OSError("getaddrinfo failed"))[0] == "network"
    assert W.classify_error(OSError("SSL: CERTIFICATE_VERIFY_FAILED"))[0] == "tls"
    assert W.classify_error(ValueError("tuhaf"))[0] == "unknown"


def test_basari_ilk_deneme():
    store, io = {}, FakeIO(secrets=["abcd efgh ijkl mnop"])
    code = W.run_setup(email="a@gmail.com", method="app-password", io=io,
                       do_test=lambda h, u, p, port: ["INBOX", "Spam"],
                       do_save=_saver(store), no_browser=True)
    assert code == 0
    assert store["IMAP_HOST"] == ("imap.gmail.com", False)
    assert store["IMAP_USER"] == ("a@gmail.com", False)
    assert store["IMAP_PASSWORD"] == ("abcdefghijklmnop", True)  # boşluksuz
    assert any("2 klasör" in s for s in io.shown)


def test_retry_sonra_basari():
    calls = {"n": 0}

    def _flaky(h, u, p, port):
        calls["n"] += 1
        if calls["n"] < 2:
            raise OSError("AUTHENTICATIONFAILED")
        return ["INBOX"]

    io = FakeIO(secrets=["yanlis", "dogru1234567890"])
    code = W.run_setup(email="a@gmail.com", method="app-password", io=io,
                       do_test=_flaky, do_save=_saver({}), no_browser=True)
    assert code == 0 and calls["n"] == 2
    assert any("UYGULAMA" in s for s in io.shown)  # yol gösterici mesaj


def test_uc_hata_vazgec():
    def _boom(h, u, p, port):
        raise OSError("AUTHENTICATIONFAILED")

    io = FakeIO(secrets=["1", "2", "3"])
    code = W.run_setup(email="a@gmail.com", method="app-password", io=io,
                       do_test=_boom, do_save=_saver({}), no_browser=True)
    assert code == 2


def test_gecersiz_eposta():
    io = FakeIO()
    assert W.run_setup(email="eposta-degil", io=io, no_browser=True) == 2


def test_custom_saglayici():
    store, io = {}, FakeIO(answers=["6", "mail.sirket.com", "993"], secrets=["pw123456"])
    code = W.run_setup(email="a@sirket.com", io=io,
                       do_test=lambda h, u, p, port: ["INBOX"] if h == "mail.sirket.com" else [],
                       do_save=_saver(store), no_browser=True)
    assert code == 0
    assert store["IMAP_HOST"] == ("mail.sirket.com", False)


def test_custom_hatali_port():
    io = FakeIO(answers=["6", "mail.sirket.com", "abc"])
    assert W.run_setup(email="a@sirket.com", io=io, no_browser=True) == 2


def test_oauth_delegasyonu():
    io = FakeIO()
    out = W.run_setup(email="a@gmail.com", method="oauth", io=io, no_browser=True)
    assert out == "OAUTH:gmail"


def test_interaktif_yontem_secimi():
    io = FakeIO(answers=["", "2"])  # menüde Enter=tahmin, yöntemde 2=oauth
    out = W.run_setup(email="a@hotmail.com", io=io, no_browser=True)
    assert out == "OAUTH:outlook"
    io2 = FakeIO(answers=["", "9"], secrets=["x" * 16])
    assert W.run_setup(email="a@hotmail.com", io=io2, no_browser=True,
                       do_test=lambda h, u, p, port: [],
                       do_save=_saver({})) == 2  # geçersiz seçim
    io3 = FakeIO(answers=["", "1"], secrets=["y" * 16])
    assert W.run_setup(email="a@hotmail.com", io=io3, no_browser=True,
                       do_test=lambda h, u, p, port: ["INBOX"],
                       do_save=_saver({})) == 0


def test_menu_numara_secimi():
    io = FakeIO(answers=["3", "1"], secrets=["z" * 16])  # 3=yahoo, yöntem 1
    store = {}
    code = W.run_setup(email="a@sirket.com", io=io, no_browser=True,
                       do_test=lambda h, u, p, port: ["INBOX"],
                       do_save=_saver(store))
    assert code == 0
    assert store["IMAP_HOST"] == ("imap.mail.yahoo.com", False)


def test_menu_hatali_sonra_gecerli():
    io = FakeIO(answers=["99", "yahoo", "1"], secrets=["z" * 16])
    code = W.run_setup(email="a@sirket.com", io=io, no_browser=True,
                       do_test=lambda h, u, p, port: ["INBOX"],
                       do_save=_saver({}))
    assert code == 0
    assert any("1-6" in s for s in io.shown)


def test_menu_uc_hatada_vazgec():
    io = FakeIO(answers=["0", "yok", "99"])
    assert W.run_setup(email="a@sirket.com", io=io, no_browser=True) == 2


def test_acik_gecersiz_provider():
    io = FakeIO()
    assert W.run_setup(email="a@gmail.com", provider="foo", io=io, no_browser=True) == 2


def test_acik_provider_menu_atlar():
    store, io = {}, FakeIO(secrets=["q" * 16])
    code = W.run_setup(email="a@gmail.com", provider="yahoo",
                       method="app-password", io=io, no_browser=True,
                       do_test=lambda h, u, p, port: ["INBOX"],
                       do_save=_saver(store))
    assert code == 0
    assert store["IMAP_HOST"] == ("imap.mail.yahoo.com", False)
    assert not any("Sağlayıcı seçin" in s for s in io.shown)


def test_menu_tahmin_isareti():
    from app.setup_wizard import PROVIDER_MENU, choose_provider, menu_label

    assert PROVIDER_MENU == ("gmail", "outlook", "yahoo", "yandex", "icloud", "custom")
    assert menu_label("custom") == W.CUSTOM_LABEL
    io = FakeIO(answers=[""])
    assert choose_provider(io, "gmail") == "gmail"
    assert any("tahmin" in s for s in io.shown)


def test_oauth_tanimsiz_saglayici_menu_acar():
    io = FakeIO(answers=["1"])  # menüden gmail seç → OAuth delegasyonu
    assert W.run_setup(email="a@sirket.com", method="oauth", io=io, no_browser=True) == "OAUTH:gmail"
    io2 = FakeIO(answers=["0", "yok", "99"])
    assert W.run_setup(email="a@sirket.com", method="oauth", io=io2, no_browser=True) == 2


def test_bos_sifre_hak_yer():
    io = FakeIO(secrets=["", "gecerli12345678"])
    code = W.run_setup(email="a@gmail.com", method="app-password", io=io,
                       do_test=lambda h, u, p, port: ["INBOX"],
                       do_save=_saver({}), no_browser=True)
    assert code == 0


def test_tarayici_acilir():
    io = FakeIO(secrets=["x" * 16])
    W.run_setup(email="a@gmail.com", method="app-password", io=io,
                do_test=lambda h, u, p, port: ["INBOX"],
                do_save=_saver({}), no_browser=False)
    assert io.browsed == ["https://myaccount.google.com/apppasswords"]


def test_cli_setup_parser_kayitli():
    import pytest

    from app.cli import build_parser

    a = build_parser().parse_args(["config", "setup", "--email", "a@gmail.com",
                                   "--method", "app-password", "--no-browser"])
    assert a.config_action == "setup" and a.email == "a@gmail.com"
    with pytest.raises(SystemExit) as e:
        build_parser().parse_args(["config", "setup", "--method", "yanlis"])
    assert e.value.code == 2
    assert cli_main is not None  # noqa: F841 — import zinciri sağlam
