"""Çift-tık menüsü testleri — sahte IO, gerçek main'e dokunulmaz."""

from app.interactive import MENU, run_menu


class FakeIO:
    def __init__(self, answers):
        self._answers = list(answers)
        self.shown = []
        self.calls = []

    def ask(self, prompt):
        self.shown.append(prompt)
        assert self._answers, f"beklenmeyen soru: {prompt}"
        return self._answers.pop(0)

    def show(self, msg):
        self.shown.append(msg)

    def fake_main(self, argv):
        self.calls.append(list(argv))
        return 0


def test_menu_cikis():
    io = FakeIO(["0"])
    assert run_menu(io.ask, io.show, io.fake_main) == 0
    assert io.calls == []
    assert any("[1]" in s for s in io.shown)


def test_menu_secim_calistirir():
    io = FakeIO(["2", "0"])
    assert run_menu(io.ask, io.show, io.fake_main) == 0
    assert io.calls == [["health"]]
    assert any("çıkış kodu: 0" in s for s in io.shown)


def test_menu_gecersiz_secim():
    io = FakeIO(["9", "0"])
    assert run_menu(io.ask, io.show, io.fake_main) == 0
    assert io.calls == []
    assert any("HATA" in s for s in io.shown)


def test_menu_eof_cikar():
    def _boom(prompt):
        raise EOFError

    assert run_menu(_boom, print, lambda argv: 0) == 0


def test_menu_main_hatasi_exit_2():
    def _boom(argv):
        raise RuntimeError("patladı")

    io = FakeIO(["2", "0"])
    assert run_menu(io.ask, io.show, _boom) == 2
    assert any("RuntimeError" in s for s in io.shown)


def test_menu_tumu_kayitli():
    keys = [m[0] for m in MENU]
    assert keys == ["1", "2", "3", "4", "5", "6", "7", "0"]
    assert all(argv for _, _, argv in MENU if argv is not None)


def test_menu_panel_calistirir():
    io = FakeIO(["6", "0"])
    assert run_menu(io.ask, io.show, io.fake_main) == 0
    assert io.calls == [["dashboard"]]
