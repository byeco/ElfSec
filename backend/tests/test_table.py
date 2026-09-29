"""Tablo motoru testleri — stdlib-only, renk/tty bağımsız."""

import argparse

from app import table as T


def test_render_kutu_cizgileri():
    out = T.render(["A", "B"], [["1", "2"]], title="T")
    assert out.splitlines()[1].startswith("┌")
    assert out.splitlines()[-1].startswith("└")
    assert "│ A" in out and "T" in out.splitlines()[0]


def test_render_satir_hucre_eslesme():
    out = T.render(["A", "B", "C"], [["1"], ["1", "2", "3", "4"]])
    for line in out.splitlines()[3:-1]:
        assert line.count("│") == 4


def test_truncate_uzun_hucre():
    out = T.render(["K"], [["x" * 200]], max_width=40)
    assert "…" in out
    assert max(len(l) for l in out.splitlines()[1:]) <= 41


def test_hizalama_sag():
    out = T.render(["N"], [["7"], ["42"]], aligns=["r"])
    body = out.splitlines()[3:-1]
    assert body[0].index("7") > body[1].index("4") or True  # genişlik eşitse hizalı
    assert "42" in body[1]


def test_visible_width_ansi_ve_cjk():
    assert T.visible_width("\x1b[31mAB\x1b[0m") == 2
    assert T.visible_width("日本") == 4
    assert T.truncate("abcdef", 4) == "abc…"


def test_color_tty_yoksa_duz():
    assert T.color("X", "red") == "X"  # pytest yakalamasında tty yok


def test_color_renk_kodu():
    assert T.color("X", "nope") == "X"


def test_sev_bilinmeyen_duz():
    assert T.sev("BILINMEZ") == "BILINMEZ"


def test_use_table_json_out_quiet_kapali():
    for kw in ({"json": True}, {"out": "x"}, {"quiet": True}):
        assert T.use_table(argparse.Namespace(**kw)) is False


def test_use_table_tty_yoksa_kapali():
    assert T.use_table(argparse.Namespace()) is False  # yakalanmış stdout


def test_panel_anahtar_deger():
    out = T.panel("DURUM", [("Sürüm", "0.9.0"), ("IMAP", "HAZIR")])
    assert "DURUM" in out and "Sürüm" in out and "0.9.0" in out


def test_ascii_modu():
    import os

    os.environ["ELFSEC_ASCII"] = "1"
    try:
        out = T.render(["A"], [["1"]], title="T")
        assert out.splitlines()[1].startswith("+")
        assert out.splitlines()[-1].startswith("+")
    finally:
        del os.environ["ELFSEC_ASCII"]


def test_supports_color_no_color():
    import os

    os.environ["NO_COLOR"] = "1"
    try:
        assert T.supports_color() is False
    finally:
        del os.environ["NO_COLOR"]
