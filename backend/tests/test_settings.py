"""Ayar sistemi testleri: katman önceliği, doğrulama, şifreli saklama."""

import os

import pytest

from app import secret_vault
from app.settings_store import (ConfigError, build_settings, load_file_values,
                                semantic_warnings, upsert_kv)


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_once_dosya_okunur(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("IMAP_HOST", raising=False)
    f = _write(tmp_path / "c.env", "IMAP_HOST=mail.ornek.com\nIMAP_USER=a@b.com\n")
    s, found, _w = build_settings(explicit=f)
    assert s.imap_host == "mail.ornek.com"
    assert str(found) == f


def test_ortam_degiskeni_dosyayi_ezer(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = _write(tmp_path / "c.env", "IMAP_HOST=mail.ornek.com\n")
    monkeypatch.setenv("IMAP_HOST", "mail.farkli.com")
    s, _found, _w = build_settings(explicit=f)
    assert s.imap_host == "mail.farkli.com"


def test_hatali_port_turkce_hata_verir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = _write(tmp_path / "c.env", "IMAP_PORT=degil\n")
    with pytest.raises(ConfigError) as e:
        build_settings(explicit=f)
    assert any("IMAP_PORT" in h for h in e.value.hints)


def test_olmayan_config_dosyasi_hata_verir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigError):
        build_settings(explicit=str(tmp_path / "yok.env"))


def test_semantik_uyari_sifresiz_kullanici(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = _write(tmp_path / "c.env", "IMAP_USER=a@b.com\n")
    s, _found, warnings = build_settings(explicit=f)
    assert any("IMAP_PASSWORD" in w for w in warnings)
    assert semantic_warnings(s)


def test_vault_roundtrip_dosyada(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "c.env"
    upsert_kv(f, "IMAP_PASSWORD", "gizli123", secret=True)
    vals, _w = load_file_values(f)
    assert vals["imap_password"] == "gizli123"
    if os.name == "nt":
        line = f.read_text(encoding="utf-8").splitlines()[0]
        assert secret_vault.is_protected(line.split("=", 1)[1].strip().strip('"'))
    # upsert mevcut anahtarı çoğaltmamalı
    upsert_kv(f, "IMAP_PASSWORD", "yeni", secret=True)
    assert f.read_text(encoding="utf-8").count("IMAP_PASSWORD=") == 1


def test_bilinmeyen_anahtar_reddedilir(tmp_path):
    with pytest.raises(ConfigError):
        upsert_kv(tmp_path / "c.env", "YOK_BOYLE", "x")
