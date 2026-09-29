"""Dashboard + tablo çıktıları — IMAP mock'lu, stdout yakalamalı."""

import argparse
import json
import types

import pytest

import app.table as table_mod
from app.cli import cmd_dashboard, main as cli_main
from app.table import render


def _tablo_ac(monkeypatch):
    monkeypatch.setattr(table_mod, "use_table", lambda args: True)


def _sahte_ayar():
    return types.SimpleNamespace(imap_host="x", imap_user="u@x",
                                 imap_password="pw", imap_port=993,
                                 imap_configured=True, env="dev")


def _sahte_mail(uid="7"):
    return {"uid": uid, "subject": "Hesabınız kapanacak! Hemen doğrulayın",
            "from": "destek@banka-secure.tk", "to": "",
            "date": "2026-01-01",
            "body": "<p>Hemen tıkla http://evil.tk/verify, şifreni gönder</p>",
            "headers": {}, "attachments": []}


def test_dashboard_alarmsiz(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("app.settings_store.current_settings", lambda: _sahte_ayar())
    assert cli_main(["dashboard"]) == 0
    assert "henüz alarm yok" in capsys.readouterr().out


def test_dashboard_tablo_alarmla(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "guard_alerts.jsonl").write_text(
        json.dumps({"alerted_at": "2026-01-01", "risk_score": 80,
                    "risk_level": "HIGH", "uid": "7", "subject": "Fatura"}) + "\n",
        encoding="utf-8")
    monkeypatch.setattr("app.settings_store.current_settings", lambda: _sahte_ayar())
    _tablo_ac(monkeypatch)
    assert cli_main(["dashboard"]) == 0
    out = capsys.readouterr().out
    assert "ELFSEC PANEL" in out and "SON ALARMLAR" in out and "Fatura" in out


def test_dashboard_limit_hatasi():
    with pytest.raises(SystemExit):
        cli_main(["dashboard", "--limit", "abc"])


def test_dashboard_json(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("app.settings_store.current_settings", lambda: _sahte_ayar())
    assert cli_main(["dashboard", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["alarms"] == [] and "health" in data


def test_dashboard_bozuk_satir_atlanir(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "guard_alerts.jsonl").write_text("bozuk-satır\n", encoding="utf-8")
    monkeypatch.setattr("app.settings_store.current_settings", lambda: _sahte_ayar())
    assert cli_main(["dashboard", "--json"]) == 0


def test_health_tablo(monkeypatch, capsys):
    monkeypatch.setattr("app.settings_store.current_settings", lambda: _sahte_ayar())
    _tablo_ac(monkeypatch)
    assert cli_main(["health"]) == 0
    assert "ELFSEC DURUM" in capsys.readouterr().out


def test_fetch_tablo(monkeypatch, capsys):
    async def _fake_fetch(params):
        return [_sahte_mail()]

    monkeypatch.setattr("app.settings_store.current_settings", lambda: _sahte_ayar())
    monkeypatch.setattr("app.services.imap_client.fetch_emails", _fake_fetch)
    _tablo_ac(monkeypatch)
    assert cli_main(["fetch", "--limit", "1"]) == 0
    out = capsys.readouterr().out
    assert "E-POSTALAR" in out and "│ 7 " in out


def test_triage_tablo(monkeypatch, capsys):
    async def _fake_fetch(params):
        return [_sahte_mail()]

    monkeypatch.setattr("app.settings_store.current_settings", lambda: _sahte_ayar())
    monkeypatch.setattr("app.services.imap_client.fetch_emails", _fake_fetch)
    _tablo_ac(monkeypatch)
    assert cli_main(["triage", "--limit", "1"]) == 0
    out = capsys.readouterr().out
    assert "TRIAGE" in out and "HIGH" in out


def test_rules_tablo(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("ELFSEC_CONFIG_DIR", str(tmp_path))
    _tablo_ac(monkeypatch)
    assert cli_main(["rules", "show"]) == 0
    out = capsys.readouterr().out
    assert "MOTOR KURALLARI" in out and "phishing_pattern" in out


def test_kontrol_tablo_render():
    from app.kontrol import run_kontrol

    r = run_kontrol(["TOOL"])
    out = render(["Durum", "ID"], [[b["durum"], b["id"]] for b in r["bulgular"]],
                 title=f"BULGULAR ({len(r['bulgular'])})")
    assert "BULGULAR" in out and "TOOL-01" in out


def test_dashboard_namespace_limit_hatasi():
    ns = argparse.Namespace(limit="x", alert_log="", json=False, out="")
    assert cmd_dashboard(ns) == 2
