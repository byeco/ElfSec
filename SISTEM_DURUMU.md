# ElfSec Sistem Durum Çizelgesi (baz: v1.2.0)

> Tek exe: `elfsec.exe` (CLI + guard + web API). Web API opt-in'dir,
> varsayılan localhost + stdlib-only (ek bağımlılık yok).
> v1.0.0 stabil: CLI sözleşmesi donduruldu, geriye dönük uyumluluk korunur.

## 1. Yapılmışlar [x]

| # | Sistem | Dosya | Durum |
|---|--------|-------|-------|
| 1 | CLI çekirdek (health/fetch/analyze/analyze-file/triage/guard/config/kontrol) + exit-code 0/1/2 | `backend/app/cli.py` | [x] |
| 2 | TEMİZLE: bleach dar liste + bs4/lxml + tracking piksel sayacı + MAX_INPUT 500k | `backend/app/services/sanitizer.py` | [x] |
| 3 | ANALİZ: offline deterministik motor `elfsec-local/1.0` (phishing/prompt-injection/URL skoru) | `backend/app/services/ai_analyzer.py` | [x] |
| 4 | OKU: imap-tools + quarantine (thread'de), klasör listeleme | `backend/app/services/imap_client.py` | [x] |
| 5 | TOOL iç doğrulama: folder<=128 + `..` yasak, limit 1-100, body<=30k, interval min 1 | `backend/app/cli.py`, `schemas.py` | [x] |
| 6 | KONTROL: 32 sızma denetimi + sürümlü yol haritası (TOOL-only) | `backend/app/kontrol.py` | [x] |
| 8 | Katmanlı config + DPAPI `ENC()` + Türkçe ConfigError (TOOL-only, API alanı yok) | `backend/app/settings_store.py`, `secret_vault.py`, `config.py` | [x] |
| 9 | SDK: `scan_text/scan_file/sanitize` | `backend/app/sdk.py` | [x] |
| 10 | Guard: tek-exe `--tray`, toast, https-only webhook, autostart schtasks | `backend/app/cli.py`, `notify.py`, `tray.py`, `scripts/setup_autostart.ps1` | [x] |
| 11 | CI pytest/pip-audit + dependabot + release tek-exe (serversiz) | `.github/`, `scripts/build_exe.ps1` | [x] |
| 12 | Testler (32) + README (TOOL-only) | `backend/tests/` | [x] |
| 13 | Server/frontend/Docker | SİLİNDİ (bilinçli TOOL-only): main.py, api/, limiter.py, serve, Dockerfile, compose | [x] karar |

## 2. Yapılacaklar (sürümsel, v0.x.x)

### v0.1.1 — Durum takibi + konfigürasyon borcu [ ]

| # | İş | Dosya | Durum |
|---|----|-------|-------|
| 14 | `SISTEM_DURUMU.md` + merkezi `app/__version__.py` + `CHANGELOG.md` | kök, `app/__version__.py` | [x] |
| 15 | README frontend vaadini temizle (`tool-only` netleştir) | `README.md` | [x] |
| 16 | Secret dosya izni 0600 + `config show --reveal` uyarısı | `settings_store.py` | [x] v0.7.0 |

### v0.6.0 — Kurumsal operasyon [x]

| # | İş | Dosya | Durum |
|---|----|-------|-------|
| 43 | Kural motoru: `rules.json` 24 kural + `rules` komutu | `rules.py`, `ai_analyzer.py`, `cli.py` | [x] |
| 44 | CEF (`triage --cef`, `guard --cef-log`) + yapısal log + `update --check` | `cef.py`, `log.py`, `cli.py` | [x] |
| 45 | `installer/elfsec.iss` + CI lint (ruff) + kontrol kapısı | `installer/`, `ci.yml` | [x] |
| 46 | KONTROL OPS-05/06/07 + `tests/test_ops.py` (8 test) | `kontrol.py`, `tests/` | [x] |

### v0.5.0 — Ek + URL istihbaratı [x]

| # | İş | Dosya | Durum |
|---|----|-------|-------|
| 41 | Ek üstverisi + homoglif + `--expand-urls` | `ai_analyzer.py`, `imap_client.py`, `urlintel.py`, `cli.py`, `sdk.py` | [x] |
| 42 | KONTROL ATT-01/02, URL-02/03 + `tests/test_urlintel_attach.py` (13 test) | `kontrol.py`, `tests/` | [x] |

### v0.4.0 — Başlık doğrulama [x]

| # | İş | Dosya | Durum |
|---|----|-------|-------|
| 39 | SPF/DKIM/DMARC + Reply-To/Return-Path/Message-ID + marka haritası | `ai_analyzer.py`, `imap_client.py` | [x] |
| 40 | `--header` bayrağı + SDK headers + KONTROL HDR-01/02/03 + 10 test | `cli.py`, `sdk.py`, `tests/test_headers.py` | [x] |

### v0.3.0 — OAuth2 girişi (outlook+gmail) [x] (taraması: 38 bulgu, 0 FAIL, 0 WARN)

| # | İş | Dosya | Durum |
|---|----|-------|-------|
| 40 | `app/oauth.py` (stdlib-only) + XOAUTH2 IMAP yolu + `config login/logout` | `oauth.py`, `imap_client.py`, `cli.py`, `config.py` | [x] |
| 41 | Refresh-token kasada (ENC), `health/test` OAuth yolu, README Azure+Google adımları | `settings_store.py`, `.env.example` | [x] |
| 42 | KONTROL OAUTH-01/02/03 + `tests/test_oauth.py` (10 test) | `kontrol.py`, `tests/` | [x] |

### v0.2.3 — Hata kodları + loop-yutma çözümü [x] (taraması: 35 bulgu, 0 FAIL, 0 WARN)

| # | İş | Dosya | Durum |
|---|----|-------|-------|
| 37 | `guard --once` err→2, `config test` fail→2, `_guard_cycle` status + ardışık-hata sayacı | `cli.py` | [x] |
| 38 | `_safe_notify` + `guard_errors.jsonl`, bozuk state yedeği, mail-başına izolasyon | `cli.py` | [x] |
| 39 | KONTROL ERR-01/02/03 + `tests/test_error_codes.py` (12 test) | `kontrol.py`, `tests/` | [x] |

### v0.2.2 — TOOL-only + 0 WARN [x] (taraması: 32 bulgu, 0 FAIL, 0 WARN)

| # | İş | Dosya | Durum |
|---|----|-------|-------|
| 33 | Server sökümü: main.py, api/, limiter.py, serve, Dockerfile, compose silindi | — | [x] |
| 34 | TOOL sertliği: folder/limit/interval doğrulama + oversize kırpma CLI'ya taşındı | `cli.py`, `schemas.py`, `config.py` | [x] |
| 35 | KONTROL TOOL-only: API/Docker checkleri yerine TOOL-01..04 + SURUM-04 + OPS-04 | `kontrol.py`, `tests/test_api_cli.py` | [x] |
| 36 | requirements 14→8 paket (serversiz), build_exe/spec sadeleşti | `requirements.txt` | [x] |

### v0.2.1 — KONTROL sistemi [x] (32 bulgu, 0 FAIL, 4 WARN — v0.2.2'de sıfırlandı)

| # | İş | Dosya | Durum |
|---|----|-------|-------|
| 33 | CLI `kontrol` + `app/kontrol.py` (sızma testleri + sürümlü yol haritası) | `app/kontrol.py`, `cli.py`, `tests/test_kontrol.py` | [x] |

### v0.2.0 — Tek exe + arka plan eklenti [x]

| # | İş | Dosya | Durum |
|---|----|-------|-------|
| 17 | Tek exe: `console=True` + `--tray/--background` modunda konsolu gizle | `backend/elfsec.py`, `elfsec.spec` | [x] |
| 18 | Guard bayrakları: `--tray --background --notify on/off` | `backend/app/cli.py` | [x] |
| 19 | Windows Toast bildirimi (hatada + HIGH+ alarmda), ek bağımlılıksız (PowerShell fallback) | `backend/app/notify.py` | [x] |
| 20 | Minimal tray/sessiz loop (pystray varsa ikon, yoksa sessiz) | `backend/app/tray.py` | [x] |
| 21 | `setup_autostart.ps1` tek exe'ye geçir (`elfsec.exe guard --tray`) | `scripts/setup_autostart.ps1` | [x] |
| 22 | `build_exe.ps1` + `release.yml` tek artifact | `scripts/build_exe.ps1`, `.github/workflows/release.yml` | [x] |

### v0.3.0 — Tehlikeyi durdur/yok et (default KAPALI) [ ]

| # | İş | Dosya | Durum |
|---|----|-------|-------|
| 23 | `guard --action notify-only/quarantine/delete` (default notify-only) | `cli.py` | [x] iskelet |
| 24 | IMAP `move_to_junk/mark_seen/delete` + `quarantine.jsonl` yedeği | `services/imap_client.py` | [x] iskelet |
| 25 | Toast aksiyonu: Karantinaya al / Yoksay (protocol `elfsec:quarantine?uid=`) + `quarantine` komutu + `register_protocol.ps1` | `notify.py`, `cli.py`, `scripts/` | [x] v0.7.0 |
| 26 | Webhook https-only (http atlanır) + retry (3 deneme, üstel bekleme) + `--webhook-header` auth | `cli.py:_notify_webhook` | [x] v0.7.0 |

### v0.8.2 — Çift-tık menüsü [x]

| # | İş | Dosya | Durum |
|---|----|-------|-------|
| 59 | Argümansız açılışta interaktif menü + kapanışta Enter bekleme | `interactive.py`, `elfsec.py` | [x] |
| 60 | KONTROL MENU-01 + `tests/test_interactive.py` (6 test) | `kontrol.py`, `tests/` | [x] |

### v0.8.1 — Sağlayıcı menüsü [x]

| # | İş | Dosya | Durum |
|---|----|-------|-------|
| 57 | Numaralı sağlayıcı menüsü (1-6) + tahmin-onay (Enter), `--provider` ile atlama | `setup_wizard.py` | [x] |
| 58 | KONTROL SETUP-04 + menü testleri | `kontrol.py`, `tests/test_setup.py` | [x] |

### v0.8.0 — Kolay kurulum [x]

| # | İş | Dosya | Durum |
|---|----|-------|-------|
| 50 | `config setup` sihirbazı: sağlayıcı otomatik tanıma (gmail/outlook/yahoo/yandex/icloud/custom) | `setup_wizard.py`, `cli.py` | [x] |
| 51 | Tarayıcıyı doğru uygulama-şifresi sayfasında açma + anında bağlantı testi (3 deneme) | `setup_wizard.py` | [x] |
| 52 | Hata sınıflandırma (auth/network/tls) + Türkçe yol gösterici mesajlar, şifre bayraksız (getpass/ENV) | `setup_wizard.py` | [x] |
| 53 | KONTROL SETUP-01/02/03 + `tests/test_setup.py` | `kontrol.py`, `tests/` | [x] |

### v0.9.0 — Ölçek + hız [plan]

| # | İş | Durum |
|---|----|-------|
| 54 | Artımlı senkron (`UIDVALIDITY` + son UID takibi, sadece yeni mailler) | [ ] |
| 55 | Toplu fetch (`bulk`) + tur başına süre metriği (`--profile`) | [ ] |
| 56 | Kural paketi güncellemesi (`update --rules` ile imzalı rules.json) | [ ] |

### v1.2.0 — Next.js istemcisi [x]

| # | İş | Dosya | Durum |
|---|---|-------|-------|
| 63 | `web/elfsec.js` + `web/route-example.js`, uçtan uca Node→Python doğrulaması | `web/` | [x] |

### v1.1.0 — Web API [x]

| # | İş | Dosya | Durum |
|---|---|-------|-------|
| 61 | `app/serve.py` (stdlib): health/analyze/sanitize + token/rate-limit/413/CORS | `serve.py`, `cli.py`, `interactive.py` | [x] |
| 62 | KONTROL SERVE-01..05 + `tests/test_serve.py` (9 test) | `kontrol.py`, `tests/` | [x] |

### v1.0.0 — Stabil sürüm [x] (okul projesi finali)

| # | İş | Durum |
|---|---|-------|
| 53 | Sürüm 1.0.0 + CLI sözleşmesi dondurma + yorum/README cilası | [x] |
| 54 | 0 FAIL / 0 WARN + %75 coverage (eşik %70) + `pip-audit` temiz | [x] |
| 55 | Authenticode imzalı exe + `setup.exe` ile dağıtım | [ ] v1.x hedefi |

### v0.7.0 — Etkileşim + dayanıklılık [x]

| # | İş | Dosya | Durum |
|---|----|-------|-------|
| 47 | PII redaksiyon (`--redact`) + retention (`--retention-days`) | `redact.py`, `cli.py` | [x] |
| 48 | CI: coverage eşiği (%70) + SBOM artifact | `ci.yml` | [x] |
| 49 | SVG-01 (`svg/cid:/vml` blok kanıtı) — eski #28 artığı kapandı | `kontrol.py` | [x] |

### v0.4.0 — Mail başlık güvenliği [x] (üstteki yeni v0.4.0'da yapıldı)

| # | İş | Durum |
|---|----|-------|
| 27 | `From/Reply-To/Return-Path/Received/Authentication-Results` çek + `Reply-To mismatch` kuralı | [x] |
| 28 | Unicode confusable + çift uzantı (`fatura.pdf.exe`) + `svg/style url()/cid:` bloklama | [x] |
| 29 | Shortener genişletme (opsiyonel, offline default) | [x] |

### v0.5.0 — Dağıtım + gözlemlenebilirlik [x] (üstteki yeni sürümlerde yapıldı)

| # | İş | Durum |
|---|----|-------|
| 30 | logging + PII redaksiyonu + retention | [x] v0.6.0/v0.7.0 |
| 31 | CI: ruff + coverage eşiği + SBOM + Inno Setup `setup.exe` | [x] v0.6.0/v0.7.0 |

## 3. Notlar

- Oto-sil asla sessiz yapılmaz: önce `notify + quarantine`, `delete` sadece bayrakla.
- `guard_alerts.jsonl` PII içerir, paylaşılmaz. Webhook yalnızca `https://` verilir.
- Server/frontend/Docker bilinçli yok — dağıtım tek `elfsec.exe`.
