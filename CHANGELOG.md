# CHANGELOG

## v1.2.0 — Next.js istemcisi

- Yeni `web/elfsec.js`: bağımlılıksız Next.js istemcisi (health/analyze/sanitize,
  timeout + 401/429/413 hata eşleme, istemci tarafı limit kırpma).
- Yeni `web/route-example.js`: kopyala-yapıştır App Router örneği (token sunucuda kalır).
- README'ye "Next.js sunucunda çalışır mı?" tablosu (VPS Windows/Linux ✅, Vercel ❌).
- Uçtan uca doğrulandı: Node istemci → Python API → skor.

## v1.1.0 — Web API (site entegrasyonu)

- Yeni `elfsec serve`: stdlib-only web API (ek bağımlılık yok, exe şişmez).
  Uçlar: `GET /v1/health`, `POST /v1/analyze`, `POST /v1/sanitize`.
- Güvenlik (açık kaynak, paranoyak varsayılanlar): ağa açık + tokensuz
  başlama reddedilir (fail-closed), token sadece `ELFSEC_API_TOKEN`
  ortam değişkeninden okunur (bayrak yok), IP başına rate-limit (429),
  1MB gövde kesmesi (413), CORS allowlist, loglara PII yazılmaz,
  siteye dönen raporda gövde 2000 karaktere kırpılır.
- KONTROL: yeni SERVE grubu (5 denetim). Testler: 9 yeni test_serve.py.
- Menüye [7] Web API eklendi.

## v1.0.0 — Stabil sürüm (okul projesi finali)

- Sürüm `1.0.0`'a çekildi: CLI sözleşmesi donduruldu, `kontrol` 61/61 PASS,
  testler 152/152 yeşil, coverage %75 (eşik %70), `pip-audit` temiz.
- Kod yorumları ve README sadeleştirildi (projeyi derste anlatabilmek için):
  her modülde neyi neden yaptığımı kendi cümlelerimle yazdım.
- README'ye "Nasıl çalışıyor?" bölümü + İngilizce özet eklendi.
- Önceki sürümlerin hepsi aşağıda duruyor, hiçbir şey silinmedi.

## v0.9.0 — Tablo arayüzü

- Yeni `app/table.py` (stdlib-only): kutulu tablolar, seviye renkleri (NO_COLOR
  saygılı, pipe'ta kapalı), CJK-uyumlu genişlik, otomatik kısaltma.
- `health/fetch/triage/rules/kontrol` tty'de tablo basar; `--json/--out/--quiet`
  ve boru hatları eski düz metni korur (sözleşme testli).
- Yeni `dashboard` komutu: durum paneli + son alarmlar tablosu; menüye [6] eklendi.
- KONTROL: TABLO-01, DASH-01. Testler: 13 yeni test_table.py + 11 test_dashboard.py.

## v0.8.2 — Çift-tık menüsü

- Exe'ye çift tıklayınca pencere kapanmıyor: interaktif menü
  (kurulum / durum / tara / koruma / denetim / çıkış) + çıkışta Enter bekleme.
- `app/interactive.py` (test edilebilir) + KONTROL MENU-01.

## v0.8.1 — Sağlayıcı menüsü

- `config setup` artık exe içinde numaralı sağlayıcı menüsü soruyor
  (1 Gmail · 2 Outlook · 3 Yahoo · 4 Yandex · 5 iCloud · 6 Diğer);
  e-postadan tahmin edileni Enter ile onaylama, `--provider` ile atlama.
- Niyet belliyse (`--method` + tanınan alan adı) sorusuz devam.
- KONTROL: SETUP-04.

## v0.8.0 — Kolay kurulum

- Yeni `elfsec config setup`: e-postanı yaz, sağlayıcı otomatik tanınır
  (gmail/outlook/yahoo/yandex/icloud + özel sunucu), tarayıcı doğru
  uygulama-şifresi sayfasında açılır, bağlantı anında test edilir.
- Hata sınıflandırma (auth/network/tls) + Türkçe adım adım çözüm önerisi, 3 deneme.
- Şifre asla komut satırı bayrağı olmaz (getpass veya `ELFSEC_SETUP_PASSWORD`).
- OAuth isteyen `config login` akışına sorunsuz devreder.
- KONTROL: SETUP-01/02/03. Testler: 115 passed (17 yeni test_setup.py).

## v0.7.0 — Etkileşim + dayanıklılık

- Butonlu toast: "Karantinaya al" (`elfsec:quarantine?uid=`) + "Yoksay"; `quarantine UID`
  komutu (`--action quarantine|delete`, delete `--yes` ister); `register_protocol.ps1`.
- Webhook retry (3 deneme, üstel bekleme) + `--webhook-header` auth başlığı.
- PII redaksiyon: `redact.py` (e-posta/IBAN/TC/kart) + guard `--redact`;
  retention: `--retention-days N` eski log satırlarını budar.
- Secret 0600 (`upsert_kv` chmod, POSIX) + `config show` izin/reveal uyarıları.
- CI: coverage eşiği (%70) + SBOM artifact. SVG-01 (`cid:/vml` blok kanıtı).
- KONTROL: WH-01, TST-01, QAR-01, PII-01, SEC-02, SVG-01.

## v0.6.0 — Kurumsal operasyon

- Yapılandırılabilir motor: `rules.json` (24 kural), `rules show|set|enable|disable|reset`.
- CEF dışa aktarım: `triage --cef`, `guard --cef-log` (SIEM).
- Yapısal log: `elfsec.log` (1MB x3 rotasyon) + `guard_errors.jsonl` dual iz.
- `update --check`: GitHub Releases karşılaştırması (çevrimdışında uyarı, kapı değil).
- `installer/elfsec.iss` (Inno Setup), CI `lint` job (ruff) + kontrol kapısı.
- KONTROL: OPS-05/06/07. Testler: 85 passed (8 yeni test_ops.py).

## v0.5.0 — Ek + URL istihbaratı

- Ek üstverisi (içerik indirilmez): çift uzantı (+25), riskli ext (+20), makrolu Office (+15), arşiv (+8).
- Homoglif: Kiril/Yunan+Latin karışımı alan adı (+25, punycode ötesi, unicodedata).
- URL anahtar kelime sinyali (+8): login/verify/account/update.
- `--expand-urls` (analyze/analyze-file/triage/guard): kısaltmaları çevrimiçi genişletir,
  varsayılan KAPALI (çevrimdışı ilke). Başarısızlıkta offline skor korunur.
- KONTROL: ATT-01/02, URL-02/03. Testler: 77 passed (13 yeni test_urlintel_attach.py).

## v0.4.0 — Başlık doğrulama (SPF/DKIM/DMARC + spoof avı)

- IMAP'ten `Reply-To/Return-Path/Authentication-Results/Message-ID` çekilir (`extract_headers`).
- Yeni kurallar: spf/dkim/dmarc fail (+20), Reply-To≠From (+20), Return-Path≠From (+15),
  yabancı Message-ID (+10), marka display-name taklidi (+20, 18 marka haritası).
- Eksik başlık ceza almaz (FP koruması) — sadece çelişki puanlanır.
- `analyze/analyze-file --header 'Reply-To: x@y'` (tekrarlanabilir), SDK `headers=` paramı.
- KONTROL: HDR-01/02/03. Testler: 64 passed (10 yeni test_headers.py).

## v0.3.0 — OAuth2 girişi (outlook+gmail)

- Windows hazır hesabı sessizce devralma YOKTUR (DPAPI-bound) — yerine bir kez tarayıcı onayı.
- `config login --provider outlook|gmail` / `config logout`, `config init` OAuth önerir.
- Refresh-token DPAPI kasada (ENC), access-token her turda yenilenir, IMAP XOAUTH2.
- Herkes kendi uygulama kaydını açar (Azure/Google adımları README'de). Ek bağımlılık yok.
- `health` auth yöntemini gösterir (`oauth:provider|sifre|yok`), `config test` OAuth yolunu dener.
- KONTROL: OAUTH-01/02/03. Testler: 54 passed (10 yeni test_oauth.py).

## v0.2.3 — Hata kodları + loop-yutma çözümü

- `guard --once` tur hatasında exit 0 yerine **2** (temiz gibi raporlanmaz).
- `config test` bağlantı hatasında exit 1 yerine **2** (ortam hatası).
- `_guard_cycle` status döndürür (`ok/error-config/error-imap`); sürekli modda ardışık hata
  sayacı (3 turda tek toast + `guard_errors.jsonl`, spam yok).
- `_fetch_and_analyze` err_kind (`config/imap`) + mail-başına izolasyon (tek bozuk mail turu öldürmez).
- `_safe_notify`: bildirim ölürse `except-pass` yerine stderr + `guard_errors.jsonl` izi.
- `_load_seen` bozuk JSON'u sessizce silmez: `.bozuk-<tarih>` yedeğine alır.
- `main()`: `KeyboardInterrupt`→2 (temiz "İptal"), `BrokenPipeError`→0, beklenmeyen crash→tek satır + 2.
- `emit --out` yazma hatası traceback yerine stderr uyarısı.
- KONTROL: ERR-01/02/03 eklendi. Sonuç: 35/35 PASS. Testler: 44 passed.

## v0.2.2 — TOOL-only + 0 WARN

- SİLİNDİ: `app/main.py`, `app/api/`, `app/limiter.py`, `cli serve`, `Dockerfile`, `docker-compose.yml`.
- requirements 14→8 paket (fastapi/starlette/uvicorn/slowapi/multipart/httpx gitti).
- Faydalı sınırlar tool'a taşındı: folder<=128 + `..` yasak, limit 1-100, body<=30k, interval min 1.
- KONTROL TOOL-only: TOOL-01..04 + SURUM-04 + OPS-04, API/Docker checkleri kalktı. Sonuç: 32/32 PASS.
- README/SISTEM tool-only. 4 WARN kapandı (API-01, IMAP-01, OPS-01/02).

## v0.2.1 — KONTROL sistemi

- Yeni CLI: `elfsec kontrol [--kategori SURUM,TEMIZLE,ANALIZ,API,IMAP,OPS] [--fail-only] [--fail-on] [--json --out]`.
- `app/kontrol.py`: 32 sızma denetimi (XSS 7 + tracking/URL/DoS + bypass 7 + API 4 + IMAP/guard/secret 5 + surum/ops 6).
- Hacker-gözü: script/onerror/js:/data:/svg/style-url/iframe, prompt-inj TR/EN, spoof, punycode, shortener, oversize 100k, auth bypass, folder `../INBOX`, http-webhook, 600k DoS.
- Sonuç FAIL-önce + sürüm sırasına göre optimize (`yol_haritasi`), exit-code `0/1/2` CI uyumlu.
- Test: `tests/test_kontrol.py` (3 test). Toplam 31 test yeşil.

## v0.2.0 — Tek exe + arka plan eklenti

- TEK EXE: `elfsec.exe` CLI + guard birleşik (`--tray/--background` konsolu gizler).
- `guard --notify on/off`, `--action notify-only/quarantine/delete` (default dokunmaz).
- Windows Toast: HIGH+ alarm + hata/bug bildirimi (ek bağımlılıksız, PowerShell fallback).
- Webhook https-only zorunlu (http atlanır).
- `setup_autostart.ps1` exe-öncelikli, `build_exe.ps1` tek artifact smoke-testli.
- Merkezi `app/__version__.py`, `SISTEM_DURUMU.md` çizelgesi.

## v0.1.0 — Baz

- CLI/API/SDK, sanitizer, offline motor, IMAP, guard, Docker, CI, exe.
