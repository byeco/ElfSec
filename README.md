# ElfSec — E-posta Güvenlik Analiz Tool'u (v1.2.1)

IMAP'tan e-posta çeken, **zararlı HTML'i temizleyen** ve **oltalama (phishing) / prompt-injection** analizi yapan güvenlik tool'u.
TOOL-only: tek `elfsec.exe` — CLI + arka plan guard + `kontrol` denetimi. Server/frontend/Docker yok.

> EN: ElfSec is a student-built, offline email security tool (Python). It fetches mail over IMAP,
> sanitizes malicious HTML, and scores phishing / prompt-injection locally — no API keys, no cloud,
> your mail never leaves your PC. Single `elfsec.exe`, 161 tests, 66 self-audits (`kontrol`) green. v1.1.0 adds an opt-in stdlib-only web API (`elfsec serve`) so your own site can score mail.

## İndirme (kullanıcılar için — `elfsec.exe`)

Kodla uğraşmak istemeyen kullanıcı **tek dosya** indirir, Python gerekmez:

1. GitHub **Releases** sayfasından `elfsec.exe`'yi indir (`v*` tag'inde otomatik üretilir, ~19 MB).
2. Yanına bir `.env` dosyası koy (tek gizli bilgi IMAP şifrendir — API anahtarı gerekmez):
   ```ini
   IMAP_HOST=imap.gmail.com
   IMAP_USER=sen@gmail.com
   IMAP_PASSWORD=uygulama-sifresi
   ```
3. Çalıştır — iki yol var:
   - **Çift tıkla:** menü açılır (kurulum / durum / tara / koruma / denetim), pencere kapanmaz.
   - **Terminalden:**
   ```cmd
   elfsec.exe health
   elfsec.exe guard --unseen --interval 10
   ```

> Not: exe imzasız olduğu için Windows SmartScreen ilk açılışta uyarabilir → "Yine de çalıştır".
> Geliştiriciler için kaynaktan kurulum aşağıda. Exe'yi kendin üretmek istersen: `backend\scripts\build_exe.ps1`.

## Nasıl çalışıyor? (kısaca)

Şüpheli bir mail geldiğini düşün. ElfSec onu 4 adımda inceliyor:

```
OKU  ->  TEMİZLE  ->  ANALİZ ET  ->  RAPORLA
```

1. **OKU:** Mail kutuna IMAP ile bağlanıp maili çekiyor (başlık + gövde). İstersen tek bir maili dosyadan da verebiliyorsun.
2. **TEMİZLE:** Mailin HTML'indeki tehlikeli kısımları (`<script>`, gizli takip pikseli, `javascript:` linkleri...) atıp güvenli düz metin çıkarıyor. Linkleri analiz için kenara not ediyor.
3. **ANALİZ ET:** Temiz metne bakıp puan veriyor (0-100): "acilen tıkla!" baskısı var mı? Gönderici bankaymış gibi mi davranıyor? Link `.tk` gibi şüpheli uzantılı mı? Cevap adresi gönderenle uyuşuyor mu? İnternet yok, yapay zekâ servisi yok — hepsi kendi yazdığım kurallarla, bilgisayarın içinde oluyor.
4. **RAPORLA:** Sonucu yazıyor: risk skoru + seviyesi (LOW/MEDIUM/HIGH/CRITICAL) + nedenleri + ne yapman gerektiği ("linke tıklama, eki açma...").

Örnek:
```cmd
python -m app.cli analyze --subject "Hesabınız kapanacak!" --sender "x@banka-secure.tk" --body "Hemen tıkla http://evil.tk/verify"
→ [XXX] RISK 80/100 [CRITICAL] — Oltalama kalıbı + şüpheli link + gönderici taklidi
```

## Tool'un mantığı (pipeline)

```
OKU  ->  TEMİZLE  ->  ANALİZ ET  ->  RAPORLA
```

| Aşama | Ne yapar | Kütüphane |
|---|---|---|
| **1. OKU** | Gmail/Outlook'a IMAP ile bağlanır, klasörleri listeler, e-postaları çeker (başlık + gövde). Sunucuyu kilitlememek için `asyncio.to_thread` ile arka planda çalışır. | `imap-tools` |
| **2. TEMİZLE (kalp)** | `<script>/<style>/<iframe>/<img>` ve `on*` handler'ları atar, `javascript:` URL'leri keser, **1x1 takip piksellerini** sayıp engeller, linkleri `rel="nofollow noopener"` yapar. Sonra saf düz metin çıkarır. URL'ler temizlikten **önce** toplanır (analiz için). | `bleach` + `beautifulsoup4` + `lxml` |
| **3. ANALİZ ET** | Temiz metin + URL + göndericiyi inceler. **API anahtarı yok, internet yok** — deterministik yerel motor: oltalama kalıpları, homoglif/punycode ve IP URL'ler, gönderici taklidi, aciliyet baskısı, ek tuzağı, prompt injection. E-posta içeriği asla üçüncü partiye gitmez. | saf Python (`ai_analyzer`) |
| **4. RAPORLA** | `risk_score (0-100)`, `risk_level (LOW/MEDIUM/HIGH/CRITICAL)`, gerekçeler, şüpheli URL'ler, `phishing/prompt-injection` bayrakları, aksiyon önerisi. | `pydantic` |
| **Savunma** | Klasör/limit/interval girdileri doğrulanır (`..` yasak, limit 1-100), gövde 30k'ya kırpılır, 500k DoS kesmesi. Şifreler koda gömülmez, katmanlı config'den okunur (ortam > `--config` > kullanıcı dosyası). | katmanlı ayar + `kontrol` |

## Kurulum (geliştirici)

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate         # Windows  |  source .venv/bin/activate  (Linux)
pip install -r requirements.txt

# Kolay kurulum: e-postanı yaz, sağlayıcıyı menüden seç (tahmini Enter ile onayla),
# tarayıcı doğru sayfada açılır, bağlantı anında test edilir
python -m app.cli config setup            # veya: elfsec.exe config setup
python -m app.cli config test             # IMAP bağlantısını dene
```

> Eski usul `.env` dosyası da hâlâ çalışır (`backend/.env` → örneği `.env.example`), ama yeni ayar sistemi önceliklidir. Hiçbir config dosyası GitHub'a yüklenmez.

## Ayar sistemi (katmanlı config)

Düz `.env` yerine öncelikli katmanlar + doğrulama + şifreli saklama:

| Öncelik | Kaynak | Ne için |
|---|---|---|
| 1 (en yüksek) | Ortam değişkenleri (`IMAP_PASSWORD=...`) | CI / otomasyon |
| 2 | `--config YOLU` / `ELFSEC_CONFIG` | Çoklu profil (ev/iş) |
| 3 | `%APPDATA%/ElfSec/elfsec.env` (Win) / `~/.config/elfsec/elfsec.env` | Kullanıcı ayarı (önerilen) |
| 4 | `backend/.env` | Geriye uyumluluk |

```bash
python -m app.cli config setup                                 # kolay kurulum (önerilir)
python -m app.cli config init                                  # klasik sihirbaz
python -m app.cli config show                                  # etkin ayarlar (şifreler maskeli)
python -m app.cli config set IMAP_PASSWORD                     # gizli sorar, şifreli yazar
python -m app.cli config get IMAP_HOST                         # scriptler için tek değer
python -m app.cli config path                                  # hangi dosya kullanılıyor?
python -m app.cli config test                                  # ayar + IMAP bağlantı testi
python -m app.cli --config is.env triage --limit 20            # farklı profille çalış
```

- **Şifre kasası:** gizli bilgiler (`IMAP_PASSWORD`, `OAUTH_REFRESH_*`) dosyada `ENC(...)` olarak Windows DPAPI ile o kullanıcı hesabına bağlı şifrelenir — başka kullanıcı/PC'de çözülemez, ek bağımlılık yok.
- **Türkçe doğrulama:** hatalı ayarda `CONFIG HATASI` + hangi anahtar + nasıl düzeltilir basılır, exit-code 2.
- Klasör/limit sertliği: `folder` max 128 + `..` yasak, `limit` 1-100, `interval` min 1 dk.

## OAuth ile giriş (önerilir — şifre yok)

Windows'taki hazır mail hesabı **sessizce devralınamaz** (kimlik bilgileri Mail uygulamasına bağlıdır, admin bile çıkaramaz — tasarım gereği). Bunun yerine bir kez tarayıcıda onay verirsiniz, refresh-token kasada durur:

**1) Outlook (Hotmail/Outlook/Office365):**
1. [Azure Portal](https://portal.azure.com) → Microsoft Entra ID → App registrations → New registration (isim: `ElfSec`, hesap türü: kişisel Microsoft hesapları, redirect: Public client).
2. Authentication → Mobile and desktop applications → `http://127.0.0.1` (MSAL loopback için) + "Allow public client flows: Yes".
3. API permissions → Add → `Office 365 Exchange Online` → Delegated → `IMAP.AccessAsUser.All` + `offline_access` → Grant admin consent **gerekmez** (kişisel hesap).
4. Overview → **Application (client) ID**'yi kopyalayın.

**2) Gmail:**
1. [Google Cloud Console](https://console.cloud.google.com) → yeni proje → APIs & Services → Enable **Gmail API**.
2. OAuth consent screen → External → test kullanıcısına kendi e-postanızı ekleyin.
3. Credentials → Create Credentials → OAuth client ID → **Desktop app** → **Client ID**'yi kopyalayın.

**3) ElfSec'e bağlama:**
```powershell
elfsec.exe config login --provider outlook   # veya gmail
# client-id sorar (bir kez), tarayıcı açılır, onay ver, kapat
elfsec.exe config test        # IMAP bağlantısı OK
elfsec.exe config logout      # çıkış (token temizlenir)
```
Not: paylaşımlı/hazır client-id kullanılmaz — herkes kendi kaydını açar (kota ve güvenlik gereği). OAuth ek bağımlılık getirmez (stdlib).

## TOOL olarak kullanım (terminal)

```bash
cd backend
.venv\Scripts\activate

# 1) Durum kontrolü
python -m app.cli health
python -m app.cli health --json

# 2) E-postaları çek ve özetle
python -m app.cli fetch --limit 10
python -m app.cli fetch --limit 5 --unseen --folder INBOX
python -m app.cli fetch --limit 20 --json --out mailler.json

# 3) Tek e-postayı analiz et (pipe destekli)
python -m app.cli analyze --subject "Hesabınız kapanacak!" --sender "x@banka-secure.tk" --body "Hemen tıkla http://evil.tk/verify"
cat supheli.eml | python -m app.cli analyze --stdin --json
python -m app.cli analyze --body-file supheli.html --json --out rapor.json

# 4) Dosya/glob analizi (toplu)
python -m app.cli analyze-file --path mail.html
python -m app.cli analyze-file --path "ornekler/*.eml" --fail-on MEDIUM --json

# 5) TRİAGE — güvenlikçi iş akışı: son N maili çek+analiz et, riske göre sırala
python -m app.cli triage --limit 50
python -m app.cli triage --limit 50 --unseen --min-score 25 --top 10
python -m app.cli triage --limit 100 --fail-on HIGH --out triage.jsonl   # SIEM'e göm

# 6) Güvenlik denetimi (sızma testleri + sürümlü yol haritası)
python -m app.cli kontrol --fail-only
python -m app.cli kontrol --kategori TOOL,IMAP --json --out kontrol.json
```

### PC açıkken sürekli koruma (guard)

`guard` PC açık olduğu sürece her N dakikada okunmamışları tarar, HIGH ve üstünü **alarma** çevirir, aynı mail için twice alarm vermez (state dosyası), alarmları `guard_alerts.jsonl`'a yazar, istersen webhook'a POST eder:

```bash
# Elle başlat (test)
python -m app.cli guard --unseen --interval 10

# Tek tur (zamanlanmış görev / cron alternatifi)
python -m app.cli guard --unseen --once --fail-on HIGH

# Webhook ile (Discord/Slack/SIEM) — 3 deneme + auth başlığı
python -m app.cli guard --unseen --interval 10 --webhook https://ornek/webhook \
  --webhook-header "Authorization: Bearer X"

# PII maskeli + eski log budamalı koruma
python -m app.cli guard --unseen --interval 10 --redact --retention-days 30

# Tek maili elle karantinaya al (toast "Karantinaya al" butonu da bunu tetikler)
python -m app.cli quarantine 123 --folder INBOX
python -m app.cli quarantine 123 --action delete --yes   # kalıcı, onaylı
```

**Otomatik başlatma — PC her açıldığında devreye girsin (yönetici gerekmez):**

```powershell
cd backend
powershell -ExecutionPolicy Bypass -File scripts\setup_autostart.ps1 -Unseen
# test:   schtasks /run /tn ElfSecGuard
# durum:  schtasks /query /tn ElfSecGuard
# loglar: backend\guard_alerts.jsonl
# kaldır: powershell -ExecutionPolicy Bypass -File scripts\remove_autostart.ps1
```

Mantık: girişten ~1 dk sonra (Wi-Fi gelsin diye) `guard_start.cmd` üzerinden `guard` başlar, arka planda her 10 dk tarar. IMAP kesilirse guard çökmez — hatayı sınıflandırır (`config`/`imap`), `guard_errors.jsonl`'ye yazar, 3 üst üste hatada tek toast atar, sonraki tura devam eder. Bozuk state dosyası silinmez, `.bozuk-<tarih>` yedeğine alınır. Tek bozuk mail turu öldürmez, atlanıp sayılır.

### Exit-code sözleşmesi (otomasyon/CI kapısı)

| Kod | Anlam |
|---|---|
| `0` | Temiz / başarılı (risk `--fail-on` eşiğinin altında) |
| `1` | Şüpheli — risk eşiğe ulaştı (örn. `--fail-on HIGH` + HIGH bulundu) |
| `2` | Ortam/kullanım hatası (IMAP yok, dosya yok, bağlantı hatası, `guard --once` tur hatası, `config test` bağlantı hatası dahil) |

```bash
# CI örneği: şüpheli mail varsa pipeline'ı durdur
python -m app.cli analyze-file --path "gelen/*.eml" --fail-on MEDIUM --quiet
# veya: triage ile kutuyu her sabah tara, HIGH varsa alarm üret
python -m app.cli triage --limit 50 --unseen --fail-on HIGH --out gunluk.jsonl
```

### Web sitesinden kullanım (API)

Site bu adresten skor çeker — API'yi sitenin sunucusunda çalıştır, tarayıcıdan POST at:

```cmd
REM sunucuda (token ŞART, ağa açıkken tokensuz başlamaz):
set ELFSEC_API_TOKEN=uzun-rastgele-bir-deger
elfsec.exe serve --host 127.0.0.1 --port 8765 --cors-origins https://benimsitem.com
```

```js
// sitede (tarayıcı):
const r = await fetch("http://127.0.0.1:8765/v1/analyze", {
  method: "POST",
  headers: { "Content-Type": "application/json", "Authorization": "Bearer UZUN-TOKEN" },
  body: JSON.stringify({ subject: "Hesabınız kapanacak!", sender: "x@banka-secure.tk", body: "Hemen tıkla http://evil.tk/verify" })
});
const rapor = await r.json(); // { ok, risk_level, risk_score, reasons, ... }
```

Uçlar: `GET /v1/health` · `POST /v1/analyze` · `POST /v1/sanitize`.
Güvenlik notları: token sadece ortam değişkeninden okunur (koda gömme!),
varsayılan localhost'tur, rate-limit 60/dk, gövde limiti 1MB, loglara mail
içeriği yazılmaz. Üretimde HTTPS önüne (reverse proxy) koy.

#### Next.js sunucunda çalışır mı?

`web/elfsec.js` (hazır istemci, bağımlılıksız) + `web/route-example.js` (örnek API Route) var.
Önce ortamına bak — dürüst tablo:

| Ortam | Çalışır mı? | Nasıl |
|---|---|---|
| Kendi VPS'in (Windows) | ✅ | `elfsec.exe serve` koy, Next.js route'undan `fetch` ile çağır |
| Kendi VPS'in (Linux) | ✅ | `elfsec.exe` OLMAZ (Windows programı) — Python kaynağından çalıştır: `pip install -r backend/requirements.txt` sonra `python -m app.cli serve`. Analiz yolu Linux'ta saf çalışır (Windows'a özel import yok) |
| Vercel / serverless | ❌ | Uzun yaşayan process yasak + exe çalışmaz — API'yi ayrı bir sunucuda tutup URL ile bağla |

Kural: tarayıcı ElfSec'e direkt bağlanmaz. `elfsec.js`'i **sadece sunucu tarafında** (API Route / Server Action) kullan,
token `process.env.ELFSEC_API_TOKEN`'da durur (`NEXT_PUBLIC_` ile başlayan değişkene ASLA koyma).
Uçtan uca doğrulandı: Node istemci → Python API → skor (v1.2.0).

### Yazılımcılar için SDK (import edilebilir çekirdek)

CLI ile aynı pipeline, kod içinden tek çağrı:

```python
from app.sdk import scan_text, scan_file, sanitize

report = scan_text(subject="Fatura", body="<p>Borcu öde http://x.tk/o</p>", sender="a@b.com")
print(report["risk_level"], report["risk_score"], report["reasons"])

clean = sanitize("<script>x</script><p>selam</p>")  # AI'sız, hızlı: safe_html + plain_text + urls
```

### Testler (geliştirme odaklı)

```bash
cd backend
.venv\Scripts\activate
python -m pytest tests -q        # 161 test: sanitizer, motor, TOOL CLI/guard/ayar/kontrol/headers/oauth/ops/serve
python -m app.cli kontrol --fail-only   # 66 sızma denetimi (SURUM,TEMIZLE,ANALIZ,TOOL,IMAP,OPS,SERVE)
```

### Kurumsal kullanım (v0.6.0)

```bash
# Motor kuralları (ağırlık aç/kapa, varsayılana dön)
python -m app.cli rules show
python -m app.cli rules set urgency 40
python -m app.cli rules disable url_keyword
python -m app.cli rules reset

# SIEM'e CEF akışı
python -m app.cli triage --limit 50 --cef gunluk.cef
python -m app.cli guard --unseen --interval 10 --cef-log alarmlar.cef

# Güncelleme kontrolü
python -m app.cli update --check
# Kurulum paketi: installer\elfsec.iss (Inno Setup) ile ElfSecSetup.exe üretilir
```

Katkı akışı: test yaz → `pytest` yeşil → PR. Temizlik katmanını gevşeten her değişiklik testleri kırmalı — bilinçli tasarlandı.

**Çıktı örneği:**
```
[XXX] RISK 80/100 [CRITICAL] (motor: elfsec-local/1.0)
Özet: Yerel analiz: 4 bulgu, skor 80/100.
Nedenler:
  - Oltalama kalıbı: aciliyet + hesap/kapanma/doğrulama baskısı.
  - Şüpheli TLD içeren URL: http://evil.tk/verify
  - Gönderici taklidi: kurumsal kimlik + bedava posta alan adı (gmail.com).
Phishing: True | Prompt-injection: False
Takip-piksel engeli: 0
Öneri: Bağlantılara tıklama, eki açma, göndericiyi resmi kanaldan doğrula.
```

## KONTROL olarak kullanım (sızma testleri)

```bash
python -m app.cli kontrol --fail-only
python -m app.cli kontrol --kategori TOOL,IMAP --fail-on LOW
```

Kategoriler: `SURUM,TEMIZLE,ANALIZ,TOOL,IMAP,OPS`. Sonuç FAIL-önce + sürüm sırasına göre optimize edilir.
Exit: `0` temiz, `1` açık var, `2` hata.

## Proje yapısı

```
backend/
  app/
    cli.py               # TOOL arayüzü (health/fetch/analyze/triage/guard/config/kontrol) + exit-code
    kontrol.py           # sürümlü denetim + sızma testleri (TOOL-only)
    notify.py            # Windows Toast (ek bağımlılıksız)
    tray.py              # tek-exe arka plan (konsol gizleme + tepsi)
    sdk.py               # import edilebilir çekirdek (scan_text/scan_file/sanitize)
    config.py            # ayar şeması (pydantic, TOOL-only)
    settings_store.py    # katmanlı config + Türkçe doğrulama
    secret_vault.py      # DPAPI şifreli saklama (ENC...)
    schemas.py           # TOOL iç doğrulama (pydantic)
    services/
      imap_client.py     # imap-tools + quarantine (thread'de)
      sanitizer.py       # bleach + bs4/lxml
      ai_analyzer.py     # yerel motor (anahtarsız, deterministik)
  tests/                 # pytest: sanitizer + yerel motor + TOOL CLI/guard/ayar/kontrol sözleşmesi
  elfsec.py              # tek-exe giriş noktası (PyInstaller, guard --tray gizler)
  scripts/               # build_exe / setup_autostart / remove_autostart
  requirements.txt  .env.example
.github/workflows/release.yml  # v* tag'inde tek elfsec.exe derleyip Releases'e yükler
```

## Güvenlik notları

- Gmail için normal şifre değil **uygulama şifresi** kullanın.
- ElfSec bilinçli olarak **hiçbir API anahtarı kullanmaz**: analiz yereldir, e-posta içeriği cihazdan çıkmaz. Server/frontend/Docker yoktur.
- **Log gizliliği:** `triage --out` ve `guard_alerts.jsonl` mail özetleri içerir — bu dosyaları paylaşmayın, `--webhook` yalnızca `https://` güvendiğiniz adrese verin (`http` atlanır).
- **Bağımlılıklar:** sürümler `requirements.txt`'te sabitlidir (serversiz, 8 paket); `pip-audit` temiz, CI her push'ta test + audit koşar, Dependabot haftalık güvenlik güncellemesi açar.
