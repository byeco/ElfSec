# ElfSec — E-posta Güvenlik Analiz Tool'u

IMAP'tan e-posta çeken, **zararlı HTML'i temizleyen** ve **oltalama (phishing) / prompt-injection** analizi yapan güvenlik tool'u.
Aynı çekirdek hem **terminalden (CLI)** hem de **API (FastAPI)** üzerinden kullanılır; Next.js frontend'i API'ye konuşur.

## İndirme (kullanıcılar için — `elfsec.exe`)

Kodla uğraşmak istemeyen kullanıcı **tek dosya** indirir, Python gerekmez:

1. GitHub **Releases** sayfasından `elfsec.exe`'yi indir (`v*` tag'inde otomatik üretilir, ~19 MB).
2. Yanına bir `.env` dosyası koy (tek gizli bilgi IMAP şifrendir — API anahtarı gerekmez):
   ```ini
   IMAP_HOST=imap.gmail.com
   IMAP_USER=sen@gmail.com
   IMAP_PASSWORD=uygulama-sifresi
   ```
3. Çalıştır:
   ```cmd
   elfsec.exe health
   elfsec.exe guard --unseen --interval 10
   ```

> Not: exe imzasız olduğu için Windows SmartScreen ilk açılışta uyarabilir → "Yine de çalıştır".
> Geliştiriciler için kaynaktan kurulum aşağıda. Exe'yi kendin üretmek istersen: `backend\scripts\build_exe.ps1`.

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
| **Savunma** | API'ye saniyede yüzlerce istek atanları bloklar (DDoS/Brute-Force kalkanı). Şifreler koda gömülmez, katmanlı config'den okunur (ortam > `--config` > kullanıcı dosyası). | `slowapi` + katmanlı ayar |

## Kurulum (geliştirici)

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate         # Windows  |  source .venv/bin/activate  (Linux)
pip install -r requirements.txt

# Etkileşimli kurulum (önerilen — şifreler şifreli saklanır)
python -m app.cli config init
python -m app.cli config test   # IMAP bağlantısını dene
```

> Eski usul `.env` dosyası da hâlâ çalışır (`backend/.env` → örneği `.env.example`), ama yeni ayar sistemi önceliklidir. Hiçbir config dosyası GitHub'a yüklenmez.

## Ayar sistemi (katmanlı config)

Düz `.env` yerine öncelikli katmanlar + doğrulama + şifreli saklama:

| Öncelik | Kaynak | Ne için |
|---|---|---|
| 1 (en yüksek) | Ortam değişkenleri (`IMAP_PASSWORD=...`) | Docker / CI |
| 2 | `--config YOLU` / `ELFSEC_CONFIG` | Çoklu profil (ev/iş) |
| 3 | `%APPDATA%/ElfSec/elfsec.env` (Win) / `~/.config/elfsec/elfsec.env` | Kullanıcı ayarı (önerilen) |
| 4 | `backend/.env` | Geriye uyumluluk |

```bash
python -m app.cli config init                                  # sihirbazla kur
python -m app.cli config show                                  # etkin ayarlar (şifreler maskeli)
python -m app.cli config set IMAP_PASSWORD                     # gizli sorar, şifreli yazar
python -m app.cli config get IMAP_HOST                         # scriptler için tek değer
python -m app.cli config path                                  # hangi dosya kullanılıyor?
python -m app.cli config test                                  # ayar + IMAP bağlantı testi
python -m app.cli --config is.env triage --limit 20            # farklı profille çalış
```

- **Şifre kasası:** tek gizli bilgi `IMAP_PASSWORD`'dür; dosyada `ENC(...)` olarak Windows DPAPI ile o kullanıcı hesabına bağlı şifrelenir — başka kullanıcı/PC'de çözülemez, ek bağımlılık yok. Başka API anahtarı yoktur.
- **Türkçe doğrulama:** hatalı ayarda `CONFIG HATASI` + hangi anahtar + nasıl düzeltilir basılır, exit-code 2.
- API (`serve`) tarafı da aynı merkezi ayarı okur (`--config` → `ELFSEC_CONFIG` ile alt sürece aktarılır).

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

# 6) API sunucusunu başlat
python -m app.cli serve
# veya: uvicorn app.main:app --reload
```

### PC açıkken sürekli koruma (guard)

`guard` PC açık olduğu sürece her N dakikada okunmamışları tarar, HIGH ve üstünü **alarma** çevirir, aynı mail için twice alarm vermez (state dosyası), alarmları `guard_alerts.jsonl`'a yazar, istersen webhook'a POST eder:

```bash
# Elle başlat (test)
python -m app.cli guard --unseen --interval 10

# Tek tur (zamanlanmış görev / cron alternatifi)
python -m app.cli guard --unseen --once --fail-on HIGH

# Webhook ile (Discord/Slack/SIEM)
python -m app.cli guard --unseen --interval 10 --webhook https://ornek/webhook
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

Mantık: girişten ~1 dk sonra (Wi-Fi gelsin diye) `guard_start.cmd` üzerinden `guard` başlar, arka planda her 10 dk tarar. IMAP kesilirse guard çökmez — uyarı basıp sonraki tura devam eder.

### Exit-code sözleşmesi (otomasyon/CI kapısı)

| Kod | Anlam |
|---|---|
| `0` | Temiz / başarılı (risk `--fail-on` eşiğinin altında) |
| `1` | Şüpheli — risk eşiğe ulaştı (örn. `--fail-on HIGH` + HIGH bulundu) |
| `2` | Ortam/kullanım hatası (IMAP yok, dosya yok, bağlantı hatası) |

```bash
# CI örneği: şüpheli mail varsa pipeline'ı durdur
python -m app.cli analyze-file --path "gelen/*.eml" --fail-on MEDIUM --quiet
# veya: triage ile kutuyu her sabah tara, HIGH varsa alarm üret
python -m app.cli triage --limit 50 --unseen --fail-on HIGH --out gunluk.jsonl
```

### Yazılımcılar için SDK (import edilebilir çekirdek)

CLI/API ile aynı pipeline, kod içinden tek çağrı:

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
python -m pytest tests -q        # 24 test: sanitizer, yerel motor, API/CLI/guard/ayar sözleşmesi
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

## API olarak kullanım

| Endpoint | Açıklama |
|---|---|
| `GET /health` | Servis durumu (`imap_configured`, `engine`) |
| `GET /api/emails?folder=INBOX&limit=20&unseen_only=false` | Çek + temizle (dönüş: `safe_html`, `plain_text`, `urls`, `tracking_pixels_blocked`) |
| `GET /api/emails/folders` | IMAP klasör listesi |
| `POST /api/analyze` | `{subject, body, sender}` → tehdit raporu |
| `GET /docs` | Swagger UI |

```bash
curl http://localhost:8000/health
curl -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" \
  -d "{\"subject\":\"Fatura\",\"body\":\"<p>Borcu öde http://x.tk/o</p>\",\"sender\":\"a@b.com\"}"
```

**Rate limit:** varsayılan `30/dakika`, e-posta `20/dakika`, analiz `10/dakika` (katmanlı config'den ayarlanır). Aşınca `429` döner.

## Next.js ile bağlama

`CORS_ORIGINS=http://localhost:3000` varsayılanı hazır. Frontend `GET /api/emails` ile listeler, `safe_html`'i `iframe sandbox` içinde gösterir, `POST /api/analyze` ile rozet (LOW/MEDIUM/HIGH/CRITICAL) basar.

## Docker / Azure (B1s)

```bash
docker compose up --build        # API -> http://localhost:8000
```

## Proje yapısı

```
backend/
  app/
    main.py              # FastAPI çekirdeği + slowapi + CORS
    cli.py               # TOOL arayüzü (health/fetch/analyze/triage/guard/serve/config) + exit-code
    sdk.py               # import edilebilir çekirdek (scan_text/scan_file/sanitize)
    config.py            # ayar şeması (pydantic)
    settings_store.py    # katmanlı config + Türkçe doğrulama
    secret_vault.py      # DPAPI şifreli saklama (ENC...)
    schemas.py           # katı veri doğrulama (pydantic)
    limiter.py           # paylaşımlı rate-limit
    api/                 # routes_health / routes_emails / routes_analyze
    services/
      imap_client.py     # imap-tools (thread'de)
      sanitizer.py       # bleach + bs4/lxml
      ai_analyzer.py     # yerel motor (anahtarsız, deterministik)
  tests/                 # pytest: sanitizer + yerel motor + api/cli/guard/ayar sözleşmesi
  elfsec.py              # exe giriş noktası (PyInstaller)
  scripts/               # build_exe / setup_autostart / remove_autostart
  requirements.txt  Dockerfile  .env.example
.github/workflows/release.yml  # v* tag'inde elfsec.exe derleyip Releases'e yükler
```

## Güvenlik notları

- Gmail için normal şifre değil **uygulama şifresi** kullanın.
- `safe_html` bile olsa frontend'de tıklanabilir linkleri yeni sekmede + `rel=nofollow` açın.
- ElfSec bilinçli olarak **hiçbir API anahtarı kullanmaz**: analiz yereldir, e-posta içeriği cihazdan çıkmaz.
- **API koruması:** `API_TOKEN` boşsa `/api/*` korumasızdır — yalnızca yerel kullanım içindir. LAN'a/Internete açıyorsanız mutlaka token koyun:
  ```bash
  python -m app.cli config set API_TOKEN --secret
  curl -H "Authorization: Bearer <token>" http://localhost:8000/api/emails?limit=5
  ```
  (`/health` ve `/` her zaman açıktır; token yoksa sunucu açılışta uyarır.)
- **Log gizliliği:** `triage --out` ve `guard_alerts.jsonl` mail özetleri içerir — bu dosyaları paylaşmayın, `--webhook` yalnızca güvendiğiniz adrese verin.
- **Bağımlılıklar:** sürümler `requirements.txt`'te sabitlidir; `pip-audit` temiz (bilinen zafiyet yok), CI her push'ta test + audit koşar, Dependabot haftalık güvenlik güncellemesi açar. Azure'ya çıkarken önüne TLS ters vekil (Caddy/Nginx) koyun — API kendisi HTTP konuşur. Kapsayıcı root'suz çalışır (`USER elfsec`).
