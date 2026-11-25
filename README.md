# ElfSec — Windows Güvenlik Eklentisi & E-posta Analiz Aracı (v1.6.0)

[🇹🇷 Türkçe](#-türkçe) | [🇬🇧 English](#-english)

> **%100 Yerel · API Anahtarsız · Tek `elfsec.exe` · 205+ Test · 80/80 `kontrol` PASS · 8 Sabit Bağımlılık**
>
> Tarayıcıdaki webmail (**Gmail, Outlook Web, Yahoo, Yandex, iCloud, Proton Mail**), masaüstü mail uygulamaları (**Outlook Classic/New, Windows Mail, `.eml`/`.msg`, IMAP/OAuth2**), **Windows dosya/İndirilenler** ve **pano (ClickFix)** tehditlerini cihazınızdan dışarı tek byte çıkarmadan tespit eden yerel **Windows Güvenlik Eklentisi**.

---

## 🇹🇷 Türkçe

### Neleri Korur? (4 Güvenlik Katmanı)

| Katman | Ne Yapar? | Bileşenler |
|---|---|---|
| **1. Tarayıcı Webmail Eklentisi (`extension/`)** | **Gmail, Outlook Web, Yahoo, Yandex, iCloud, Proton Mail** içinde açılan postayı okur; canlı risk şeridi, marka doğrulama rozeti, 1x1 takip pikseli sayacı, link hover hedef önizleme, modern şüpheli link engel modalı ve tarayıcı **İndirme Kalkanı** sunar. | Manifest V3 + `_locales` + `options.html` + `elfsec.exe native-host` |
| **2. Masaüstü Mail & IMAP** | **Outlook Classic** (`INetCache\Content.Outlook\*`), **Yeni Outlook** ve **Windows Mail** ek önbelleklerini otomatik izler; `.eml`/`.msg` dosyalarına sağ-tık tarama ekler. İsteğe bağlı olarak IMAP/OAuth2 ile gelen kutusunu periyodik tarar (`triage`, `guard`). | `file_watcher` + `imap_client` + `oauth` |
| **3. Windows Dosya & İndirilenler** | İndirilenler klasörünü ve Gezgin sağ-tık seçili dosya/klasörleri tarar: çift uzantı (`fatura.pdf.exe`), Unicode RLO gizleme, `.pdf`/`.docx`/`.jpg` içine gizlenmiş `MZ` (PE/EXE) dosyası, NTFS Mark-of-the-Web (`Zone.Identifier`), LOLBin script/`.lnk` analizi ve `.quarantined` karantina kasası. | `file_scanner` + `scan-path` + `quarantine-file` |
| **4. Pano (Clipboard) / ClickFix** | Kopyalanan `powershell -w hidden -enc`, `mshta http://...`, `cmd /c curl ...`, `certutil -urlcache` gibi ClickFix tuzaklarını ve phishing URL'lerini yakalayıp Windows Toast ile uyarır. | `clipboard_guard` + `agent --tray` |
| **5. Doğrulanmış Marka Göndericileri** | Apple (`no_reply@email.apple.com`, `appleid@id.apple.com`, `email.apple.com`, `id.apple.com`), Google, Microsoft, PayPal, bankalar ve e-Devlet gibi resmi adresleri SPF/DKIM/DMARC ile çapraz doğrular (`VERIFIED_STRONG` / `IMPERSONATION` / `SPOOFED`). | `verified_senders` + `elfsec verified` |

---

### İndirme ve Kurulum

#### Seçenek A — Windows Kurulum Sihirbazı (`ElfSecSetup.exe` — Önerilen)

1. Doğrudan **[ElfSecSetup.exe](https://github.com/byeco/ElfSec/releases/latest/download/ElfSecSetup.exe)** kurulum dosyasını ([GitHub Releases](https://github.com/byeco/ElfSec/releases)) indirin ve çift tıklayarak çalıştırın *(veya kaynak koddan `powershell -ExecutionPolicy Bypass -File installer\build_installer.ps1` ile derleyin)*.
2. Çerçevesiz grafiksel kurulum sihirbazı tek tıkla otomatik olarak:
   - `elfsec.exe` ve `extension\` klasörünü `C:\Program Files\ElfSec\` altına kurar,
   - `ElfSecGuard` Windows Servisini (SYSTEM yetkisinde İndirilenler + Outlook/Windows Mail ek önbelleği + opsiyonel IMAP koruyucusu) başlatır,
   - Windows Gezgini sağ-tık menüsünü (tüm dosyalar, klasörler, `.eml`, `.msg`) ve `elfsec://` protokolünü kaydeder,
   - Chrome, Edge, Brave ve Firefox Native Messaging Host (`com.elfsec.guard`) kayıtlarını ekler,
   - Sistem Tepsisi + Pano koruma ajanını (`elfsec.exe agent --tray`) ve **ElfSec Güvenlik Merkezi** penceresini başlatır.

   > **Alternatif (Taşınabilir `elfsec.exe` / PowerShell):** Yalnızca tek çalıştırılabilir dosya kullanmak isterseniz Releases sayfasından `elfsec.exe` indirip Yönetici PowerShell ile kurabilirsiniz:
   > ```powershell
   > cd backend
   > powershell -ExecutionPolicy Bypass -File scripts\install_windows_plugin.ps1
   > ```
   > Kaldırmak için Windows *Ayarlar → Uygulamalar → ElfSec Güvenlik Sistemi* veya Yönetici PowerShell'de `powershell -ExecutionPolicy Bypass -File scripts\uninstall_windows_plugin.ps1` çalıştırın.
   > İmzalanmamış exe ilk açılışta Windows SmartScreen uyarısı verirse *"Ek bilgi → Yine de çalıştır"* seçilebilir.

#### Seçenek B — Tarayıcı Webmail Eklentisini Yükleme (Chrome / Edge / Brave)

1. Tarayıcıda `chrome://extensions` (veya `edge://extensions`) adresini açın.
2. Sağ üstten **Geliştirici modu (Developer mode)** anahtarını açın.
3. **Paketlenmemiş öğe yükle (Load unpacked)** düğmesine tıklayın ve `C:\Program Files\ElfSec\extension` (veya repodaki `extension\`) klasörünü seçin.
4. Eklenti, sabit Public Key sayesinde otomatik olarak `jkmbfppdffpiodlmikbdfdihdkejcfjj` kimliğini alır ve `com.elfsec.guard` Native Host'una bağlanır. Gmail veya Outlook Web'de bir e-posta açtığınızda üstte canlı güvenlik şeridi görünür.

*(Native Host kaydını tek başına yönetmek için: `elfsec.exe browser register` · `elfsec.exe browser status` · `elfsec.exe browser unregister`. Mağaza paketlerini üretmek için: `python backend/scripts/pack_extensions.py` → `elfsec-extension-chrome-edge-store.zip`, `elfsec-extension-firefox-amo.zip`)*

---

### Nasıl Çalışır?

```
OKU (IMAP / .eml / DOM / Dosya / Pano)
  -> TEMİZLE (Bleach + BeautifulSoup/lxml — XSS/script/takip pikseli temizliği)
  -> ANALİZ ET (yerel deterministik kurallar — API anahtarı yok, internet yok)
  -> RAPORLA (0-100 risk skoru, LOW/MEDIUM/HIGH/CRITICAL, Toast & karantina)
```

Örnek terminal çıktısı:
```cmd
elfsec.exe analyze --subject "Hesabiniz kapanacak!" --sender "destek@banka-secure.tk" --body "Hemen tikla http://evil.tk/verify"
→ [XXX] RISK 80/100 [CRITICAL] (motor: elfsec-local/1.0)
```

---

### Temel Komutlar (CLI)

```powershell
# Eklenti, servis ve tarayıcı durumu
elfsec.exe plugin status
elfsec.exe service status
elfsec.exe browser status

# Dosya, klasör veya pano tarama
elfsec.exe scan-path "C:\Users\ad\Downloads\fatura.pdf" --notify
elfsec.exe quarantine-file "C:\Users\ad\Downloads\supheli.ps1"
elfsec.exe watch --once
elfsec.exe clipboard --once --text "powershell -w hidden -enc JAB4"

# E-posta (IMAP + OAuth2) kurulumu ve tarama
elfsec.exe config setup                 # kolay sihirbaz (Gmail/Outlook/Yahoo/Yandex/iCloud/Özel)
elfsec.exe config login --provider outlook   # veya gmail (OAuth2, şifresiz)
elfsec.exe config test
elfsec.exe triage --limit 50 --unseen --fail-on HIGH --out triage.jsonl
elfsec.exe guard --unseen --interval 10 --tray

# Panel, kurallar, gönderici doğrulama ve öz-denetim
elfsec.exe dashboard
elfsec.exe rules show
elfsec.exe verified list
elfsec.exe verified check "Apple <appleid@id.apple.com>" --auth-results "spf=pass dkim=pass"
elfsec.exe kontrol --fail-only
```

**Çıkış kodları:** `0` = temiz / başarılı · `1` = `--fail-on` eşiğinde tehdit bulundu · `2` = ortam / yapılandırma hatası.

<details>
<summary>Katmanlı Ayar Sistemi, OAuth2 ve Web API (Next.js) Detayları (TR)</summary>

- **Ayar önceliği:** Ortam değişkenleri → `--config` / `ELFSEC_CONFIG` → `%APPDATA%\ElfSec\elfsec.env` (veya `~/.config/elfsec/elfsec.env`) → `C:\ProgramData\ElfSec\elfsec.env` → `backend\.env`.
- **Şifre kasası:** Kullanıcı sırları Windows DPAPI ile `ENC(...)`, servis sırları makine düzeyi DPAPI ile `ENCM(...)` biçiminde saklanır; başka kullanıcı/makinede çözülemez.
- **OAuth2 (Outlook / Gmail):** Windows Mail'deki mevcut oturum sessizce alınamaz; kullanıcı kendi Azure / Google Desktop Client ID'si ile tarayıcıdan bir kez onay verir (`elfsec.exe config login --provider outlook|gmail`), refresh token şifreli kasada saklanır.
- **Web API (`elfsec serve`):** İsteğe bağlı stdlib-only HTTP sunucusu (`GET /v1/health`, `POST /v1/analyze`, `POST /v1/sanitize`). `ELFSEC_API_TOKEN` ortam değişkeni olmadan ağa açık başlamayı reddeder; `web/elfsec.js` ve `web/route-example.js` Next.js App Router sunucu tarafı örneği içerir.

</details>

---

### Geliştirici Kurulumu, Testler & SDK

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt

python -m pytest tests -q                # 194 test
python -m app.cli kontrol --fail-only    # 76 güvenlik denetimi (SURUM,TEMIZLE,ANALIZ,TOOL,IMAP,OPS,SERVE,WIN)
```

Python SDK:
```python
from app.sdk import scan_text, scan_file, sanitize

report = scan_text(subject="Fatura", body="<p>Hemen öde http://evil.tk/o</p>", sender="a@b.com")
print(report["risk_level"], report["risk_score"], report["reasons"])
```

---

## 🇬🇧 English

### What Does It Protect? (4 Security Layers)

| Layer | What It Does | Components |
|---|---|---|
| **1. Browser Webmail Extension (`extension/`)** | Inspects opened emails in **Gmail, Outlook Web, Yahoo, Yandex, iCloud, and Proton Mail**; adds a live risk banner, verified-brand badge, 1x1 tracking-pixel counter, link-hover target preview, blocking modal, and browser **Downloads Guard**. | Manifest V3 + `_locales` + `options.html` + `elfsec.exe native-host` |
| **2. Desktop Mail Apps & IMAP** | Automatically monitors **Outlook Classic** (`INetCache\Content.Outlook\*`), **New Outlook**, and **Windows Mail** attachment cache folders; adds Explorer right-click analysis for `.eml` and `.msg` files; supports periodic IMAP/OAuth2 scanning (`triage`, `guard`). | `file_watcher` + `imap_client` + `oauth` |
| **3. Windows File & Downloads Protection** | Scans Downloads and Explorer right-clicked files/folders for double extensions (`invoice.pdf.exe`), Unicode RLO filename spoofing, PE `MZ` executables disguised as `.pdf`/`.docx`/`.jpg`, NTFS Mark-of-the-Web (`Zone.Identifier`), LOLBin `.ps1`/`.bat`/`.vbs`/`.hta`/`.lnk` scripts, and isolates threats as `.quarantined`. | `file_scanner` + `scan-path` + `quarantine-file` |
| **4. Clipboard / ClickFix Guard** | Detects pasted ClickFix lures (`powershell -w hidden -enc`, `mshta http://...`, `cmd /c curl ...`, `certutil -urlcache`) and phishing URLs, alerting immediately via Windows Toast notifications. | `clipboard_guard` + `agent --tray` |
| **5. Verified Brand Senders** | Cross-checks official brand domains & reachable addresses (Apple, Google, Microsoft, PayPal, banks, e-Devlet, etc.) against SPF/DKIM/DMARC headers (`VERIFIED_STRONG` / `IMPERSONATION` / `SPOOFED`). | `verified_senders` + `elfsec verified` |

---

### Download & Installation

#### Option A — Windows Graphical Installer (`ElfSecSetup.exe` — Recommended)

1. Download **[ElfSecSetup.exe](https://github.com/byeco/ElfSec/releases/latest/download/ElfSecSetup.exe)** directly from [GitHub Releases](https://github.com/byeco/ElfSec/releases) *(or build from source with `powershell -ExecutionPolicy Bypass -File installer\build_installer.ps1`)*.
2. Double-click the setup wizard to automatically:
   - Install `elfsec.exe` and `extension\` into `C:\Program Files\ElfSec\`,
   - Install and start the `ElfSecGuard` Windows Service (SYSTEM privilege — watches all users' Downloads + Outlook/Windows Mail attachment caches + optional IMAP),
   - Register Windows Explorer right-click menus (all files, folders, `.eml`, `.msg`) and the `elfsec://` URI protocol,
   - Register Native Messaging hosts (`com.elfsec.guard`) for Chrome, Edge, Brave, and Firefox,
   - Launch the user-session System Tray + Clipboard + Service Alert Bridge (`elfsec.exe agent --tray`) and the **ElfSec Security Center** desktop window.

   > **Alternative (Portable `elfsec.exe` / PowerShell):** If you prefer the standalone binary, download `elfsec.exe` from Releases and run in Administrator PowerShell:
   > ```powershell
   > cd backend
   > powershell -ExecutionPolicy Bypass -File scripts\install_windows_plugin.ps1
   > ```
   > To uninstall, use Windows *Settings → Apps → ElfSec Güvenlik Sistemi* or run `powershell -ExecutionPolicy Bypass -File scripts\uninstall_windows_plugin.ps1`.
   > Because the binary is currently unsigned, Windows SmartScreen may show a warning on first run → *"More info → Run anyway"*.

#### Option B — Load the Browser Webmail Extension (Chrome / Edge / Brave)

1. Navigate to `chrome://extensions` (or `edge://extensions`).
2. Enable **Developer mode** in the top-right corner.
3. Click **Load unpacked** and select `C:\Program Files\ElfSec\extension` (or `extension/` in this repo).
4. The manifest's pinned public key deterministically sets the extension ID to `jkmbfppdffpiodlmikbdfdihdkejcfjj`, connecting automatically to `com.elfsec.guard`. Opening any email in Gmail or Outlook Web immediately displays the ElfSec risk banner.

*(Manage browser Native Host registration manually via: `elfsec.exe browser register` · `elfsec.exe browser status` · `elfsec.exe browser unregister`. Build store zip packages via: `python backend/scripts/pack_extensions.py` → `elfsec-extension-chrome-edge-store.zip`, `elfsec-extension-firefox-amo.zip`)*

---

### How It Works

```
READ (IMAP / .eml / DOM / File / Clipboard)
  -> SANITIZE (Bleach + BeautifulSoup/lxml — strips XSS/scripts/1x1 tracking pixels)
  -> ANALYZE (offline deterministic engine — zero API keys, zero cloud)
  -> REPORT (0-100 risk score, LOW/MEDIUM/HIGH/CRITICAL, Windows Toast & quarantine)
```

Sample CLI run:
```cmd
elfsec.exe analyze --subject "Your account will be closed!" --sender "x@bank-secure.tk" --body "Click now http://evil.tk/verify"
→ [XXX] RISK 80/100 [CRITICAL] (engine: elfsec-local/1.0)
```

---

### Key CLI Commands & Exit Codes

```powershell
# Plugin, service, and browser status
elfsec.exe plugin status
elfsec.exe service status
elfsec.exe browser status

# File, directory, and clipboard scanning
elfsec.exe scan-path "C:\Users\me\Downloads\invoice.pdf" --notify
elfsec.exe quarantine-file "C:\Users\me\Downloads\suspicious.ps1"
elfsec.exe watch --once
elfsec.exe clipboard --once --text "powershell -w hidden -enc JAB4"

# Email (IMAP + OAuth2) setup and continuous guard
elfsec.exe config setup
elfsec.exe config login --provider outlook   # or gmail
elfsec.exe config test
elfsec.exe triage --limit 50 --unseen --fail-on HIGH --out triage.jsonl
elfsec.exe guard --unseen --interval 10 --tray

# Dashboard, rules, verified senders, and self-audit
elfsec.exe dashboard
elfsec.exe rules show
elfsec.exe verified list
elfsec.exe verified check "Apple <appleid@id.apple.com>" --auth-results "spf=pass dkim=pass"
elfsec.exe kontrol --fail-only
```

**Exit codes:** `0` = clean / success · `1` = threat reached `--fail-on` threshold · `2` = environment / configuration error.

<details>
<summary>Layered Config, OAuth2, and Web API (Next.js) Details (EN)</summary>

- **Config precedence:** Environment variables → `--config` / `ELFSEC_CONFIG` → `%APPDATA%\ElfSec\elfsec.env` (or `~/.config/elfsec/elfsec.env`) → `C:\ProgramData\ElfSec\elfsec.env` → `backend\.env`.
- **Encrypted vault:** User secrets use Windows DPAPI `ENC(...)`, machine/service secrets use `ENCM(...)` (`CRYPTPROTECT_LOCAL_MACHINE`).
- **OAuth2 (Outlook / Gmail):** Credentials from the Windows Mail app are never extracted; users register their own Azure / Google Desktop Client ID and approve once in the browser (`elfsec.exe config login --provider outlook|gmail`).
- **Optional Web API (`elfsec serve`):** Stdlib-only HTTP server (`GET /v1/health`, `POST /v1/analyze`, `POST /v1/sanitize`) with fail-closed `ELFSEC_API_TOKEN` auth, 60/min rate limit, 1 MB body cap, and CORS allowlist. Server-side Next.js helpers live in `web/elfsec.js` and `web/route-example.js` (supported on Windows/Linux VPS; unsupported on serverless platforms like Vercel).

</details>

---

### Developer Setup, Tests & SDK

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows | source .venv/bin/activate (Linux)
pip install -r requirements.txt

python -m pytest tests -q                 # 194 tests
python -m app.cli kontrol --fail-only     # 76 self-audits (SURUM,TEMIZLE,ANALIZ,TOOL,IMAP,OPS,SERVE,WIN)
```

Python SDK:
```python
from app.sdk import scan_text, scan_file, sanitize

report = scan_text(subject="Invoice", body="<p>Pay now http://evil.tk/o</p>", sender="a@b.com")
print(report["risk_level"], report["risk_score"], report["reasons"])
```

---

### Project Structure

```text
extension/                   # Manifest V3 browser extension (Gmail, Outlook Web, Yahoo, Yandex, iCloud, Proton)
  manifest.json              # Pinned public key (ID: jkmbfppdffpiodlmikbdfdihdkejcfjj) + Firefox Gecko ID
  background.js              # Native Messaging bridge + context menus + badge updates
  content.js / banner.css    # Webmail DOM extraction + live risk banner + link click guard
  fallback_analyzer.js       # Offline browser fallback engine
  popup.html / popup.js      # Extension status, toggle, quick scanner, recent alerts
backend/
  app/
    cli.py                   # CLI entry points + protocol & browser native-host routing
    native_host.py           # Chrome/Edge/Brave/Firefox stdio JSON-framing host
    win_service.py           # Native Win32 SCM service (ElfSecGuard) + ServiceRunner
    win_plugin.py            # Registry (Explorer/Protocol/Run/Browsers) + AlertBridge + agent
    tray.py                  # Pure ctypes Win32 System Tray icon & menu
    notify.py                # Windows Toast notifications (email / file / clipboard)
    kontrol.py               # 76 security self-audits (SURUM,TEMIZLE,ANALIZ,TOOL,IMAP,OPS,SERVE,WIN)
    services/
      file_scanner.py        # Offline PE magic, RLO, MotW, LOLBin, .eml/.html & .quarantined vault
      ai_analyzer.py         # Deterministic local phishing/prompt-injection engine
      sanitizer.py           # Bleach + BeautifulSoup/lxml HTML sanitizer
      imap_client.py         # Async-threaded IMAP client & quarantine
    watchers/
      file_watcher.py        # Downloads + Outlook/Windows Mail cache watcher
      clipboard_guard.py     # ClickFix & phishing clipboard guard
  scripts/                   # install_windows_plugin.ps1 / uninstall_windows_plugin.ps1 / build_exe.ps1
  tests/                     # 194 pytest unit & integration tests
installer/
  setup_wizard_gui.py        # Frameless Windows setup wizard (ElfSecSetup.exe)
  build_installer.ps1        # Builds installer\Output\ElfSecSetup.exe
  elfsec.iss                 # Inno Setup Admin installer alternative
.github/workflows/           # ci.yml (pytest/coverage/kontrol/ruff/pip-audit) & release.yml (ElfSecSetup.exe + elfsec.exe)
```

### Security Notes

- **Zero API keys / local-only:** Email bodies, attachments, and clipboard content never leave your PC.
- **Log privacy:** `guard_alerts.jsonl` and `triage --out` may contain email/file summaries; use `--redact` to mask PII (emails, IBAN, national IDs, card numbers) and `--retention-days` to prune old logs. Use `--webhook` only with trusted `https://` endpoints.
- **Dependencies:** Pinned to 9 core packages in [backend/requirements.txt](backend/requirements.txt); checked with `pip-audit`, `ruff`, and Dependabot.
