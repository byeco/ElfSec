# ElfSec — Store Publishing Guide (Chrome / Edge / Firefox)

## 1. Ready Packages

Build all 3 packages cleanly with:
```bash
cd backend
python scripts/pack_extensions.py --out ..
```
Outputs:
- `elfsec-extension-chrome-edge-store.zip` → Upload to **Chrome Web Store** and **Microsoft Edge Add-ons** (automatically omits `"key"` and `"browser_specific_settings"`).
- `elfsec-extension-firefox-amo.zip` → Upload to **Firefox Add-ons (AMO)** (automatically keeps `browser_specific_settings.gecko.id` and uses `"background.scripts"`).
- `elfsec-browser-extension.zip` → Unpacked developer / GitHub release package (includes the pinned developer `"key"`).

## 2. Store Listing Copy (English)

- **Name:** ElfSec
- **Category:** Productivity / Privacy & Security
- **Short Summary (<= 132 chars):**
  Open-source, local phishing, brand impersonation, link, and download security guard for webmail.
- **Detailed Description:**
  ElfSec is an open-source, privacy-first email, link, and download security shield developed by byeco (https://byeco.com.tr | https://github.com/byeco/ElfSec) under the GNU GPL-3.0 license.

  Key Features:
  - Real-time local security analysis for supported webmail providers.
  - Brand impersonation detection and official domain verification for recognized organizations and government domains (.gov, .gov.tr, .edu.tr), while excluding user-hosted content domains.
  - Link hover security preview showing the true destination domain, protocol badge, verified institution badge, and domain-mismatch warnings.
  - Safe confirmation modal when clicking suspicious or mismatched links.
  - Hidden 1x1 tracking pixel counter inside emails.
  - Browser download guard inspecting double extensions (.pdf.exe), Unicode RLO spoofing, risky scripts, and suspicious download sources.
  - Optional desktop bridge to local elfsec.exe Native Messaging Host for deep offline file inspection (PE/MotW/LOLBin).
  - 100% on-device processing: zero cloud APIs, zero telemetry, zero external requests.
- **Privacy Policy URL:** `https://github.com/byeco/ElfSec/blob/main/extension/PRIVACY.md`
- **Homepage / Website URL:** `https://byeco.com.tr`
- **Source Code Repository:** `https://github.com/byeco/ElfSec`

### Store Listing Copy (Türkçe)

- **Ad:** ElfSec
- **Kategori:** Verimlilik / Gizlilik ve Güvenlik
- **Kısa Özet (<= 132 karakter):**
  Web e-posta için açık kaynaklı, yerel oltalama, marka taklidi, bağlantı ve indirme güvenlik kalkanı.
- **Ayrıntılı Açıklama:**
  ElfSec, byeco (https://byeco.com.tr | https://github.com/byeco/ElfSec) tarafından GNU GPL-3.0 lisansı altında geliştirilen açık kaynaklı ve gizlilik odaklı bir e-posta, bağlantı ve indirme güvenlik kalkanıdır.

  Öne Çıkan Özellikler:
  - Desteklenen web e-posta sağlayıcıları içinde gerçek zamanlı, cihaz içi güvenlik analizi.
  - Tanınmış kurumlar ve resmi alan adları (.gov, .gov.tr, .edu.tr) için marka taklidi tespiti ve resmi alan adı doğrulaması (kullanıcı içerik barındırma alan adları hariç tutulur).
  - Bağlantı üzerine gelindiğinde gerçek hedef alan adını, protokol rozetini, doğrulanmış kurum rozetini ve alan adı uyuşmazlığı uyarılarını gösteren güvenlik önizlemesi.
  - Şüpheli veya hedefi uyuşmayan bağlantılara tıklandığında güvenli onay ekranı.
  - E-postalar içindeki gizli 1x1 takip pikseli sayacı.
  - Çift uzantıları (.pdf.exe), Unicode RLO sahteciliğini, riskli betikleri ve şüpheli indirme kaynaklarını inceleyen tarayıcı indirme kalkanı.
  - Derin çevrimdışı dosya incelemesi (PE/MotW/LOLBin) için yerel elfsec.exe Native Messaging Host ile isteğe bağlı masaüstü köprüsü.
  - %100 cihaz üzerinde işlem: bulut API yok, telemetri yok, dış ağ isteği yok.

## 3. Permission Justifications (for Store Review)

| Permission | Why it is needed |
|---|---|
| `nativeMessaging` | Optional bridge to the local desktop `elfsec.exe` engine (`com.elfsec.guard`) for deep offline PE/MotW/LOLBin file inspection and shared alert logging. Falls back cleanly to the embedded JS engine when absent. |
| `contextMenus` | Adds "Scan Selected Text with ElfSec" and "Scan Link with ElfSec" to the right-click context menu. |
| `storage` | Saves user preferences, trusted domain allowlist, custom verified brands, and local scan statistics in `chrome.storage.local`. |
| `downloads` | Inspects downloaded filenames, double extensions (`.pdf.exe`), Unicode RLO spoofing, and source URLs locally when a browser download starts or completes. |
| `notifications` | Displays local desktop alerts when a high-risk download or context-menu threat is detected. |
| Content script hosts (`mail.google.com`, `outlook.*`, `mail.yahoo.com`, `mail.yandex.*`, `www.icloud.com/mail*`, `mail.proton.me`) | Reads only the opened email DOM locally inside the browser to display the security banner, verified-brand badge, tracking-pixel count, hover preview, and suspicious-link modal. No data is sent to any server. |

**Data handling notes for reviewers:** All analysis runs on-device. When the optional Native Host is connected, only HIGH/CRITICAL findings are appended to a rotating local log (max 2 MB) for desktop notifications; see [PRIVACY.md](PRIVACY.md). The extension has no `host_permissions`, no `externally_connectable`, no remote code, and no telemetry.

## 4. Linking Store Extension ID to Desktop `elfsec.exe`

Once Chrome Web Store / Edge Add-ons assigns your live Store Extension ID (visible inside the extension's **Settings / Options** page):
```cmd
elfsec.exe browser register --extension-id YOUR_STORE_EXTENSION_ID
```
