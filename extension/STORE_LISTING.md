# ElfSec Browser Extension — Store Publishing Guide (Chrome / Edge / Firefox)

## 1. Ready Packages

Build all 3 packages cleanly with:
```bash
cd backend
python scripts/pack_extensions.py --out ../dist_ext
```
Outputs:
- `elfsec-extension-chrome-edge-store.zip` → Upload to **Chrome Web Store** and **Microsoft Edge Add-ons** (automatically strips `"key"` & `"browser_specific_settings"`).
- `elfsec-extension-firefox-amo.zip` → Upload to **Firefox Add-ons (AMO)** (automatically keeps `browser_specific_settings.gecko.id` and uses `"background.scripts"`).
- `elfsec-browser-extension.zip` → Unpacked developer / GitHub release package (keeps pinned `"key"`).

## 2. Store Listing Copy

- **Name:** ElfSec Security Extension / ElfSec Güvenlik Eklentisi
- **Category:** Productivity / Privacy & Security
- **Privacy Policy URL:** `https://github.com/byeco/ElfSec/blob/main/extension/PRIVACY.md`
- **Short Summary (EN):** 100% local phishing, brand impersonation, link-hover, tracking-pixel, and download guard for Gmail, Outlook Web & more.
- **Short Summary (TR):** Gmail, Outlook Web ve diğer webmail'ler için %100 yerel phishing, marka taklidi, link önizleme ve indirme güvenlik kalkanı.

## 3. Permission Justifications (for Store Review)

| Permission | Why it is needed |
|---|---|
| `nativeMessaging` | Optional bridge to the local desktop `elfsec.exe` engine (`com.elfsec.guard`) for deep offline PE/MotW/LOLBin file inspection and shared alert logging. Falls back cleanly to the embedded JS engine when absent. |
| `contextMenus` | Adds "Scan Selected Text with ElfSec" and "Scan Link with ElfSec" to the right-click context menu. |
| `storage` | Saves user preferences, trusted domain allowlist, custom verified brands, and local scan statistics in `chrome.storage.local`. |
| `downloads` | Inspects downloaded filenames, double extensions (`.pdf.exe`), Unicode RLO spoofing, and source URLs locally when a browser download starts or completes. |
| `notifications` | Displays local desktop alerts when a high-risk download is detected. |
| Content script hosts (`mail.google.com`, `outlook.*`, `mail.yahoo.com`, `mail.yandex.*`, `www.icloud.com/mail*`, `mail.proton.me`) | Reads only the opened email DOM locally inside the browser to display the security banner, verified-brand badge, tracking-pixel count, hover preview, and suspicious-link modal. No data is sent to any server. |

**Data handling notes for reviewers:** All analysis is local. When the optional Native Host is connected, only HIGH/CRITICAL findings are appended to a rotating local log (max 2 MB) for desktop notifications; see [PRIVACY.md](PRIVACY.md). The extension has no `host_permissions`, no `externally_connectable`, no remote code, and no telemetry.

## 4. Linking Store Extension ID to Desktop `elfsec.exe`

Once Chrome Web Store / Edge Add-ons assigns your live Store Extension ID (visible inside the extension's **Ayarlar / Options** page):
```cmd
elfsec.exe browser register --extension-id YOUR_STORE_EXTENSION_ID
```
