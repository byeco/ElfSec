# ElfSec — Email Security Analysis Tool (v1.2.1)

Fetches email over IMAP, **sanitizes malicious HTML**, and runs **phishing / prompt-injection** analysis locally.
TOOL-only: single `elfsec.exe` — CLI + background guard + `kontrol` self-audit. No server / frontend / Docker.

> Student-built, offline email security tool (Python). It fetches mail over IMAP,
> sanitizes malicious HTML, and scores phishing / prompt-injection locally — no API keys, no cloud,
> your mail never leaves your PC. Single `elfsec.exe`, 161 tests, 66 self-audits (`kontrol`) green. v1.1.0 adds an opt-in stdlib-only web API (`elfsec serve`) so your own site can score mail.

## Download (for users — `elfsec.exe`)

No code, no Python needed — just download a single file:

1. Download `elfsec.exe` from the GitHub **Releases** page (auto-built on every `v*` tag, ~19 MB).
2. Put a `.env` file next to it (the only secret is your IMAP password — no API key needed):
   ```ini
   IMAP_HOST=imap.gmail.com
   IMAP_USER=you@gmail.com
   IMAP_PASSWORD=app-password
   ```
3. Run it — two ways:
   - **Double-click:** opens an interactive menu (setup / status / scan / protection / audit), the window stays open.
   - **From terminal:**
   ```cmd
   elfsec.exe health
   elfsec.exe guard --unseen --interval 10
   ```

> Note: because the exe is unsigned, Windows SmartScreen may warn on first launch → "Run anyway".
> For developers, source install is below. To build the exe yourself: `backend\scripts\build_exe.ps1`.

## How it works? (short version)

Imagine a suspicious email arrives. ElfSec inspects it in 4 steps:

```
READ  ->  SANITIZE  ->  ANALYZE  ->  REPORT
```

1. **READ:** Connects to your mailbox over IMAP and pulls the mail (headers + body). You can also pass a single mail from a file.
2. **SANITIZE:** Strips dangerous parts from the mail HTML (`<script>`, hidden tracking pixels, `javascript:` links...) and extracts safe plain text. Links are collected on the side for analysis.
3. **ANALYZE:** Scores the clean text (0-100): is there "click now!" pressure? Does the sender pretend to be a bank? Is the link on a shady TLD like `.tk`? Does the reply address match the sender? No internet, no AI service — all with local hand-written rules, inside your own PC.
4. **REPORT:** Prints the result: risk score + level (LOW/MEDIUM/HIGH/CRITICAL) + reasons + what to do ("don't click the link, don't open the attachment...").

Example:
```cmd
python -m app.cli analyze --subject "Your account will be closed!" --sender "x@bank-secure.tk" --body "Click now http://evil.tk/verify"
→ [XXX] RISK 80/100 [CRITICAL] — Phishing pattern + suspicious link + sender spoof
```

## Tool pipeline

```
READ  ->  SANITIZE  ->  ANALYZE  ->  REPORT
```

| Stage | What it does | Library |
|---|---|---|
| **1. READ** | Connects to Gmail/Outlook over IMAP, lists folders, fetches emails (header + body). Runs in background via `asyncio.to_thread` to avoid blocking the server. | `imap-tools` |
| **2. SANITIZE (core)** | Drops `<script>/<style>/<iframe>/<img>` and `on*` handlers, cuts `javascript:` URLs, counts and blocks **1x1 tracking pixels**, adds `rel="nofollow noopener"` to links. Then extracts pure plain text. URLs are collected **before** sanitizing (for analysis). | `bleach` + `beautifulsoup4` + `lxml` |
| **3. ANALYZE** | Inspects clean text + URLs + sender. **No API key, no internet** — deterministic local engine: phishing patterns, homoglyph/punycode and IP URLs, sender spoofing, urgency pressure, attachment traps, prompt injection. Email content never goes to a third party. | pure Python (`ai_analyzer`) |
| **4. REPORT** | `risk_score (0-100)`, `risk_level (LOW/MEDIUM/HIGH/CRITICAL)`, reasons, suspicious URLs, `phishing/prompt-injection` flags, action recommendation. | `pydantic` |
| **Defense** | Folder/limit/interval inputs are validated (`..` forbidden, limit 1-100), body truncated to 30k, 500k DoS cutoff. Passwords are never hard-coded, read from layered config (env > `--config` > user file). | layered settings + `kontrol` |

## Installation (developers)

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate         # Windows  |  source .venv/bin/activate  (Linux)
pip install -r requirements.txt

# Easy setup: type your email, pick the provider from the menu (confirm guess with Enter),
# the browser opens on the right page, connection is tested instantly
python -m app.cli config setup            # or: elfsec.exe config setup
python -m app.cli config test             # test the IMAP connection
```

> The old-style `.env` file still works (`backend/.env` → see `.env.example`), but the new settings system takes precedence. No config file is ever uploaded to GitHub.

## Settings system (layered config)

Instead of a flat `.env`, prioritized layers + validation + encrypted storage:

| Priority | Source | Use for |
|---|---|---|
| 1 (highest) | Environment variables (`IMAP_PASSWORD=...`) | CI / automation |
| 2 | `--config PATH` / `ELFSEC_CONFIG` | Multiple profiles (home/work) |
| 3 | `%APPDATA%/ElfSec/elfsec.env` (Win) / `~/.config/elfsec/elfsec.env` | User settings (recommended) |
| 4 | `backend/.env` | Backwards compatibility |

```bash
python -m app.cli config setup                                 # easy setup (recommended)
python -m app.cli config init                                  # classic wizard
python -m app.cli config show                                  # active settings (passwords masked)
python -m app.cli config set IMAP_PASSWORD                     # asks secretly, writes encrypted
python -m app.cli config get IMAP_HOST                         # single value for scripts
python -m app.cli config path                                  # which file is in use?
python -m app.cli config test                                  # settings + IMAP connection test
python -m app.cli --config work.env triage --limit 20          # run with a different profile
```

- **Password vault:** secrets (`IMAP_PASSWORD`, `OAUTH_REFRESH_*`) are stored as `ENC(...)` encrypted with Windows DPAPI, bound to that user account — cannot be decrypted on another user/PC, no extra dependency.
- **Turkish validation:** on bad config prints `CONFIG ERROR` + which key + how to fix, exit code 2.
- Folder/limit strictness: `folder` max 128 + `..` forbidden, `limit` 1-100, `interval` min 1 min.

## Login with OAuth (recommended — no password)

The ready-made mail account on Windows **cannot be silently inherited** (credentials are bound to the Mail app, even admins can't extract them — by design). Instead you approve once in the browser, the refresh token stays in the vault:

**1) Outlook (Hotmail/Outlook/Office365):**
1. [Azure Portal](https://portal.azure.com) → Microsoft Entra ID → App registrations → New registration (name: `ElfSec`, account type: personal Microsoft accounts, redirect: Public client).
2. Authentication → Mobile and desktop applications → `http://127.0.0.1` (for MSAL loopback) + "Allow public client flows: Yes".
3. API permissions → Add → `Office 365 Exchange Online` → Delegated → `IMAP.AccessAsUser.All` + `offline_access` → Grant admin consent **not needed** (personal account).
4. Overview → copy the **Application (client) ID**.

**2) Gmail:**
1. [Google Cloud Console](https://console.cloud.google.com) → new project → APIs & Services → Enable **Gmail API**.
2. OAuth consent screen → External → add your own email as a test user.
3. Credentials → Create Credentials → OAuth client ID → **Desktop app** → copy the **Client ID**.

**3) Connect to ElfSec:**
```powershell
elfsec.exe config login --provider outlook   # or gmail
# asks for client-id once, browser opens, approve, close
elfsec.exe config test        # IMAP connection OK
elfsec.exe config logout      # logout (clears tokens)
```
Note: no shared/built-in client-id — everyone creates their own registration (quota and security). OAuth adds no extra dependency (stdlib).

## Usage as a TOOL (terminal)

```bash
cd backend
.venv\Scripts\activate

# 1) Health check
python -m app.cli health
python -m app.cli health --json

# 2) Fetch and summarize emails
python -m app.cli fetch --limit 10
python -m app.cli fetch --limit 5 --unseen --folder INBOX
python -m app.cli fetch --limit 20 --json --out mails.json

# 3) Analyze a single email (pipe supported)
python -m app.cli analyze --subject "Your account will be closed!" --sender "x@bank-secure.tk" --body "Click now http://evil.tk/verify"
cat suspicious.eml | python -m app.cli analyze --stdin --json
python -m app.cli analyze --body-file suspicious.html --json --out report.json

# 4) File/glob analysis (batch)
python -m app.cli analyze-file --path mail.html
python -m app.cli analyze-file --path "samples/*.eml" --fail-on MEDIUM --json

# 5) TRIAGE — analyst workflow: fetch+analyze last N mails, sort by risk
python -m app.cli triage --limit 50
python -m app.cli triage --limit 50 --unseen --min-score 25 --top 10
python -m app.cli triage --limit 100 --fail-on HIGH --out triage.jsonl   # feed into SIEM

# 6) Security audit (penetration checks + versioned roadmap)
python -m app.cli kontrol --fail-only
python -m app.cli kontrol --kategori TOOL,IMAP --json --out kontrol.json
```

### Continuous protection while the PC is on (guard)

`guard` scans unread mail every N minutes while the PC is on, turns HIGH and above into **alarms**, never alarms twice for the same mail (state file), writes alarms to `guard_alerts.jsonl`, optionally POSTs to a webhook:

```bash
# Start manually (test)
python -m app.cli guard --unseen --interval 10

# Single run (scheduled task / cron alternative)
python -m app.cli guard --unseen --once --fail-on HIGH

# With webhook (Discord/Slack/SIEM) — 3 retries + auth header
python -m app.cli guard --unseen --interval 10 --webhook https://example/webhook \
  --webhook-header "Authorization: Bearer X"

# PII-masked + old-log-pruned protection
python -m app.cli guard --unseen --interval 10 --redact --retention-days 30

# Manually quarantine a single mail (toast "Quarantine" button triggers this too)
python -m app.cli quarantine 123 --folder INBOX
python -m app.cli quarantine 123 --action delete --yes   # permanent, confirmed
```

**Autostart — kick in on every boot (no admin needed):**

```powershell
cd backend
powershell -ExecutionPolicy Bypass -File scripts\setup_autostart.ps1 -Unseen
# test:   schtasks /run /tn ElfSecGuard
# status: schtasks /query /tn ElfSecGuard
# logs:   backend\guard_alerts.jsonl
# remove: powershell -ExecutionPolicy Bypass -File scripts\remove_autostart.ps1
```

Logic: ~1 min after login (so Wi-Fi is up) `guard_start.cmd` starts `guard`, scans in background every 10 min. If IMAP drops, guard doesn't crash — it classifies the error (`config`/`imap`), logs to `guard_errors.jsonl`, sends a single toast after 3 consecutive errors, then continues. A corrupt state file is not deleted, it's backed up to `.corrupt-<date>`. One broken mail never kills the run, it's skipped and counted.

### Exit-code contract (automation/CI gate)

| Code | Meaning |
|---|---|
| `0` | Clean / success (risk below `--fail-on` threshold) |
| `1` | Suspicious — risk reached the threshold (e.g. `--fail-on HIGH` + HIGH found) |
| `2` | Environment/usage error (no IMAP, no file, connection error, `guard --once` run error, `config test` connection error) |

```bash
# CI example: stop the pipeline if suspicious mail exists
python -m app.cli analyze-file --path "incoming/*.eml" --fail-on MEDIUM --quiet
# or: scan the mailbox every morning with triage, alarm on HIGH
python -m app.cli triage --limit 50 --unseen --fail-on HIGH --out daily.jsonl
```

### Usage from a website (API)

Your site fetches the score from here — run the API on your site's server, POST from the browser:

```cmd
REM on the server (token REQUIRED, refuses to start network-open without token):
set ELFSEC_API_TOKEN=a-long-random-value
elfsec.exe serve --host 127.0.0.1 --port 8765 --cors-origins https://mysite.com
```

```js
// on the site (browser):
const r = await fetch("http://127.0.0.1:8765/v1/analyze", {
  method: "POST",
  headers: { "Content-Type": "application/json", "Authorization": "Bearer LONG-TOKEN" },
  body: JSON.stringify({ subject: "Your account will be closed!", sender: "x@bank-secure.tk", body: "Click now http://evil.tk/verify" })
});
const report = await r.json(); // { ok, risk_level, risk_score, reasons, ... }
```

Endpoints: `GET /v1/health` · `POST /v1/analyze` · `POST /v1/sanitize`.
Security notes: token is read only from environment (never hard-code!),
default is localhost, rate-limit 60/min, body limit 1MB, mail content is never
written to logs. In production put it behind HTTPS (reverse proxy).

#### Does it run on a Next.js server?

`web/elfsec.js` (ready client, zero deps) + `web/route-example.js` (sample API Route) included.
Check your environment first — honest table:

| Environment | Works? | How |
|---|---|---|
| Own VPS (Windows) | ✅ | Drop `elfsec.exe serve`, call it with `fetch` from your Next.js route |
| Own VPS (Linux) | ✅ | `elfsec.exe` does NOT work (Windows binary) — run from Python source: `pip install -r backend/requirements.txt` then `python -m app.cli serve`. Analysis path runs purely on Linux (no Windows-only imports) |
| Vercel / serverless | ❌ | Long-lived process forbidden + exe won't run — host the API on a separate server and connect via URL |

Rule: the browser never talks to ElfSec directly. Use `elfsec.js` **only server-side** (API Route / Server Action),
token stays in `process.env.ELFSEC_API_TOKEN` (NEVER put it in a `NEXT_PUBLIC_` variable).
Verified end-to-end: Node client → Python API → score (v1.2.0).

### SDK for developers (importable core)

Same pipeline as the CLI, single call from code:

```python
from app.sdk import scan_text, scan_file, sanitize

report = scan_text(subject="Invoice", body="<p>Pay the debt http://x.tk/o</p>", sender="a@b.com")
print(report["risk_level"], report["risk_score"], report["reasons"])

clean = sanitize("<script>x</script><p>hello</p>")  # no AI, fast: safe_html + plain_text + urls
```

### Tests (developer-focused)

```bash
cd backend
.venv\Scripts\activate
python -m pytest tests -q        # 161 tests: sanitizer, engine, TOOL CLI/guard/settings/kontrol/headers/oauth/ops/serve
python -m app.cli kontrol --fail-only   # 66 penetration checks (SURUM,TEMIZLE,ANALIZ,TOOL,IMAP,OPS,SERVE)
```

### Enterprise usage (v0.6.0)

```bash
# Engine rules (tune weights on/off, reset to defaults)
python -m app.cli rules show
python -m app.cli rules set urgency 40
python -m app.cli rules disable url_keyword
python -m app.cli rules reset

# CEF stream to SIEM
python -m app.cli triage --limit 50 --cef daily.cef
python -m app.cli guard --unseen --interval 10 --cef-log alarms.cef

# Update check
python -m app.cli update --check
# Installer package: installer\elfsec.iss (Inno Setup) builds ElfSecSetup.exe
```

Contribution flow: write test → `pytest` green → PR. Any change loosening the sanitizer layer must break tests — by design.

**Sample output:**
```
[XXX] RISK 80/100 [CRITICAL] (engine: elfsec-local/1.0)
Summary: Local analysis: 4 findings, score 80/100.
Reasons:
  - Phishing pattern: urgency + account/closure/verification pressure.
  - URL with suspicious TLD: http://evil.tk/verify
  - Sender spoof: corporate identity + free mail domain (gmail.com).
Phishing: True | Prompt-injection: False
Tracking-pixel blocks: 0
Recommendation: Don't click links, don't open attachments, verify the sender via an official channel.
```

## Usage as KONTROL (penetration tests)

```bash
python -m app.cli kontrol --fail-only
python -m app.cli kontrol --kategori TOOL,IMAP --fail-on LOW
```

Categories: `SURUM,TEMIZLE,ANALIZ,TOOL,IMAP,OPS`. Results are FAIL-first + optimized in version order.
Exit: `0` clean, `1` issue found, `2` error.

## Project structure

```
backend/
  app/
    cli.py               # TOOL interface (health/fetch/analyze/triage/guard/config/kontrol) + exit-code
    kontrol.py           # versioned audit + penetration tests (TOOL-only)
    notify.py            # Windows Toast (no extra dependency)
    tray.py              # single-exe background (console hide + tray)
    sdk.py               # importable core (scan_text/scan_file/sanitize)
    config.py            # settings schema (pydantic, TOOL-only)
    settings_store.py    # layered config + Turkish validation
    secret_vault.py      # DPAPI encrypted storage (ENC...)
    schemas.py           # TOOL input validation (pydantic)
    services/
      imap_client.py     # imap-tools + quarantine (in thread)
      sanitizer.py       # bleach + bs4/lxml
      ai_analyzer.py     # local engine (keyless, deterministic)
  tests/                 # pytest: sanitizer + local engine + TOOL CLI/guard/settings/kontrol contract
  elfsec.py              # single-exe entry point (PyInstaller, guard --tray hides)
  scripts/               # build_exe / setup_autostart / remove_autostart
  requirements.txt  .env.example
.github/workflows/release.yml  # builds single elfsec.exe on v* tag and uploads to Releases
```

## Security notes

- For Gmail use an **app password**, not your normal password.
- ElfSec deliberately uses **no API keys**: analysis is local, email content never leaves the device. No server/frontend/Docker.
- **Log privacy:** `triage --out` and `guard_alerts.jsonl` contain mail summaries — don't share these files, pass `--webhook` only to a trusted `https://` address (`http` is skipped).
- **Dependencies:** versions pinned in `requirements.txt` (serverless, 8 packages); `pip-audit` clean, CI runs tests + audit on every push, Dependabot opens weekly security updates.
