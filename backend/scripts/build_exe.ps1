#Requires -Version 5.1
<#
.SYNOPSIS
  ElfSec'i TEK dosyalık elfsec.exe olarak paketler (CLI + guard birleşik).
  İkinci guard exe YOKTUR — arka plan modu aynı exe'nin --tray bayrağıdır.
.KULLANIM (backend klasöründen)
  powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
.SONUC
  backend\dist\elfsec.exe  ->  GitHub Releases'e yüklenir, kullanıcı indirip çalıştırır.
  Test: dist\elfsec.exe health + dist\elfsec.exe guard --help
#>
$ErrorActionPreference = "Stop"
$Backend = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Backend

& ".\.venv\Scripts\python.exe" -m pip install -q pyinstaller==6.13.0 "pywebview>=6.0"
if ($LASTEXITCODE -ne 0) { throw "pyinstaller veya pywebview kurulamadı" }

& ".\.venv\Scripts\python.exe" "scripts\make_ico.py"
if ($LASTEXITCODE -ne 0) { throw "elfsec.ico üretilemedi" }

& ".\.venv\Scripts\pyinstaller.exe" --noconfirm --clean --onefile --console --name elfsec `
  --icon "..\installer\elfsec.ico" `
  --add-data "assets\elfsec.ico;assets" `
  --add-data "..\extension\icons\icon128.png;assets" `
  --collect-all webview `
  --collect-all clr_loader `
  --collect-all pythonnet `
  --hidden-import imap_tools --hidden-import bleach --hidden-import lxml `
  --hidden-import pydantic_settings --hidden-import app.win_service `
  --hidden-import app.win_plugin --hidden-import app.native_host `
  --hidden-import app.game_mode --hidden-import app.desktop_ui `
  --hidden-import app.privacy --hidden-import app.window_host --hidden-import webview `
  --hidden-import webview.platforms.winforms --hidden-import webview.platforms.edgechromium `
  --hidden-import app.verified_senders --hidden-import app.services.file_scanner `
  --hidden-import app.services.local_ai --hidden-import app.services.pe_analyzer `
  --hidden-import app.watchers.file_watcher --hidden-import app.watchers.clipboard_guard `
  elfsec.py
if ($LASTEXITCODE -ne 0) { throw "build başarısız (exit=$LASTEXITCODE)" }

Write-Output "OK: dist\elfsec.exe hazır (TEK EXE). Test: .\dist\elfsec.exe health"
& ".\dist\elfsec.exe" health
if ($LASTEXITCODE -ne 0) { throw "smoke-test başarısız: health" }
& ".\dist\elfsec.exe" guard --help
if ($LASTEXITCODE -ne 0) { throw "smoke-test başarısız: guard --help" }
