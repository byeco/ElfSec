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

& ".\.venv\Scripts\python.exe" -m pip install -q pyinstaller==6.13.0
if ($LASTEXITCODE -ne 0) { throw "pyinstaller kurulamadı" }

& ".\.venv\Scripts\pyinstaller.exe" --noconfirm --clean --onefile --console --name elfsec `
  --hidden-import imap_tools --hidden-import bleach --hidden-import lxml `
  --hidden-import pydantic_settings `
  elfsec.py
if ($LASTEXITCODE -ne 0) { throw "build başarısız (exit=$LASTEXITCODE)" }

Write-Output "OK: dist\elfsec.exe hazır (TEK EXE). Test: .\dist\elfsec.exe health"
& ".\dist\elfsec.exe" health
if ($LASTEXITCODE -ne 0) { throw "smoke-test başarısız: health" }
& ".\dist\elfsec.exe" guard --help
if ($LASTEXITCODE -ne 0) { throw "smoke-test başarısız: guard --help" }
