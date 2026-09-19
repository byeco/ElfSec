#Requires -Version 5.1
<#
.SYNOPSIS
  ElfSec'i tek dosyalık elfsec.exe olarak paketler (kullanıcı indirmesi için).
.KULLANIM (backend klasöründen)
  powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
.SONUC
  backend\dist\elfsec.exe  ->  GitHub Releases'e yüklenir, kullanıcı indirip çalıştırır.
#>
$ErrorActionPreference = "Stop"
$Backend = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Backend

& ".\.venv\Scripts\python.exe" -m pip install -q pyinstaller==6.13.0
if ($LASTEXITCODE -ne 0) { throw "pyinstaller kurulamadı" }

& ".\.venv\Scripts\pyinstaller.exe" --noconfirm --clean --onefile --console --name elfsec `
  --hidden-import slowapi --hidden-import imap_tools --hidden-import bleach --hidden-import lxml `
  --hidden-import pydantic_settings `
  elfsec.py
if ($LASTEXITCODE -ne 0) { throw "build başarısız (exit=$LASTEXITCODE)" }

Write-Output "OK: dist\elfsec.exe hazır. Test: .\dist\elfsec.exe health"
& ".\dist\elfsec.exe" health
