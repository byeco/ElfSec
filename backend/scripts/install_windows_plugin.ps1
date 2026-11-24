#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  ElfSec'i tam Windows Güvenlik Eklentisi olarak kurar (Yönetici / Windows Servisi + Tepsi + Sağ-tık).

.KULLANIM (backend klasöründen, Yönetici PowerShell ile)
  powershell -ExecutionPolicy Bypass -File scripts\install_windows_plugin.ps1
#>
param(
  [string]$InstallDir = "$env:ProgramFiles\ElfSec",
  [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$Backend = Split-Path -Parent $PSScriptRoot
$SourceExe = Join-Path $Backend "dist\elfsec.exe"

if (-not (Test-Path -LiteralPath $SourceExe)) {
  Write-Output "dist\elfsec.exe bulunamadı, derleniyor..."
  & (Join-Path $PSScriptRoot "build_exe.ps1")
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
$TargetExe = Join-Path $InstallDir "elfsec.exe"
Copy-Item -LiteralPath $SourceExe -Destination $TargetExe -Force

$RepoRoot = Split-Path -Parent $Backend
$ExtSrc = Join-Path $RepoRoot "extension"
$ExtDst = Join-Path $InstallDir "extension"
if (Test-Path -LiteralPath $ExtSrc) {
  Copy-Item -Path $ExtSrc -Destination $ExtDst -Recurse -Force
}

$ArgsList = @("plugin", "install", "--exe", $TargetExe)
if ($NoStart) { $ArgsList += "--no-start" }

& $TargetExe @ArgsList
if ($LASTEXITCODE -ne 0) { throw "Eklenti kurulumu başarısız (exit=$LASTEXITCODE)" }

Write-Output ""
& $TargetExe plugin status
Write-Output ""
Write-Output "Tarayıcı (Chrome/Edge) Webmail Eklentisi (Gmail / Outlook Web / Yahoo / Yandex):"
Write-Output "  1) chrome://extensions (veya edge://extensions) açın -> Geliştirici Modunu açın"
Write-Output "  2) 'Paketlenmemiş öğe yükle' -> şu klasörü seçin: $ExtDst"
