#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  ElfSec Windows Güvenlik Eklentisini, servisini ve kayıt defteri girdilerini kaldırır.
#>
param(
  [string]$InstallDir = "$env:ProgramFiles\ElfSec",
  [switch]$KeepFiles
)

$ErrorActionPreference = "Stop"
$TargetExe = Join-Path $InstallDir "elfsec.exe"
$Backend = Split-Path -Parent $PSScriptRoot
$FallbackExe = Join-Path $Backend "dist\elfsec.exe"

if (Test-Path -LiteralPath $TargetExe) {
  & $TargetExe plugin uninstall
} elseif (Test-Path -LiteralPath $FallbackExe) {
  & $FallbackExe plugin uninstall
} else {
  sc.exe stop ElfSecGuard 2>$null | Out-Null
  sc.exe delete ElfSecGuard 2>$null | Out-Null
}

if (-not $KeepFiles -and (Test-Path -LiteralPath $InstallDir)) {
  Start-Sleep -Milliseconds 500
  Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output "OK: ElfSec Windows Güvenlik Eklentisi kaldırıldı."
