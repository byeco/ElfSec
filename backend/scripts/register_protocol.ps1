#Requires -Version 5.1
<#
.SYNOPSIS
  elfsec:// protokolunu kaydeder (toast "Karantinaya al" butonu icin).
  Yalnizca gecerli kullanici (HKCU) - yonetici gerekmez.

.KULLANIM (backend klasorunden)
  powershell -ExecutionPolicy Bypass -File scripts\register_protocol.ps1
  Kaldirma: scripts\unregister_protocol.ps1
#>
$ErrorActionPreference = "Stop"
$Backend = Split-Path -Parent $PSScriptRoot
$Exe = Join-Path $Backend "dist\elfsec.exe"
if (-not (Test-Path -LiteralPath $Exe)) {
  throw "dist\elfsec.exe yok - once scripts\build_exe.ps1 calistirin."
}

$root = "HKCU:\Software\Classes\elfsec"
New-Item -Path $root -Force | Out-Null
Set-ItemProperty -Path $root -Name "(Default)" -Value "URL:ElfSec Protocol"
Set-ItemProperty -Path $root -Name "URL Protocol" -Value ""
New-Item -Path "$root\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "$root\shell\open\command" -Name "(Default)" -Value "`"$Exe`" `"%1`""

Write-Output "OK: elfsec:// protokolu kaydedildi"
Write-Output ("Hedef: " + $Exe)
Write-Output "Test:  elfsec.exe quarantine 123  (UID ile dener, IMAP hatasi exit 2 verir)"
