#Requires -Version 5.1
<#
.SYNOPSIS
  ElfSec otomatik başlatmayı kaldırır.
.KULLANIM
  powershell -ExecutionPolicy Bypass -File scripts\remove_autostart.ps1
#>
$ErrorActionPreference = "Stop"
schtasks /delete /tn "ElfSecGuard" /f
Write-Output "OK: ElfSecGuard kaldırıldı. (Çalışan guard penceresi varsa Ctrl+C ile durdurun.)"
