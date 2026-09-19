#Requires -Version 5.1
<#
.SYNOPSIS
  ElfSec guard'ı PC açılışında otomatik başlatır (geçerli kullanıcı, yönetici gerekmez).

.KULLANIM (backend klasöründen)
  powershell -ExecutionPolicy Bypass -File scripts\setup_autostart.ps1 [-Interval 10] [-Unseen]

  PC her açıldığında (girişten ~1 dk sonra, ağ gelsin diye) arka planda çalışır:
    python -m app.cli guard --unseen --interval 10
#>
param([int]$Interval = 10, [switch]$Unseen)

$ErrorActionPreference = "Stop"
$Backend = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Backend ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python)) { throw "venv bulunamadı: $Python (önce pip install yapın)" }

# 1) Başlatıcı üret (görevin çalışma klasörü sorununu çözer: önce backend'e geçer)
$GuardArgs = "-m app.cli guard --interval $Interval --alert-on HIGH --alert-log guard_alerts.jsonl --state .guard_seen.json"
if ($Unseen) { $GuardArgs += " --unseen" }
$Launcher = Join-Path $Backend "guard_start.cmd"
"@echo off`r`ncd /d `"$Backend`"`r`n`"$Python`" $GuardArgs" | Set-Content -LiteralPath $Launcher -Encoding ASCII

# 2) Oturum-açma görevini kur (gizli pencere + 1 dk gecikme ki Wi-Fi/IMAP hazır olsun)
schtasks /delete /tn "ElfSecGuard" /f 2>$null | Out-Null
schtasks /create /tn "ElfSecGuard" /sc onlogon /delay 0001:00 /tr "`"$Launcher`"" /rl limited /f
if ($LASTEXITCODE -ne 0) { throw "Zamanlanmış görev kurulamadı (exit=$LASTEXITCODE)" }

Write-Output "OK: ElfSecGuard kuruldu (her girişte: guard --interval $Interval)."
Write-Output "Hemen test:  schtasks /run /tn ElfSecGuard"
Write-Output "Durum:       schtasks /query /tn ElfSecGuard"
Write-Output "Loglar:      backend\guard_alerts.jsonl"
Write-Output "Kaldirma:    powershell -ExecutionPolicy Bypass -File scripts\remove_autostart.ps1"
