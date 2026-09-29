#Requires -Version 5.1
<#
.SYNOPSIS
  ElfSec guard'ı PC açılışında otomatik başlatır (geçerli kullanıcı, yönetici gerekmez).
  TEK EXE: dist\elfsec.exe varsa onu, yoksa venv python kullanır.

.KULLANIM (backend klasöründen)
  powershell -ExecutionPolicy Bypass -File scripts\setup_autostart.ps1 [-Interval 10] [-Unseen] [-Action notify-only]

  PC her açıldığında (girişten ~1 dk sonra, ağ gelsin diye) arka planda çalışır:
    elfsec.exe guard --unseen --interval 10 --tray
#>
param([int]$Interval = 10, [switch]$Unseen, [string]$Action = "notify-only")

$ErrorActionPreference = "Stop"
$Backend = Split-Path -Parent $PSScriptRoot
$Exe = Join-Path $Backend "dist\elfsec.exe"
$Python = Join-Path $Backend ".venv\Scripts\python.exe"

# 1) Başlatıcı üret — TEK EXE öncelikli
$GuardArgs = "guard --interval $Interval --alert-on HIGH --alert-log guard_alerts.jsonl --state .guard_seen.json --tray --action $Action"
if ($Unseen) { $GuardArgs += " --unseen" }
$Launcher = Join-Path $Backend "guard_start.cmd"
if (Test-Path -LiteralPath $Exe) {
  "@echo off`r`ncd /d `"$Backend`"`r`n`"$Exe`" $GuardArgs" | Set-Content -LiteralPath $Launcher -Encoding ASCII
  Write-Output "Mod: TEK EXE ($Exe)"
} else {
  if (-not (Test-Path -LiteralPath $Python)) { throw "ne dist\elfsec.exe ne de venv bulundu (önce build_exe.ps1 veya pip install yapın)" }
  "@echo off`r`ncd /d `"$Backend`"`r`n`"$Python`" -m app.cli $GuardArgs" | Set-Content -LiteralPath $Launcher -Encoding ASCII
  Write-Output "Mod: venv python (exe yok, geliştirme modu)"
}

# 2) Oturum-açma görevini kur (gizli pencere + 1 dk gecikme ki Wi-Fi/IMAP hazır olsun)
schtasks /delete /tn "ElfSecGuard" /f 2>$null | Out-Null
schtasks /create /tn "ElfSecGuard" /sc onlogon /delay 0001:00 /tr "`"$Launcher`"" /rl limited /f
if ($LASTEXITCODE -ne 0) { throw "Zamanlanmış görev kurulamadı (exit=$LASTEXITCODE)" }

Write-Output "OK: ElfSecGuard kuruldu (her girişte: guard --interval $Interval --tray --action $Action)."
Write-Output "Hemen test:  schtasks /run /tn ElfSecGuard"
Write-Output "Durum:       schtasks /query /tn ElfSecGuard"
Write-Output "Loglar:      backend\guard_alerts.jsonl"
Write-Output "Kaldirma:    powershell -ExecutionPolicy Bypass -File scripts\remove_autostart.ps1"
