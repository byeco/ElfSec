#Requires -Version 5.1
<#
.SYNOPSIS
  elfsec:// protokol kaydini kaldirir (yalnizca gecerli kullanici).
#>
$ErrorActionPreference = "Stop"
Remove-Item -Path "HKCU:\Software\Classes\elfsec" -Recurse -Force -ErrorAction SilentlyContinue
Write-Output "OK: elfsec:// kaydi kaldirildi."
