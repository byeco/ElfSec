#Requires -Version 5.1
<#
.SYNOPSIS
  ElfSec Grafiksel Windows Kurulum Sihirbazını (installer\Output\ElfSecSetup.exe) derler.
.KULLANIM
  powershell -ExecutionPolicy Bypass -File installer\build_installer.ps1
#>
param(
  [switch]$RebuildExe
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Backend = Join-Path $RepoRoot "backend"
$Py = Join-Path $Backend ".venv\Scripts\python.exe"
$PyInstaller = Join-Path $Backend ".venv\Scripts\pyinstaller.exe"

if (-not (Test-Path -LiteralPath $Py)) {
  throw "backend\.venv bulunamadı: $Py"
}

& $Py (Join-Path $Backend "scripts\make_ico.py")
if ($LASTEXITCODE -ne 0) { throw "elfsec.ico üretilemedi" }

$CoreExe = Join-Path $Backend "dist\elfsec.exe"
if ($RebuildExe -or -not (Test-Path -LiteralPath $CoreExe)) {
  Write-Output "backend\dist\elfsec.exe derleniyor..."
  & (Join-Path $Backend "scripts\build_exe.ps1")
  if ($LASTEXITCODE -ne 0) { throw "elfsec.exe derlenemedi" }
}

$Ico = Join-Path $RepoRoot "installer\elfsec.ico"
$Png = Join-Path $RepoRoot "extension\icons\icon128.png"
$ExtDir = Join-Path $RepoRoot "extension"
$OutDir = Join-Path $RepoRoot "installer\Output"
$WorkDir = Join-Path $RepoRoot "installer\build"
$WizardPy = Join-Path $RepoRoot "installer\setup_wizard_gui.py"

& $PyInstaller --noconfirm --clean --onefile --windowed --uac-admin `
  --icon $Ico `
  --name ElfSecSetup `
  --distpath $OutDir `
  --workpath $WorkDir `
  --specpath $WorkDir `
  --add-data "$CoreExe;payload" `
  --add-data "$Ico;payload" `
  --add-data "$Png;payload" `
  --add-data "$ExtDir;payload\extension" `
  $WizardPy
if ($LASTEXITCODE -ne 0) { throw "ElfSecSetup.exe derleme başarısız (exit=$LASTEXITCODE)" }

$SetupExe = Join-Path $OutDir "ElfSecSetup.exe"
if (-not (Test-Path -LiteralPath $SetupExe)) {
  throw "Çıktı bulunamadı: $SetupExe"
}
$SizeMb = [math]::Round((Get-Item $SetupExe).Length / 1MB, 2)
Write-Output "OK: Kurulum dosyası hazır -> $SetupExe ($SizeMb MB)"
