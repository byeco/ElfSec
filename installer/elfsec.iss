; ElfSec Inno Setup — tek exe + otostart (v0.6.0)
; Kullanim: ISCC.exe installer\elfsec.iss  (çıktı: installer\Output\ElfSecSetup.exe)
; Not: SmartScreen için Authenticode imzası releaser'da eklenir (signtool).

#define MyAppName "ElfSec"
#define MyAppVersion "0.6.0"
#define MyAppExeName "elfsec.exe"

[Setup]
AppId={{3F2A9C41-7E1B-4C9D-9F2A-ELFSEC000001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={localappdata}\ElfSec
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=ElfSecSetup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64

[Files]
Source: "..\backend\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\ElfSec Guard (arka plan)"; Filename: "{app}\{#MyAppExeName}"; Parameters: "guard --unseen --interval 10 --tray"

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "config init"; Flags: postinstall nowait skipifsilent; Description: "İlk kurulum sihirbazını çalıştır"
