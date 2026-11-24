; ElfSec Inno Setup — Windows Güvenlik Eklentisi (v1.3.0)
; Kullanım: ISCC.exe installer\elfsec.iss  (çıktı: installer\Output\ElfSecSetup.exe)
; Not: SmartScreen için Authenticode imzası releaser'da eklenir (signtool).

#define MyAppName "ElfSec"
#define MyAppVersion "1.6.0"
#define MyAppExeName "elfsec.exe"

[Setup]
AppId={{3F2A9C41-7E1B-4C9D-9F2A-ELFSEC000001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={autopf}\ElfSec
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=ElfSecSetup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Files]
Source: "..\backend\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\extension\*"; DestDir: "{app}\extension"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{commonprograms}\ElfSec Güvenlik Paneli"; Filename: "{app}\{#MyAppExeName}"; Parameters: "dashboard"
Name: "{commonprograms}\ElfSec Tepsi Koruması"; Filename: "{app}\{#MyAppExeName}"; Parameters: "agent --tray"

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "plugin install --exe ""{app}\{#MyAppExeName}"""; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Parameters: "config setup"; Flags: postinstall nowait skipifsilent unchecked; Description: "E-posta koruma sihirbazını çalıştır"

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "plugin uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "ElfSecPluginUninstall"
