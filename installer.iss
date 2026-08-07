; Narsaq Desktop — Windows installer (Inno Setup 6)
; Build: ISCC.exe installer.iss
; Output: releases\NarsaqDesktop-Setup-v1.0.0.exe

#ifndef MyAppVer
  #define MyAppVer "1.0.0"
#endif

#define MyAppName "Narsaq Desktop"
#define MyAppExe "NarsaqDesktop-v1.0.0.exe"
#define MyAppPublisher "Narsaq"
#define MyAppURL "https://github.com/Misagh95/NarsaqDesktop"

[Setup]
; per-user install → بدون نیاز به ادمین، و پوشه {app} قابل نوشتن است
; (برنامه فایل‌های خروجی clean_ips_*.txt را کنار exe ذخیره می‌کند)
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DefaultDirName={localappdata}\Programs\NarsaqDesktop
DefaultGroupName=Narsaq Desktop
DisableProgramGroupPage=yes
AppId={{8F4A7C2B-9E31-4E6A-8D5B-3A5F9C0E1B2D}
AppName={#MyAppName}
AppVersion={#MyAppVer}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
VersionInfoVersion={#MyAppVer}
VersionInfoDescription=Narsaq Desktop — Cloudflare clean IP finder & config optimizer
VersionInfoCopyright=Copyright (C) Narsaq
OutputDir=releases
OutputBaseFilename=NarsaqDesktop-Setup-{#MyAppVer}
SetupIconFile=assets\narsaq.ico
UninstallDisplayIcon={app}\{#MyAppExe}
UninstallDisplayName=Narsaq Desktop
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=no
WizardSizePercent=120
ShowLanguageDialog=no
; به کاربر می‌گوییم برنامه خروجی‌ها را کجا می‌گذارد
InfoBeforeFile=installer_info.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "farsi"; MessagesFile: "compiler:Languages\Farsi.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "launchapp"; Description: "{cm:LaunchProgram,Narsaq Desktop}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\{#MyAppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\xray.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Narsaq Desktop"; Filename: "{app}\{#MyAppExe}"; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppExe}"
Name: "{group}\Uninstall Narsaq Desktop"; Filename: "{uninstallexe}"; IconFilename: "{app}\{#MyAppExe}"
Name: "{autodesktop}\Narsaq Desktop"; Filename: "{app}\{#MyAppExe}"; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "{cm:LaunchProgram,Narsaq Desktop}"; Flags: nowait postinstall skipifsilent; Tasks: launchapp

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    Log('Narsaq Desktop installed to: ' + ExpandConstant('{app}'));
end;
