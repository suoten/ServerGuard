; ServerGuard Agent Windows Installer (Inno Setup)
; Build: iscc serverguard_agent.iss

#define MyAppName "ServerGuard Agent"
#define MyAppVersion "3.3.0"
#define MyAppPublisher "ShuoTeng Network"
#define MyAppExeName "serverguard-agent.exe"
#define MyAppDir "C:\Program Files\ServerGuard"

[Setup]
AppId={{8A7F9B2E-3C5D-4E6F-9A1B-2C3D4E5F6A7B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL=https://github.com/suoten/serverguard
DefaultDirName={#MyAppDir}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=serverguard-agent-{#MyAppVersion}-windows-amd64
Compression=lzma
SolidCompression=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
SignTool=SignTool /fd sha256 /tr http://timestamp.digicert.com /td sha256 $f
SetupIconFile=..\..\build\windows\resources\icon.svg
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "service"; Description: "安装为Windows服务（推荐）"; GroupDescription: "服务选项:"; Flags: checked
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加选项:"; Flags: unchecked

[Files]
Source: "..\bin\serverguard-agent.exe"; DestDir: "{app}"; Flags: ignoreversion signonce
Source: "..\bin\sgctl.exe"; DestDir: "{app}"; Flags: ignoreversion signonce
Source: "..\configs\*"; DestDir: "{app}\configs"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\ServerGuard CLI"; Filename: "{app}\sgctl.exe"; WorkingDir: "{app}"
Name: "{group}\卸载 ServerGuard"; Filename: "{uninstallexe}"
Name: "{commondesktop}\ServerGuard CLI"; Filename: "{app}\sgctl.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\serverguard-agent.exe"; Parameters: "service install"; StatusMsg: "正在安装 Windows 服务..."; Flags: runhidden waituntilterminated; Tasks: service
Filename: "{app}\serverguard-agent.exe"; Parameters: "service start"; StatusMsg: "正在启动 Windows 服务..."; Flags: runhidden waituntilterminated; Tasks: service

[UninstallRun]
Filename: "{app}\serverguard-agent.exe"; Parameters: "service stop"; StatusMsg: "正在停止 Windows 服务..."; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{app}\serverguard-agent.exe"; Parameters: "service uninstall"; StatusMsg: "正在卸载 Windows 服务..."; Flags: runhidden waituntilterminated; RunOnceId: "UninstallService"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\configs"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\data"

[Registry]
Root: HKLM; Subkey: "SOFTWARE\ServerGuard"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\ServerGuard"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Services\ServerGuard"; ValueType: dword; ValueName: "Start"; ValueData: 2; Flags: uninsdeletekey; Tasks: service

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsWin64 then
  begin
    MsgBox('ServerGuard Agent 需要 64 位 Windows 系统。', mbError, MB_OK);
    Result := False;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    ShellExec('open', 'netsh', 'advfirewall firewall add rule name="ServerGuard Agent" dir=in action=allow program="' + ExpandConstant('{app}\serverguard-agent.exe') + '" enable=yes', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    ShellExec('open', 'netsh', 'advfirewall firewall delete rule name="ServerGuard Agent"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;