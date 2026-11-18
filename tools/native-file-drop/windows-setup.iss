; SPDX-License-Identifier: GPL-2.0-or-later
; Compile with ISCC /DPackageDir=<absolute staged package> /DOutputDir=<absolute output>.
#ifndef PackageDir
  #error PackageDir must point to the validated Windows package directory.
#endif
#ifndef OutputDir
  #error OutputDir must be specified.
#endif
#define AppVersion "0.3.20"

[Setup]
; No finish page to forget: the app starts on its own and setup closes.
DisableFinishedPage=yes
AppId=org.barriershare.desktop
AppName=Cursorway
AppVersion={#AppVersion}
AppPublisher=Cursorway contributors
AppPublisherURL=https://github.com/sunnylinisme/barrier
AppSupportURL=https://github.com/sunnylinisme/barrier
; Installs from before the rename (Program Files\Barrier Share) move here; see MoveOldFolder.
DefaultDirName={autopf}\Cursorway
UsePreviousAppDir=no
DefaultGroupName=Cursorway
DisableProgramGroupPage=yes
; Administrator rights install the Cursorway service, which lets the other computer
; control the sign-in screen, the lock screen and UAC prompts.
PrivilegesRequired=admin
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.18362
SetupMutex=Local\BarrierShare.Setup
CloseApplications=no
RestartApplications=no
WizardStyle=modern
ShowLanguageDialog=auto
OutputDir={#OutputDir}
OutputBaseFilename=Cursorway-Setup-{#AppVersion}-x64
SetupIconFile={#AddBackslash(SourcePath)}icons\BarrierShare.ico
UninstallDisplayName=Cursorway
UninstallDisplayIcon={app}\BarrierShare.exe
VersionInfoVersion={#AppVersion}.0
Compression=lzma2
SolidCompression=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesetraditional"; MessagesFile: "{#AddBackslash(SourcePath)}installer-languages\ChineseTraditional.isl"

[CustomMessages]
english.CloseFailed=Cursorway could not be closed. Choose Exit from its notification-area icon and run Setup again.
chinesetraditional.CloseFailed=無法自動關閉 Cursorway。請從右下角系統匣的圖示選擇「結束」，再重新執行安裝程式。

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#PackageDir}\BarrierShare.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\barriers.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\barrierc.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\barrier-pair.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\barrier-link.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\barrier-service.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\GUI-README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\COMMIT.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\licenses\*.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion

[InstallDelete]
; Shortcuts from before the rename, so the Start menu and desktop show one entry.
Type: files; Name: "{autoprograms}\Barrier Share.lnk"
Type: files; Name: "{autodesktop}\Barrier Share.lnk"

[Icons]
Name: "{autoprograms}\Cursorway"; Filename: "{app}\BarrierShare.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\Cursorway"; Filename: "{app}\BarrierShare.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Registry]
; The app writes this value when "launch at sign-in" is ticked; uninstall removes it without ever creating it.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "BarrierShare"; Flags: uninsdeletevalue dontcreatekey

[Run]
; A copy that was running before the update is started again, also for silent installs.
; The app runs as the signed-in user, never with the installer's administrator rights.
Filename: "{app}\BarrierShare.exe"; WorkingDir: "{app}"; Flags: nowait runasoriginaluser; Check: WasRunning
Filename: "{app}\BarrierShare.exe"; WorkingDir: "{app}"; Flags: nowait skipifsilent runasoriginaluser; Check: not WasRunning

; Settings and pairing live in LocalAppData\Cursorway (moved from LocalAppData\BarrierShare) and are kept. The service's copy of them
; (pairing identity, screen settings, logs, received files) lives in {app}\state and goes with the app.
[UninstallDelete]
Type: filesandordirs; Name: "{app}\state"

[Code]
const
  AppMutexName = 'Local\BarrierShare.Desktop';
  { BarrierShare.cs (ShareProgram.QuitEvent) waits on this event and exits cleanly. }
  QuitEventName = 'Local\BarrierShare.Quit';
var
  Running: Boolean;
  { Where the app was installed before this setup ran (another folder before the rename). }
  OldDir: String;

function OpenEvent(Access: Cardinal; Inherit: Integer; Name: String): Cardinal; external 'OpenEventW@kernel32.dll stdcall';
function SetEvent(Handle: Cardinal): Integer; external 'SetEvent@kernel32.dll stdcall';
function CloseHandle(Handle: Cardinal): Integer; external 'CloseHandle@kernel32.dll stdcall';
function SystemParametersInfo(Action, Param, Value, WinIni: Cardinal): Integer; external 'SystemParametersInfoW@user32.dll stdcall';

function WasRunning(): Boolean;
begin
  Result := Running;
end;

{ Close Barrier Share (and its helper processes) so the files can be replaced. 0.3.9 and later
  quit on the event; 0.3.8 and earlier, or a copy that does not answer, are ended with taskkill. }
procedure CloseBarrierShare();
var
  Handle: Cardinal;
  I, Code: Integer;
begin
  if not CheckForMutexes(AppMutexName) then exit;
  Running := True;
  Handle := OpenEvent($0002 { EVENT_MODIFY_STATE }, 0, QuitEventName);
  if Handle <> 0 then begin
    SetEvent(Handle);
    CloseHandle(Handle);
    for I := 1 to 80 do begin
      if not CheckForMutexes(AppMutexName) then break;
      Sleep(100);
    end;
  end;
  if CheckForMutexes(AppMutexName) then begin
    Log('Barrier Share did not quit on request; ending it and its helpers');
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM BarrierShare.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
    for I := 1 to 50 do begin
      if not CheckForMutexes(AppMutexName) then break;
      Sleep(100);
    end;
  end;
  { A forced stop can leave the host's cursors hidden; reload the user's cursor scheme. }
  SystemParametersInfo($0057 { SPI_SETCURSORS }, 0, 0, 0);
  Sleep(300);
end;

function Sc(Params: String): Integer;
var
  Code: Integer;
begin
  if not Exec(ExpandConstant('{sys}\sc.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, Code) then Code := -1;
  Log('sc ' + Params + ' -> ' + IntToStr(Code));
  Result := Code;
end;

{ Stop the service and wait until it has ended its core, so the files can be replaced. }
procedure StopService();
var
  I, Code: Integer;
begin
  Sc('stop BarrierShare');
  for I := 1 to 50 do begin
    { findstr succeeds while the service is still running or changing state. }
    Exec(ExpandConstant('{sys}\cmd.exe'), '/c sc query BarrierShare | findstr /c:"RUNNING" /c:"PENDING" >nul', '', SW_HIDE, ewWaitUntilTerminated, Code);
    if Code <> 0 then break;
    Sleep(200);
  end;
end;

{ Versions up to 0.3.8 installed per user under LocalAppData; remove that copy so only one remains.
  Pairing and settings are kept because they live outside the program folder. }
procedure RemovePerUserInstall();
var
  Command: String;
  Code: Integer;
begin
  if not RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\org.barriershare.desktop_is1', 'UninstallString', Command) then exit;
  Command := RemoveQuotes(Command);
  if not FileExists(Command) then exit;
  Log('Removing the per-user installation: ' + Command);
  Exec(Command, '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  if not RegQueryStringValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\org.barriershare.desktop_is1', 'Inno Setup: App Path', OldDir) then OldDir := '';
  CloseBarrierShare();
  if CheckForMutexes(AppMutexName) then begin
    Result := ExpandConstant('{cm:CloseFailed}');
    exit;
  end;
  StopService();
  RemovePerUserInstall();
  Result := '';
end;

procedure Netsh(Params: String);
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\netsh.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, Code);
  Log('netsh ' + Params + ' -> ' + IntToStr(Code));
end;

procedure RemoveFirewallRules();
begin
  Netsh('advfirewall firewall delete rule name="Barrier Share"');
  Netsh('advfirewall firewall delete rule name="Cursorway"');
end;

{ Without rules Windows asks on first use, and a core the service starts gets no prompt at all,
  so a fresh install stayed blocked until the app was restarted. Private and domain networks only, any address there, so manual addresses across subnets or a VPN work too. }
procedure AddFirewallRules();
var
  Names: TArrayOfString;
  I: Integer;
begin
  RemoveFirewallRules();
  SetArrayLength(Names, 3);
  Names[0] := 'barriers.exe'; Names[1] := 'barrierc.exe'; Names[2] := 'barrier-link.exe';
  for I := 0 to 2 do
    Netsh('advfirewall firewall add rule name="Cursorway" dir=in action=allow profile=private,domain program="' + ExpandConstant('{app}\') + Names[I] + '"');
end;

{ An install from before the rename lived in another folder: bring the service's state over (the
  service and the app are stopped by now), and remove the old folder only once that copy succeeded.
  Pairing and settings themselves live in LocalAppData; the app moves that folder when it starts. }
procedure MoveOldFolder();
var
  NewDir: String;
  Code: Integer;
begin
  NewDir := ExpandConstant('{app}');
  if (OldDir = '') or (CompareText(RemoveBackslashUnlessRoot(OldDir), RemoveBackslashUnlessRoot(NewDir)) = 0) or not DirExists(OldDir) then exit;
  Log('Moving the installation from ' + OldDir + ' to ' + NewDir);
  if DirExists(OldDir + '\state') then begin
    { robocopy succeeds with exit codes below 8; /COPY:DATS keeps the folders' permissions. }
    if not Exec(ExpandConstant('{sys}\robocopy.exe'), '"' + OldDir + '\state" "' + NewDir + '\state" /E /COPY:DATS /R:1 /W:1 /NP /NFL /NDL', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code >= 8) then begin
      Log('Copying the service state failed (robocopy ' + IntToStr(Code) + '); keeping ' + OldDir);
      exit;
    end;
  end;
  if DelTree(OldDir, True, True, True) then Log('Removed ' + OldDir) else Log('Could not remove all of ' + OldDir);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Binary: String;
begin
  if CurStep <> ssPostInstall then exit;
  MoveOldFolder();
  AddFirewallRules();
  { sc takes binPath= as one argument; the quotes the service manager needs around a path with
    spaces are escaped inside it. }
  Binary := '\"' + ExpandConstant('{app}\barrier-service.exe') + '\"';
  if Sc('create BarrierShare binPath= "' + Binary + '" start= auto DisplayName= "Cursorway"') <> 0 then
    Sc('config BarrierShare binPath= "' + Binary + '" start= auto DisplayName= "Cursorway"');
  Sc('description BarrierShare "Lets the paired computer control the sign-in screen, lock screen and UAC prompts."');
  Sc('failure BarrierShare reset= 86400 actions= restart/5000/restart/5000/restart/30000');
  Sc('start BarrierShare');
end;

function InitializeUninstall(): Boolean;
begin
  CloseBarrierShare();
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep <> usUninstall then exit;
  StopService();
  Sc('delete BarrierShare');
  RemoveFirewallRules();
end;
