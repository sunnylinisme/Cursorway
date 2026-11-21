#requires -Version 7.0
# SPDX-License-Identifier: GPL-2.0-or-later
param(
    [Parameter(Mandatory = $true)][string]$InstallerPath,
    [Parameter(Mandatory = $true)][string]$PackageDir,
    [Parameter(Mandatory = $true)][string]$TestRoot,
    # An installer released before the rename (Barrier Share); upgrading from it must leave one installation.
    [string]$PreviousInstaller = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# This test creates a disposable profile at the real per-user location.
if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or -not $env:GITHUB_WORKSPACE) {
    throw 'Run only on a disposable Windows GitHub Actions runner.'
}
$InstallerPath = (Resolve-Path -LiteralPath $InstallerPath).Path
$PackageDir = (Resolve-Path -LiteralPath $PackageDir).Path
$TestRoot = [IO.Path]::GetFullPath($TestRoot)
$workspace = [IO.Path]::GetFullPath($env:GITHUB_WORKSPACE).TrimEnd('\') + '\'
if (-not $TestRoot.StartsWith($workspace, [StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $TestRoot)) {
    throw 'TestRoot must be a new directory inside the CI workspace.'
}
# Settings start in the pre-rename folder; the app moves them to Cursorway the first time it starts.
$profileOld = Join-Path $env:LOCALAPPDATA 'BarrierShare'
$profileNew = Join-Path $env:LOCALAPPDATA 'Cursorway'
$profile = $profileOld
function Get-Profile {
    if ((Test-Path -LiteralPath $profileOld) -and (Test-Path -LiteralPath $profileNew)) { throw 'Both the old and the new settings folder exist.' }
    if (Test-Path -LiteralPath $profileNew) { return $profileNew } else { return $profileOld }
}
$programFilesNew = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Cursorway'
# 0.3.9 installs for all users (administrator) with the Barrier Share service.
# Ctrl+Alt+Del: the installer lets services send it (SoftwareSASGeneration) and uninstall puts the old state back.
$sasKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
# Strict mode: a missing value is $null, not an error.
function Get-SasPolicy { try { Get-ItemPropertyValue -LiteralPath $sasKey -Name SoftwareSASGeneration -ErrorAction Stop } catch { $null } }
$sasBefore = (Get-SasPolicy)
$uninstallKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\org.barriershare.desktop_is1'
$machineKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\org.barriershare.desktop_is1'
$shortcuts = @(
    (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Cursorway.lnk'),
    (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Cursorway.lnk')
)
# Shortcuts from before the rename must not remain next to the new ones.
$oldShortcuts = @(
    (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Barrier Share.lnk'),
    (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Barrier Share.lnk')
)
if (Get-Service Cursorway -ErrorAction SilentlyContinue) { throw 'Refusing to replace an existing Barrier Share service.' }
foreach ($path in @($profileOld, $profileNew, $programFilesNew, $uninstallKey, $machineKey) + $shortcuts + $oldShortcuts) {
    if (Test-Path -LiteralPath $path) { throw "Refusing to alter an existing profile, installation or shortcut: $path" }
}
$installDir = Join-Path $TestRoot '安裝測試 with spaces\Barrier Share'
New-Item -ItemType Directory -Path $TestRoot, $profile | Out-Null

function Invoke-TestProcess([string]$File, [string[]]$Arguments, [int]$TimeoutSeconds = 90, [bool]$ShellExecute = $false) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $File
    $info.UseShellExecute = $ShellExecute
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw "Could not start $File" }
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            throw "Timed out waiting for test process $File (PID $($process.Id)); no background processes were forcibly closed."
        }
        if ($process.ExitCode -ne 0) { throw "$File exited with code $($process.ExitCode); inspect installer/startup logs in $TestRoot" }
    } finally { $process.Dispose() }
}
function Get-ProfileHashes {
    $result = @{}; $current = Get-Profile
    foreach ($file in Get-ChildItem -LiteralPath $current -File -Recurse) {
        $result[[IO.Path]::GetRelativePath($current, $file.FullName)] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
    return $result
}
function Assert-Profile([hashtable]$Expected) {
    if (-not (Test-Path -LiteralPath (Get-Profile))) { throw 'Installer removed the existing profile.' }
    $actual = Get-ProfileHashes
    if ($actual.Count -ne $Expected.Count) { throw 'Installer changed the profile file inventory.' }
    foreach ($name in $Expected.Keys) {
        if ($actual[$name] -ne $Expected[$name]) { throw "Installer changed profile file: $name" }
    }
}
function Assert-Installed {
    foreach ($name in 'Cursorway.exe', 'cursorway-server.exe', 'cursorway-client.exe', 'cursorway-pair.exe', 'cursorway-link.exe', 'cursorway-service.exe', 'GUI-README.txt', 'LICENSE', 'COMMIT.txt') {
        if (-not (Test-Path -LiteralPath (Join-Path $installDir $name) -PathType Leaf)) { throw "Missing installed file: $name" }
    }
    foreach ($file in Get-ChildItem -LiteralPath $PackageDir -File -Recurse) {
        $relative = [IO.Path]::GetRelativePath($PackageDir, $file.FullName)
        $destination = Join-Path $installDir $relative
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or (Get-FileHash -LiteralPath $destination).Hash -ne (Get-FileHash -LiteralPath $file.FullName).Hash) {
            throw "Installed payload differs from package: $relative"
        }
    }
    if (Test-Path -LiteralPath $machineKey) { throw 'Installer unexpectedly created a per-user uninstall entry.' }
    $service = Get-CimInstance Win32_Service -Filter "Name='Cursorway'"
    if (-not $service -or $service.State -ne 'Running' -or $service.StartMode -ne 'Auto' -or -not $service.PathName.Contains((Join-Path $installDir 'cursorway-service.exe'))) {
        throw "Barrier Share service is not installed and running from this installation: $($service | Out-String)"
    }
    $sas = (Get-SasPolicy)
    if ($sas -ne 1 -and $sas -ne 3) { throw "SoftwareSASGeneration does not let the service send Ctrl+Alt+Del: '$sas' (before: '$sasBefore')" }
    $entry = Get-ItemProperty -LiteralPath $uninstallKey
    $fileVersion = [Version][Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $installDir 'Cursorway.exe')).FileVersion
    $expectedVersion = '{0}.{1}.{2}' -f $fileVersion.Major, $fileVersion.Minor, $fileVersion.Build
    if (-not $entry.DisplayName.StartsWith('Cursorway') -or $entry.DisplayVersion -ne $expectedVersion -or $entry.InstallLocation.TrimEnd('\') -ine $installDir.TrimEnd('\')) {
        throw 'Per-user uninstall metadata does not match the installed application.'
    }
    $uninstaller = Join-Path $installDir 'unins000.exe'
    if (-not (Test-Path -LiteralPath $uninstaller) -or -not $entry.UninstallString.Contains($uninstaller)) { throw 'Uninstall command does not target this test installation.' }
    # Read the native Shell link instead of WScript's legacy TargetPath projection.
    $shell = New-Object -ComObject Shell.Application
    try {
        foreach ($path in $shortcuts) {
            if (-not (Test-Path -LiteralPath $path)) { throw "Shortcut was not created: $path" }
            $folder = $item = $shortcut = $null
            try {
                $folder = $shell.NameSpace([IO.Path]::GetDirectoryName($path))
                $item = $folder.ParseName([IO.Path]::GetFileName($path))
                if (-not $item.IsLink) { throw "Not a Shell shortcut: $path" }
                $shortcut = $item.GetLink
                $target = [string]$shortcut.Path
                $expected = Join-Path $installDir 'Cursorway.exe'
                Add-Content -LiteralPath (Join-Path $TestRoot 'shortcuts.log') -Encoding utf8 -Value "Shortcut=$path; Target=$target; Expected=$expected; WorkingDirectory=$($shortcut.WorkingDirectory)"
                if (-not $target -or [IO.Path]::GetFullPath($target) -ine [IO.Path]::GetFullPath($expected)) {
                    throw "Shortcut targets the wrong application: $path; actual=[$target]; expected=[$expected]"
                }
            } finally {
                foreach ($object in @($shortcut, $item, $folder)) {
                    if ($null -ne $object) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($object) }
                }
            }
        }
    } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
    foreach ($path in $oldShortcuts) { if (Test-Path -LiteralPath $path) { throw "A shortcut from before the rename remains: $path" } }
    # One installation only: no second uninstall entry under another key for this app.
    $entries = @(Get-ChildItem 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath } | Where-Object { $_.PSObject.Properties['DisplayName'] -and ($_.DisplayName -like 'Cursorway*' -or $_.DisplayName -like 'Barrier Share*') })
    if ($entries.Count -ne 1) { throw "Expected one installation entry, found $($entries.Count): $(($entries | ForEach-Object DisplayName) -join ', ')" }
}

Set-Content -LiteralPath (Join-Path $profile 'settings.xml') -Value '<settings host="true" address="" position="left" />' -Encoding utf8
Set-Content -LiteralPath (Join-Path $profile 'preserve-marker.txt') -Value ('before install ' + [Guid]::NewGuid()) -Encoding utf8
$beforeInstall = Get-ProfileHashes
$arguments = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', "/DIR=$installDir", '/TASKS=desktopicon')
if ($PreviousInstaller) {
    # Upgrade from a release made before the rename: install it, then the new installer without /DIR.
    # The new version must stay in the previous folder, replace its shortcuts and keep settings and pairing.
    Invoke-TestProcess (Resolve-Path -LiteralPath $PreviousInstaller).Path ($arguments + "/LOG=$(Join-Path $TestRoot 'install-previous.log')")
    # 0.3.20 and earlier create Barrier Share shortcuts, 0.3.21 already Cursorway ones.
    for ($i = 0; $i -lt $oldShortcuts.Count; $i++) { if (-not (Test-Path -LiteralPath $oldShortcuts[$i]) -and -not (Test-Path -LiteralPath $shortcuts[$i])) { throw "The previous release did not create its shortcut: $($oldShortcuts[$i])" } }
    Assert-Profile $beforeInstall
    # Stand-in for the service's state (the service rewrites it from the profile on every start).
    New-Item -ItemType Directory -Force -Path (Join-Path $installDir 'state\upgrade-test') | Out-Null
    Set-Content -LiteralPath (Join-Path $installDir 'state\upgrade-test\marker.txt') -Value 'state from before the rename' -Encoding utf8
    # Launch at sign-in as the old app wrote it (value BarrierShare, pointing at BarrierShare.exe).
    $upgradeRun = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    foreach ($name in 'BarrierShare', 'Cursorway') { if ($null -ne (Get-ItemProperty -LiteralPath $upgradeRun -Name $name -ErrorAction SilentlyContinue)) { throw "Refusing to alter an existing launch-at-sign-in entry: $name" } }
    Set-ItemProperty -LiteralPath $upgradeRun -Name BarrierShare -Value ('"' + (Join-Path $installDir 'BarrierShare.exe') + '" --background')
    $oldDir = $installDir
    Invoke-TestProcess $InstallerPath (@('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', '/TASKS=desktopicon') + "/LOG=$(Join-Path $TestRoot 'upgrade.log')")
    # The installation moves to Program Files\Cursorway; the old folder is gone once its state was copied.
    $installDir = $programFilesNew
    if (Test-Path -LiteralPath $oldDir) { throw "Upgrade left the old installation folder: $oldDir" }
    if ((Get-Content -LiteralPath (Join-Path $installDir 'state\upgrade-test\marker.txt') -Raw).Trim() -ne 'state from before the rename') { throw 'Upgrade did not carry the service state over.' }
    $arguments = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', "/DIR=$installDir", '/TASKS=desktopicon')
    Assert-Installed
    Assert-Profile $beforeInstall
    if (Get-Service BarrierShare -ErrorAction SilentlyContinue) { throw 'Upgrade left the service from before the rename.' }
    & sc.exe query BarrierShare | Out-Null
    if ($LASTEXITCODE -ne 1060) { throw "sc query BarrierShare still finds a service (exit $LASTEXITCODE)." }
    $service = Get-CimInstance Win32_Service -Filter "Name='Cursorway'"
    if (-not $service -or -not $service.PathName.Contains((Join-Path $installDir 'cursorway-service.exe'))) { throw 'Upgrade did not install the Cursorway service from the new folder.' }
    if ($null -ne (Get-ItemProperty -LiteralPath $upgradeRun -Name BarrierShare -ErrorAction SilentlyContinue)) { throw 'Upgrade left the old launch-at-sign-in entry.' }
    $run = (Get-ItemProperty -LiteralPath $upgradeRun -Name Cursorway -ErrorAction SilentlyContinue).Cursorway
    if ($run -ne ('"' + (Join-Path $installDir 'Cursorway.exe') + '" --background')) { throw "Upgrade did not move launch at sign-in to Cursorway.exe: $run" }
    Remove-ItemProperty -LiteralPath $upgradeRun -Name Cursorway
    foreach ($program in @(Get-NetFirewallRule -DisplayName 'Cursorway' -ErrorAction SilentlyContinue | Get-NetFirewallApplicationFilter | ForEach-Object { $_.Program })) {
        if (-not $program.StartsWith($installDir + '\', [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $program)) { throw "Firewall rule points at a missing or old program: $program" }
    }
    if (@(Get-NetFirewallRule -DisplayName 'Barrier Share' -ErrorAction SilentlyContinue).Count -ne 0) { throw 'Upgrade left the old firewall rules.' }
    foreach ($name in 'BarrierShare.exe', 'barriers.exe', 'barrierc.exe', 'barrier-pair.exe', 'barrier-link.exe', 'barrier-service.exe') {
        if (Test-Path -LiteralPath (Join-Path $installDir $name)) { throw "Upgrade left a program from before the rename: $name" }
    }
    if (@(Get-CimInstance Win32_Service | Where-Object { $_.DisplayName -like 'Cursorway*' -or $_.DisplayName -like 'Barrier Share*' }).Count -ne 1) { throw 'Expected one service after the upgrade.' }
    Write-Output '::notice title=Upgrade::from the previous release: moved to Program Files\Cursorway, old folder removed, state kept, one entry, one service, new shortcuts only, profile kept'
} else {
    Invoke-TestProcess $InstallerPath ($arguments + "/LOG=$(Join-Path $TestRoot 'install.log')")
    Assert-Installed
    Assert-Profile $beforeInstall
}

# The service starts a host core with the winlogon token of the console session, from data sent
# over its pipe, and stops it again. The core then also serves the sign-in screen and UAC prompts.
function Invoke-Service([string]$Line) {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'Cursorway.Service', [IO.Pipes.PipeDirection]::InOut)
    try {
        $pipe.Connect(5000); $pipe.ReadMode = [IO.Pipes.PipeTransmissionMode]::Message
        $bytes = [Text.Encoding]::UTF8.GetBytes($Line); $pipe.Write($bytes, 0, $bytes.Length); $pipe.Flush()
        $buffer = [byte[]]::new(65536); $reply = [IO.MemoryStream]::new()
        do { $read = $pipe.Read($buffer, 0, $buffer.Length); $reply.Write($buffer, 0, $read) } while ($read -gt 0 -and -not $pipe.IsMessageComplete)
        return [Text.Encoding]::UTF8.GetString($reply.ToArray()).Split("`t")
    } finally { $pipe.Dispose() }
}
function Get-FirewallPrograms { @(Get-NetFirewallRule -DisplayName 'Cursorway' -ErrorAction SilentlyContinue | Get-NetFirewallApplicationFilter | ForEach-Object { [IO.Path]::GetFileName($_.Program) } | Sort-Object) }
if ((Get-FirewallPrograms) -join ',' -ne 'cursorway-client.exe,cursorway-link.exe,cursorway-server.exe') { throw "Installer did not allow the programs through the firewall: $((Get-FirewallPrograms) -join ',')" }
if (Get-NetFirewallRule -DisplayName 'Barrier Share' -ErrorAction SilentlyContinue) { throw 'A firewall rule from before the rename remains.' }
foreach ($rule in Get-NetFirewallRule -DisplayName 'Cursorway') {
    if ([string]$rule.Profile -ne 'Domain, Private') { throw "Firewall rule profile is $($rule.Profile), expected Domain, Private." }
    if (@(($rule | Get-NetFirewallAddressFilter).RemoteAddress) -join ',' -ne 'Any') { throw 'Firewall rule limits remote addresses; manual addresses across subnets would be blocked.' }
}
function Get-ServiceCore { @(Get-CimInstance Win32_Process -Filter "Name='cursorway-server.exe'" | Where-Object { $_.ExecutablePath -ieq (Join-Path $installDir 'cursorway-server.exe') }) }
$serviceProfile = Join-Path $TestRoot 'service-identity'
& (Join-Path $installDir 'cursorway-pair.exe') init $serviceProfile | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot create a test identity for the service.' }
$pem = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $serviceProfile 'SSL\Barrier.pem')))
$config = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("section: screens`n windows-host:`n windows:`nend`nsection: links`n windows-host:`n  right = windows`n windows:`n  left = windows-host`nend`nsection: options`n clipboardSharing = true`nend`n"))
$console = (Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Select-Object -First 1).SessionId
Write-Output "::notice title=Service session::test session $((Get-Process -Id $PID).SessionId), explorer session $console"
# The core runs as the signed-in user from that user's own profile on the normal desktop, and as
# SYSTEM from the service's state folder on a secure desktop (simulated here: CI cannot lock or show UAC).
[IO.File]::WriteAllText((Join-Path $serviceProfile 'windows-windows.conf'), [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($config)))
$stateRoot = Join-Path $installDir 'state'
$me = [Environment]::UserName
function Wait-Core([string]$Owner, [string]$Log, [string]$Why) {
    $deadline = [DateTime]::UtcNow.AddSeconds(20); $found = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $core = Get-ServiceCore
        if ($core.Count -eq 1) {
            # A core that is being replaced may exit before GetOwner answers; it then has no User.
            $answer = Invoke-CimMethod -InputObject $core[0] -MethodName GetOwner -ErrorAction SilentlyContinue
            $user = if ($answer -and $answer.PSObject.Properties["User"]) { $answer.User } else { $null }
            if ($user -eq $Owner) { $found = $core[0]; break }
        }
        Start-Sleep -Milliseconds 250
    }
    $notes = (Get-ChildItem -LiteralPath $stateRoot -Recurse -Filter service.log -ErrorAction SilentlyContinue | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join ' '
    if (-not $found) { throw "Service core is not running as $Owner ($Why): $notes" }
    if ($found.SessionId -ne (Get-Process -Id $PID).SessionId) { throw "Service core runs in session $($found.SessionId), not the signed-in session." }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not ((Test-Path -LiteralPath $Log) -and (Get-Content -LiteralPath $Log -Raw).Contains('started server')) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }
    if (-not ((Test-Path -LiteralPath $Log) -and (Get-Content -LiteralPath $Log -Raw).Contains('started server'))) { throw "Server did not start as $Owner; log $Log" }
    Write-Output "::notice title=Service core::$Why -> $Owner, session $($found.SessionId), log $Log"
}
$reply = Invoke-Service "START`thost`t-`t$pem`t`t$config`twindows-host`t$serviceProfile"
if ($reply[0] -ne 'OK') { throw "Service refused START: $($reply -join ' ')" }
Wait-Core $me (Join-Path $serviceProfile 'server.log') 'normal desktop'
$reply = Invoke-Service "DESKTOP`tWinlogon"
Wait-Core 'SYSTEM' $reply[2] 'secure desktop'
$reply = Invoke-Service "DESKTOP`tauto"
Wait-Core $me (Join-Path $serviceProfile 'server.log') 'back on the normal desktop'
$switches = (Get-Content -LiteralPath (Join-Path (Split-Path $reply[2]) 'service.log') -Raw)
if (-not ($switches.Contains('core now runs as SYSTEM') -and $switches.Contains('core now runs as the signed-in user'))) { throw "Service log does not record the switches: $switches" }
# The app as a user without administrator rights (CI itself runs as one): 0.3.31 refused the real service then.
$checkFile = Join-Path $TestRoot 'service-check.txt'
& python (Join-Path $PSScriptRoot 'windows-basic-user-run.py') 30 ('"' + (Join-Path $installDir 'Cursorway.exe') + '" --service-check "' + $checkFile + '"')
$check = if (Test-Path -LiteralPath $checkFile) { Get-Content -LiteralPath $checkFile -Raw } else { 'no answer' }
if ($LASTEXITCODE -ne 0 -or -not $check.StartsWith('OK')) { throw "The app without administrator rights cannot use the service: $check (exit $LASTEXITCODE)" }
Write-Output "::notice title=Service as a basic user::$check"
$reply = Invoke-Service 'STOP'
if ($reply[0] -ne 'OK' -or $reply[1] -ne '0') { throw "Service did not stop the core: $($reply -join ' ')" }
Start-Sleep -Seconds 1
if (@(Get-ServiceCore).Count -ne 0) { throw 'Core kept running after STOP.' }
$reply = Invoke-Service "START`thost`t-`tbm90IGEga2V5`t`t$config`twindows-host`t$serviceProfile"
if ($reply[0] -ne 'ERROR') { throw 'Service accepted pairing data without a private key.' }
$reply = Invoke-Service "START`thost`t-`t$pem`t`t$config`twindows-host`trelative\path"
if ($reply[0] -ne 'ERROR') { throw 'Service accepted a relative profile folder.' }
# A newly paired host: the user's own core trusts it at once, but the cores with raised rights (SYSTEM on
# the sign-in and UAC screens, UI access for windows run as administrator) only after an administrator allows it.
$hostFp = 'v2:sha256:' + ('ab' * 32)
$trusted = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$hostFp`n"))
$reply = Invoke-Service "START`treceiver`t127.0.0.1:1`t$pem`t$trusted`t`twindows`t$serviceProfile"
if ($reply[0] -ne 'OK') { throw "Service refused the receiver START: $($reply -join ' ')" }
$receiverState = Split-Path $reply[2]
$systemTrust = Join-Path $receiverState 'SSL\Fingerprints\TrustedServers.txt'
$approval = Invoke-Service 'APPROVAL'
if ($approval[1] -ne '1' -or $approval[2] -ne $hostFp) { throw "Service did not report the host as waiting for approval: $($approval -join ' ')" }
if ((Get-Content -LiteralPath $systemTrust -Raw) -match 'abab') { throw 'A host nobody approved reached the trust list of the SYSTEM core.' }
Start-Sleep -Seconds 1
if (-not (Get-Content -LiteralPath (Join-Path $receiverState 'service.log') -Raw).Contains('not yet allowed by an administrator')) { throw 'The user core got UI access for a host nobody approved.' }
& (Join-Path $installDir 'cursorway-service.exe') --approve ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) $hostFp
if ($LASTEXITCODE -ne 0) { throw "Approving the host failed (exit $LASTEXITCODE)." }
$approval = Invoke-Service 'APPROVAL'
if ($approval[1] -ne '0') { throw "Host still waits for approval after it was approved: $($approval -join ' ')" }
$reply = Invoke-Service "START`treceiver`t127.0.0.1:1`t$pem`t$trusted`t`twindows`t$serviceProfile"
$deadline = [DateTime]::UtcNow.AddSeconds(20)
while (-not (Get-Content -LiteralPath (Join-Path $receiverState 'service.log') -Raw).Contains(', UI access: on, hardened') -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }
if (-not (Get-Content -LiteralPath (Join-Path $receiverState 'service.log') -Raw).Contains(', UI access: on, hardened')) { throw "The approved host did not get the hardened UI access core: $(Get-Content -LiteralPath (Join-Path $receiverState 'service.log') -Raw)" }
if (-not (Get-Content -LiteralPath $systemTrust -Raw).Contains($hostFp)) { throw 'The approved host is missing from the trust list of the SYSTEM core.' }
$reply = Invoke-Service 'STOP'

$startupRoot = Join-Path $TestRoot '已安裝啟動 startup'
Invoke-TestProcess $shortcuts[0] @('--startup-test', $startupRoot) 45 $true
if (-not (Test-Path -LiteralPath (Join-Path $startupRoot 'STARTUP-PASS.txt'))) { throw 'Installed Start Menu shortcut did not pass normal startup/discovery checks.' }
if ((Test-Path -LiteralPath $profileOld) -or -not (Test-Path -LiteralPath $profileNew)) { throw 'The app did not move LocalAppData\BarrierShare to LocalAppData\Cursorway on its first start.' }
Assert-Profile $beforeInstall

# Reinstall over existing files exercises the updater path without inventing an older release.
Set-Content -LiteralPath (Join-Path (Get-Profile) 'preserve-marker.txt') -Value ('before reinstall ' + [Guid]::NewGuid()) -Encoding utf8
Set-Content -LiteralPath (Join-Path (Get-Profile) 'settings.xml') -Value '<settings host="false" address="192.168.1.2" position="up" />' -Encoding utf8
$beforeReinstall = Get-ProfileHashes
Invoke-TestProcess $InstallerPath ($arguments + "/LOG=$(Join-Path $TestRoot 'reinstall.log')")
Assert-Installed
Assert-Profile $beforeReinstall
Invoke-TestProcess (Join-Path $installDir 'unins000.exe') @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=$(Join-Path $TestRoot 'uninstall.log')")
$sasAfter = (Get-SasPolicy)
if ("$sasAfter" -ne "$sasBefore") { throw "Uninstall did not put SoftwareSASGeneration back: '$sasAfter', was '$sasBefore'" }
foreach ($file in Get-ChildItem -LiteralPath $PackageDir -File -Recurse) {
    if (Test-Path -LiteralPath (Join-Path $installDir ([IO.Path]::GetRelativePath($PackageDir, $file.FullName)))) { throw "Uninstall left packaged file: $($file.Name)" }
}
if (Get-Service Cursorway -ErrorAction SilentlyContinue) { throw 'Uninstall left the Barrier Share service.' }
if (@(Get-FirewallPrograms).Count -ne 0) { throw 'Uninstall left the firewall rules.' }
if (Test-Path -LiteralPath (Join-Path $installDir 'state')) { throw 'Uninstall left the service state folder.' }
foreach ($path in @($uninstallKey, $machineKey) + $shortcuts + $oldShortcuts) {
    if (Test-Path -LiteralPath $path) { throw "Uninstall left registration or shortcut: $path" }
}
Assert-Profile $beforeReinstall

# Updating over a running copy closes it cleanly and starts it again; uninstall closes it and
# removes the launch-at-sign-in value. The running app may write its own profile from here on.
function Wait-Until([scriptblock]$Condition, [string]$Failure, [int]$Seconds = 20) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while (-not (& $Condition)) {
        if ([DateTime]::UtcNow -gt $deadline) { throw $Failure }
        Start-Sleep -Milliseconds 200
    }
}
function Test-AppRunning { $mutex = $null; $open = [Threading.Mutex]::TryOpenExisting('Local\Cursorway.Desktop', [ref]$mutex); if ($mutex) { $mutex.Dispose() }; return $open }
$app = Join-Path $installDir 'Cursorway.exe'
function Step([string]$Text) { Write-Output "::notice title=Installer step::$Text" }
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if ($null -ne (Get-ItemProperty -LiteralPath $runKey -Name Cursorway -ErrorAction SilentlyContinue)) { throw 'Refusing to alter an existing launch-at-sign-in entry.' }
# The previous uninstaller removes itself shortly after exiting; let it finish before installing again.
Wait-Until { -not (Test-Path -LiteralPath (Join-Path $installDir 'unins000.exe')) } 'Previous uninstaller did not finish removing itself.' 30
Invoke-TestProcess $InstallerPath ($arguments + "/LOG=$(Join-Path $TestRoot 'install-for-update.log')")
$first = Start-Process -FilePath $app -ArgumentList '--background' -PassThru
Step "started background copy $($first.Id)"
Wait-Until { Test-AppRunning } 'Installed app did not start in the background.'
Start-Sleep -Seconds 2
$updateLog = Join-Path $TestRoot 'update-running.log'
# The same switches the app uses when it installs a downloaded update.
Invoke-TestProcess $InstallerPath ((@('/SILENT') + ($arguments | Where-Object { $_ -ne '/VERYSILENT' })) + "/LOG=$updateLog")
Step ("update finished; first exited=$($first.HasExited); log: " + ((Select-String -LiteralPath $updateLog -Pattern 'quit|taskkill|Run entry|Cursorway.exe' | ForEach-Object { $_.Line.Substring([Math]::Min(24, $_.Line.Length)) }) -join ' | '))
Step ("processes: " + ((Get-Process Cursorway -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Id) $($_.Path)" }) -join ' | '))
if (-not $first.WaitForExit(1000)) { throw 'Setup replaced files without closing the running copy.' }
if ((Get-Content -LiteralPath $updateLog -Raw).Contains('did not quit on request')) { throw 'Running copy ignored the quit signal and had to be killed.' }
Wait-Until { @(Get-Process Cursorway -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $first.Id -and $_.Path -ieq $app }).Count -eq 1 } 'Setup did not start the updated copy again.'
$second = Get-Process Cursorway | Where-Object { $_.Path -ieq $app }
Set-ItemProperty -LiteralPath $runKey -Name Cursorway -Value ('"' + $app + '" --background')
Invoke-TestProcess (Join-Path $installDir 'unins000.exe') @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=$(Join-Path $TestRoot 'uninstall-running.log')")
if (-not $second.WaitForExit(1000)) { throw 'Uninstall left the app running.' }
if ($null -ne (Get-ItemProperty -LiteralPath $runKey -Name Cursorway -ErrorAction SilentlyContinue)) { throw 'Uninstall left the launch-at-sign-in entry.' }
if (Test-Path -LiteralPath $app) { throw 'Uninstall could not remove the app that was running.' }

Set-Content -LiteralPath (Join-Path $TestRoot 'INSTALLER-PASS.txt') -Value 'Administrator silent installation with the Barrier Share service (runs the core as the signed-in user, switches to SYSTEM for a secure desktop and back, stops it; rejects incomplete data) to a Unicode path with spaces; payload hashes and shortcuts match; installed Start Menu shortcut startup passes; repeat installation and uninstall preserve an existing profile; uninstall removes payload, shortcuts and registration; updating over a running background copy closes it through the quit signal and starts it again; uninstall closes a running copy and removes the launch-at-sign-in entry. With -PreviousInstaller it first upgrades from a release made before the rename (one folder, one entry, new shortcuts only, profile kept).' -Encoding utf8
Get-Content -LiteralPath (Join-Path $TestRoot 'INSTALLER-PASS.txt')
