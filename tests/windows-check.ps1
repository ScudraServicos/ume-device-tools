# Test of device-tools.ps1.
#   usage: pwsh -NoProfile -File tests/windows-check.ps1
#
# - On Linux or macOS (PowerShell 7, e.g. the mcr.microsoft.com/powershell
#   Docker image): runs the script against fake Windows profile folders. Covers
#   the file checks, the output and the exit codes.
# - On Windows: runs only on a disposable GitHub Actions runner, because it
#   plants fake traces in the real profile and registers a scheduled task.
#   Also covers the scheduled task and running-program checks, administrator
#   mode and Windows PowerShell 5.1.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1

$Root = Split-Path -Parent $PSScriptRoot
$S = Join-Path $Root 'device-tools.ps1'
$OnWindows = ($env:OS -eq 'Windows_NT')
$IocIp = '134.209.82.225'
$IocKey = 'AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P'

function Ok([string]$m) { Write-Host "  ok   $m" }
function Fail([string]$m, [string]$out = '') {
  if ($out) { Write-Host $out }
  Write-Host "  FAIL $m"
  exit 1
}
function P { [IO.Path]::Combine([string[]]$args) }
function Put([string]$Path, [string]$Text) {
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
  [IO.File]::WriteAllText($Path, $Text + "`n")
}
function Run([string]$Shell, [string[]]$ArgList) {
  $out = & $Shell -NoProfile -ExecutionPolicy Bypass -File $S @ArgList 2>&1 | Out-String
  return @{ Rc = $LASTEXITCODE; Out = $out }
}

if ($OnWindows) {
  if ($env:GITHUB_ACTIONS -ne 'true') {
    Write-Host 'Refusing to run on a real Windows computer: this test plants fake traces in your profile.'
    Write-Host 'It runs on GitHub Actions (.github/workflows/test.yml), or on Linux/macOS with PowerShell 7.'
    exit 1
  }
  $Shells = @('powershell', 'pwsh')
  $H = $env:USERPROFILE
  $AppData = $env:APPDATA
  $Temp = $env:TEMP
  $Expected = 8
} else {
  $Shells = @('pwsh')
  $T = P ([IO.Path]::GetTempPath()) ('dt-test-' + [guid]::NewGuid().ToString('N'))
  $H = P $T 'Users' 'alice'
  $AppData = P $H 'AppData' 'Roaming'
  $Temp = P $H 'AppData' 'Local' 'Temp'
  New-Item -ItemType Directory -Force -Path $H, $AppData, $Temp | Out-Null
  $env:OS = 'Windows_NT'
  $env:USERPROFILE = $H
  $env:USERNAME = 'alice'
  $env:APPDATA = $AppData
  $env:TEMP = $Temp
  $env:ProgramData = P $T 'ProgramData'
  $env:SystemRoot = P $T 'Windows'
  $Expected = 6
}
$Version = ((Get-Content -LiteralPath $S | Where-Object { $_ -like '$Version = *' }) -split "'")[1]

$procs = @()
try {
  foreach ($sh in $Shells) {
    Write-Host "=== $sh : clean profile"
    $r = Run $sh @('--status')
    if ($r.Rc -ne 0) { Fail "exit $($r.Rc), expected 0" $r.Out }
    if ($r.Out -notmatch 'Result: OK - no traces') { Fail 'item 1 result OK' $r.Out }
    if ($r.Out -notmatch 'Result: NOT NEEDED') { Fail 'item 2 result NOT NEEDED' $r.Out }
    if ($OnWindows -and $r.Out -notmatch 'Checking every user') { Fail 'administrator mode' $r.Out }
    if (-not $OnWindows -and $r.Out -notmatch 'Checking only your own user') { Fail 'current-user mode' $r.Out }
    Ok 'exit 0, item 1 OK, item 2 NOT NEEDED'

    $r = Run $sh @('--version')
    if ($r.Rc -ne 0 -or $r.Out.Trim() -ne $Version) { Fail "--version printed '$($r.Out.Trim())'" }
    Ok "--version prints $Version"
    $r = Run $sh @('--bogus')
    if ($r.Rc -ne 2) { Fail "--bogus exit $($r.Rc), expected 2" $r.Out }
    $r = Run $sh @('--status', '--remove')
    if ($r.Rc -ne 2) { Fail "two arguments exit $($r.Rc), expected 2" $r.Out }
    Ok 'wrong arguments exit 2'
  }

  Write-Host '=== planting the published traces'
  Put (P $H '.ssh' 'authorized_keys') "ssh-ed25519 $IocKey svc-telemetry"
  Put (P $H '.config' 'smt.cmd') '@ping -n 120 127.0.0.1 >nul'
  Put (P $H '.config' 'smtk') 'key'
  Put (P $AppData 'Microsoft' 'Windows' 'Start Menu' 'Programs' 'Startup' 'sysmon.cmd') '@rem test'
  Put (P $H '.cursor' 'extensions' 'anthropic.claude-code-2.1.313-win32-x64' 'extension.js') "var h=`"$IocIp`";"
  Put (P $H '.vscode' 'extensions' 'anthropic.claude-code-2.1.312-win32-x64' 'extension.js') 'var h="clean";'
  Put (P $H '.cursor' 'extensions' 'anthropic.claude-code-2.1.314-win32-x64' 'extension.js') 'var h="clean";'
  Put (P $Temp '.stk_0123456789') 'key'
  if ($OnWindows) {
    $smt = P $H '.config' 'smt.cmd'
    $a = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c `"$smt`""
    Register-ScheduledTask -TaskName 'SysMon' -Action $a -Trigger (New-ScheduledTaskTrigger -AtStartup) -User 'SYSTEM' -RunLevel Highest | Out-Null
    # The startup script running, plus a decoy that only mentions the address.
    $procs += Start-Process cmd.exe -ArgumentList '/c', "`"$smt`"" -WindowStyle Hidden -PassThru
    $procs += Start-Process powershell.exe -ArgumentList '-NoProfile', '-Command', "Start-Sleep 120 # $IocIp" -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 2
  }

  foreach ($sh in $Shells) {
    foreach ($argList in @(@('--status'), @())) {
      $label = if ($argList.Count) { $argList[0] } else { '(no argument)' }
      Write-Host "=== $sh $label : traces planted"
      $r = Run $sh $argList
      if ($r.Rc -ne 3) { Fail "exit $($r.Rc), expected 3" $r.Out }
      if ($r.Out -notmatch "Result: ATTENTION - $Expected trace\(s\)") { Fail "expected $Expected traces" $r.Out }
      Ok "exit 3, item 1 ATTENTION with $Expected traces"
      foreach ($want in @('attacker SSH key in', 'backdoor file: .*smt\.cmd', 'backdoor file: .*smtk',
          'backdoor startup item: .*sysmon\.cmd', 'backdoored extension file: .*2\.1\.313', 'backdoor key file: .*\.stk_0123456789',
          'extension version 2\.1\.312 is installed, but its files are clean', 'ACTION NEEDED \(item 1\)',
          '2\. Ubuntu network protection: +NOT NEEDED')) {
        if ($r.Out -notmatch $want) { Fail "output lacks: $want" $r.Out }
      }
      if ($r.Out -match '2\.1\.314') { Fail 'clean 2.1.314 reported' $r.Out }
      if ($OnWindows) {
        if ($r.Out -notmatch 'backdoor scheduled task: \\SysMon') { Fail 'scheduled task' $r.Out }
        if ($r.Out -notmatch 'backdoor program running: PID \d+ .*cmd\.exe.*smt\.cmd') { Fail 'running startup script' $r.Out }
        if ($r.Out -match 'Start-Sleep') { Fail 'decoy process reported' $r.Out }
      }
      Ok 'every planted trace reported once; clean versions and decoys not counted'
    }
    $r = Run $sh @('--remove')
    if ($r.Rc -ne 0 -or $r.Out -notmatch 'not run') { Fail "--remove exit $($r.Rc)" $r.Out }
    Ok '--remove: nothing to turn off, exit 0'
  }

  foreach ($f in @((P $H '.ssh' 'authorized_keys'), (P $H '.config' 'smt.cmd'), (P $Temp '.stk_0123456789'))) {
    if (-not (Test-Path -LiteralPath $f)) { Fail "read-only: $f was removed" }
  }
  if ($OnWindows -and -not (Get-ScheduledTask -TaskName 'SysMon' -ErrorAction SilentlyContinue)) { Fail 'read-only: task removed' }
  Ok 'read-only: traces left untouched'
  Write-Host '=== All Windows check tests passed'
} finally {
  foreach ($p in $procs) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
  if ($OnWindows) {
    Unregister-ScheduledTask -TaskName 'SysMon' -Confirm:$false -ErrorAction SilentlyContinue
  } elseif ($T -and (Test-Path -LiteralPath $T)) {
    Remove-Item -LiteralPath $T -Recurse -Force
  }
}
