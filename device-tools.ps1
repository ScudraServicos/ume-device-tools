# device-tools.ps1 - UME device check for Windows.
#
# The Windows counterpart of device-tools.sh (macOS and Linux). Same two items,
# same results and exit codes:
#
#   1. Claude Code extension check. READ-ONLY.
#      Versions 2.1.312 and 2.1.313 of the Claude Code extension published on
#      the Cursor extension marketplace carried a backdoor. On Windows it plants
#      an SSH key, adds a startup item (a scheduled task "SysMon", or
#      "sysmon.cmd" in the Startup folder), tries to turn on OpenSSH Server and
#      opens a reverse SSH tunnel. Updating or removing the extension does not
#      remove what it planted. This step only looks for those traces and
#      reports them. It changes nothing.
#        Notice:   https://cursor.com/blog/claude-code-extension-security-notice
#        Analysis: https://phorion.io/blog/offical-claude-code-vsx-compromise/
#      Result: OK (no traces) or ATTENTION (traces found: contact Security).
#
#   2. Ubuntu network protection for CVE-2026-98432: Ubuntu only, so on Windows
#      the result is always NOT NEEDED.
#
# Usage (PowerShell; run it as administrator to check every user):
#   powershell -NoProfile -ExecutionPolicy Bypass -File device-tools.ps1 [--status]
# No argument, --apply and --status all run the same read-only check.
#
# Exit codes: 0 ok | 1 error | 2 usage | 3 traces of the backdoored extension found.
#
# Compatible with Windows PowerShell 5.1 and PowerShell 7. ASCII only, so
# Windows PowerShell 5.1 reads it correctly without a byte order mark.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1

$Version = '2026.11.05.2'

# --- Item 1: Claude Code extension check -----------------------------------
$ExtNotice = 'https://cursor.com/blog/claude-code-extension-security-notice'
$IocIp = '134.209.82.225'
$IocKey = 'AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P'
$IocKeyComment = 'svc-telemetry'
$IocTaskName = 'SysMon'
$IocStartupFile = 'sysmon.cmd'
# Startup script and tunnel key in the user's .config folder (smt.cmd and smtk
# on Windows; .smt and .smtk are the macOS and Linux names).
$IocConfigFiles = @('smt.cmd', 'smtk', '.smt', '.smtk')
# A scheduled task or program that runs the startup script or reaches the server.
$IocRunPattern = 'smt\.cmd|\.config\\\.?smt|' + [regex]::Escape($IocIp)

# --- Item 2: Ubuntu only ----------------------------------------------------
$Cve = 'CVE-2026-98432'
$Advisory = "https://ubuntu.com/security/$Cve"

$script:Found = 0
$script:Reported = @{}
$script:Buf = New-Object 'System.Collections.Generic.List[string]'
$script:Notes = New-Object 'System.Collections.Generic.List[string]'
$script:Result1 = $null
$script:Result2 = $null
$script:Summary = $false
$script:IsAdmin = $false
$script:Me = ''
$script:MyHome = ''
$Line = '-' * 72

function Write-Out([string]$Text = '', [string]$Color = '', [switch]$NoNewline) {
  if ($Color) { Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline }
  else { Write-Host $Text -NoNewline:$NoNewline }
}
function Write-Step([string]$Text, [string]$Color = '') { Write-Out ('  ' + $Text) $Color }
function Write-Section([string]$Title) { Write-Out ''; Write-Out $Line; Write-Out (' ' + $Title); Write-Out $Line }
function Write-Result([string]$Text, [string]$Color = '') { Write-Out ''; Write-Out ('  Result: ' + $Text) $Color }
function New-Status([string]$Word, [string]$Color, [string]$Rest) { @{ Word = $Word; Color = $Color; Rest = $Rest } }
function Write-Status($Status) {
  if (-not $Status) { Write-Out 'not run'; return }
  Write-Out $Status.Word $Status.Color -NoNewline
  Write-Out $Status.Rest
}

function Write-Summary {
  if (-not $script:Summary) { return }
  Write-Out ''
  Write-Out $Line
  Write-Out ' SUMMARY'
  Write-Out '   1. Claude Code extension check:  ' -NoNewline
  Write-Status $script:Result1
  Write-Out '   2. Ubuntu network protection:    ' -NoNewline
  Write-Status $script:Result2
  if ($script:Found -gt 0) {
    Write-Out ''
    Write-Out '   ACTION NEEDED (item 1): do not delete anything and contact the Security team now.' 'Red'
  }
  Write-Out $Line
}

function Show-Usage {
  Write-Out @"
device-tools.ps1 $Version - UME device check for Windows

It does the same two things as device-tools.sh on macOS and Linux:
  1. Claude Code extension check: looks for traces of a backdoored extension.
     Only looks, changes nothing. Result: OK or ATTENTION.
  2. Ubuntu network protection for ${Cve}: Ubuntu only, so on Windows the
     result is always NOT NEEDED.

Usage: powershell -NoProfile -ExecutionPolicy Bypass -File device-tools.ps1 [--status | --remove]
  (none), --apply, --status   run item 1 (read-only)
  --remove    nothing to turn off on Windows (item 1 is not run)
  --help      show this help
  --version   show the script version
Run PowerShell as administrator to check every user of the computer.

Exit codes: 0 ok, 1 error, 2 usage, 3 item 1 found traces.

Claude Code extension notice: $ExtNotice
Ubuntu advisory:              $Advisory
"@
}

function Test-Admin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Get-OsName {
  try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    return ('{0} {1}' -f $os.Caption, $os.Version).Trim()
  } catch { return [Environment]::OSVersion.VersionString }
}

function Join-PathPart { [IO.Path]::Combine([string[]]$args) }

# Full path with long folder names (C:\Users\RUNNER~1 -> C:\Users\runneradmin),
# so the same file reached through two paths is reported once.
function Get-LongPath([string]$Path) {
  if (-not $Path) { return '' }
  try {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.IndexOf('~') -lt 0) { return $full.TrimEnd('\') }
    $parts = $full.TrimEnd('\').Split('\')
    $out = $parts[0] + '\'
    for ($i = 1; $i -lt $parts.Count; $i++) {
      $item = @(Get-ChildItem -LiteralPath $out -Filter $parts[$i] -Force -ErrorAction Stop) | Select-Object -First 1
      if (-not $item) { return $full }
      $out = Join-Path $out $item.Name
    }
    return $out
  } catch { return $Path }
}

function Limit-Text([string]$Text, [int]$Max = 150) {
  $t = ($Text -replace '\s+', ' ').Trim()
  if ($t.Length -gt $Max) { return $t.Substring(0, $Max) + '...' }
  return $t
}

# True if the file exists and contains any of the strings (case-insensitive).
function Test-FileHas([string]$Path, [string[]]$Needles) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
  try { return [bool](Select-String -LiteralPath $Path -SimpleMatch -Pattern $Needles -Quiet -ErrorAction Stop) }
  catch { return $false }
}

# ============================================================================
# Item 1: Claude Code extension check (read-only)
# ============================================================================

# Record a trace once, even if two paths point to the same file.
function Add-Trace([string]$Text) {
  $key = $Text.ToLowerInvariant()
  if ($script:Reported.ContainsKey($key)) { return }
  $script:Reported[$key] = $true
  $script:Found++
  $script:Buf.Add($Text)
}
function Add-Note([string]$Text) { $script:Notes.Add($Text) }

# Print one line per place checked, then the traces found there.
function Write-Report([string]$Label, [int]$Before) {
  $n = $script:Found - $Before
  Write-Out ('  - {0}: ' -f $Label) -NoNewline
  if ($n -eq 0) { Write-Out 'nothing found' 'Green' } else { Write-Out ('{0} trace(s) found' -f $n) 'Red' }
  foreach ($t in $script:Buf) { Write-Out ('      ! ' + $t) 'Red' }
  foreach ($t in $script:Notes) { Write-Out ('      i ' + $t) }
  $script:Buf.Clear()
  $script:Notes.Clear()
}

# One object (User, Home) per local profile. Without administrator rights: the current user only.
function Get-HomeFolder {
  $homes = @()
  if ($script:IsAdmin) {
    try {
      foreach ($p in @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop)) {
        if ($p.Special -or -not $p.LocalPath) { continue }
        $homes += New-Object psobject -Property @{ User = (Split-Path -Leaf $p.LocalPath); Home = (Get-LongPath $p.LocalPath) }
      }
    } catch { $homes = @() }
  }
  if ($homes.Count -eq 0 -and $script:MyHome) {
    $homes += New-Object psobject -Property @{ User = $script:Me; Home = $script:MyHome }
  }
  return $homes
}

function Test-Home([string]$User, [string]$HomeDir) {
  $before = $script:Found
  $isMe = ($HomeDir -ieq $script:MyHome)

  # Installed extension folders, in any editor (~\.cursor, ~\.vscode, ...).
  $editors = @(Get-ChildItem -LiteralPath $HomeDir -Directory -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.Name.StartsWith('.') })
  foreach ($ed in $editors) {
    $exts = @(Get-ChildItem -LiteralPath (Join-PathPart $ed.FullName 'extensions') -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'anthropic.claude-code-*' })
    foreach ($d in $exts) {
      $hit = $false
      foreach ($f in @((Join-PathPart $d.FullName 'extension.js'), (Join-PathPart $d.FullName 'dist' 'extension.js'))) {
        if (Test-FileHas $f @($IocIp)) {
          Add-Trace "backdoored extension file: $f"
          $hit = $true
        }
      }
      $v = $d.Name.Substring('anthropic.claude-code-'.Length).Split('-')[0]
      if (-not $hit -and ($v -eq '2.1.312' -or $v -eq '2.1.313')) {
        Add-Note "extension version $v is installed, but its files are clean: $($d.FullName)"
      }
    }
  }

  # Attacker SSH key (matched by key and by comment).
  foreach ($f in @((Join-PathPart $HomeDir '.ssh' 'authorized_keys'), (Join-PathPart $HomeDir '.ssh' 'authorized_keys2'))) {
    if (Test-FileHas $f @($IocKey, $IocKeyComment)) { Add-Trace "attacker SSH key in $f" }
  }

  # Startup script and tunnel key.
  foreach ($n in $IocConfigFiles) {
    $f = Join-PathPart $HomeDir '.config' $n
    if (Test-Path -LiteralPath $f) { Add-Trace "backdoor file: $f" }
  }

  # Startup folder fallback (runs when the user signs in).
  $startup = @(Join-PathPart $HomeDir 'AppData' 'Roaming' 'Microsoft' 'Windows' 'Start Menu' 'Programs' 'Startup')
  if ($isMe -and $env:APPDATA) {
    $startup += Join-PathPart (Get-LongPath $env:APPDATA) 'Microsoft' 'Windows' 'Start Menu' 'Programs' 'Startup'
  }
  foreach ($dir in $startup) {
    $f = Join-PathPart $dir $IocStartupFile
    if (Test-Path -LiteralPath $f) { Add-Trace "backdoor startup item: $f" }
  }

  # Tunnel key in the temporary folder (.stk_<hex>).
  $temps = @(Join-PathPart $HomeDir 'AppData' 'Local' 'Temp')
  if ($isMe -and $env:TEMP) { $temps += Get-LongPath $env:TEMP }
  foreach ($dir in $temps) {
    $keys = @(Get-ChildItem -LiteralPath $dir -Filter '.stk_*' -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '.stk_*' })
    foreach ($k in $keys) { Add-Trace "backdoor key file: $($k.FullName)" }
  }

  Write-Report "user $User" $before
}

function Test-System {
  $before = $script:Found

  # Startup folder for all users, the administrators' SSH keys, the system temporary folder.
  if ($env:ProgramData) {
    $f = Join-PathPart $env:ProgramData 'Microsoft' 'Windows' 'Start Menu' 'Programs' 'StartUp' $IocStartupFile
    if (Test-Path -LiteralPath $f) { Add-Trace "backdoor startup item: $f" }
    $f = Join-PathPart $env:ProgramData 'ssh' 'administrators_authorized_keys'
    if (Test-FileHas $f @($IocKey, $IocKeyComment)) { Add-Trace "attacker SSH key in $f" }
  }
  if ($env:SystemRoot) {
    $keys = @(Get-ChildItem -LiteralPath (Join-PathPart $env:SystemRoot 'Temp') -Filter '.stk_*' -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '.stk_*' })
    foreach ($k in $keys) { Add-Trace "backdoor key file: $($k.FullName)" }
  }

  # Scheduled task "SysMon" (it asks for SYSTEM at startup), or any task that
  # runs the startup script or reaches the attacker server.
  if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
      $acts = @($t.Actions | ForEach-Object { ('{0} {1}' -f $_.Execute, $_.Arguments).Trim() }) -join '; '
      if ($acts -match $IocRunPattern) {
        Add-Trace ('backdoor scheduled task: {0}{1} (runs: {2})' -f $t.TaskPath, $t.TaskName, (Limit-Text $acts))
      } elseif ($t.TaskName -eq $IocTaskName) {
        Add-Note ('a scheduled task named {0} exists but does not run the backdoor script (runs: {1}). If you did not create it, tell the Security team.' -f $IocTaskName, (Limit-Text $acts))
      }
    }
  }

  # Running tunnel (ssh/autossh to the attacker server or with its key) or the
  # command shell running the startup script. This script's own process and
  # its parents are skipped, so the window that started it never matches.
  if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
    $procs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)
    $parent = @{}
    foreach ($p in $procs) { $parent[[int]$p.ProcessId] = [int]$p.ParentProcessId }
    $skip = @{}
    $id = [int]$PID
    while ($id -gt 0 -and -not $skip.ContainsKey($id)) {
      $skip[$id] = $true
      if (-not $parent.ContainsKey($id)) { break }
      $id = $parent[$id]
    }
    foreach ($p in $procs) {
      if ($skip.ContainsKey([int]$p.ProcessId)) { continue }
      $cmd = [string]$p.CommandLine
      if (-not $cmd) { continue }
      $name = ([string]$p.Name).ToLowerInvariant()
      $tunnel = (@('ssh.exe', 'autossh.exe') -contains $name) -and
        ($cmd.Contains($IocIp) -or $cmd.Contains('.stk_') -or ($cmd -match 'smtk'))
      $loop = (@('cmd.exe', 'powershell.exe', 'pwsh.exe') -contains $name) -and
        ($cmd -match ('smt\.cmd|sysmon\.cmd|tunnel@' + [regex]::Escape($IocIp)))
      if ($tunnel -or $loop) {
        Add-Trace ('backdoor program running: PID {0} {1}' -f $p.ProcessId, (Limit-Text $cmd))
      }
    }
  }

  # Open connection to the attacker server.
  if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    if (@(Get-NetTCPConnection -RemoteAddress $IocIp -ErrorAction SilentlyContinue).Count -gt 0) {
      Add-Trace "open connection to the attacker server $IocIp"
    }
  } elseif (Get-Command netstat -ErrorAction SilentlyContinue) {
    $conns = netstat -an 2>$null | Out-String
    if ($conns.Contains($IocIp)) {
      Add-Trace "open connection to the attacker server $IocIp"
    }
  }

  # Not traces by themselves, but worth a look.
  if (Get-Command Get-Service -ErrorAction SilentlyContinue) {
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($svc) {
      Add-Note ('OpenSSH Server (sshd) is installed ({0}). The backdoor tries to install and start it: if you did not set it up, tell the Security team.' -f $svc.Status.ToString().ToLowerInvariant())
    }
  }
  try {
    $lx = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    if (Test-Path -LiteralPath $lx) {
      $names = @(Get-ChildItem -LiteralPath $lx -ErrorAction SilentlyContinue |
          ForEach-Object { $_.GetValue('DistributionName') } | Where-Object { $_ })
      if ($names.Count -gt 0) {
        Add-Note ('WSL is installed ({0}). If you use Cursor or VS Code with WSL, the extension may run inside WSL: run the macOS/Linux command there too.' -f ($names -join ', '))
      }
    }
  } catch {
    Write-Verbose "WSL lookup skipped: $($_.Exception.Message)"
  }

  Write-Report 'scheduled tasks, startup items, running programs and network connections' $before
}

function Invoke-ExtCheck {
  Write-Section '1/2  Claude Code extension check'
  Write-Step 'What it does: looks for the traces left by a backdoored version of the'
  Write-Step 'Claude Code extension (2.1.312 and 2.1.313, from the Cursor extension store).'
  Write-Step 'It only looks. Nothing is changed or deleted.'
  Write-Out ''
  if ($script:IsAdmin) {
    Write-Step 'Checking every user of this computer:'
  } else {
    Write-Step 'Checking only your own user (run PowerShell as administrator to check every user):'
  }
  foreach ($h in @(Get-HomeFolder)) {
    if (-not $h.Home -or -not (Test-Path -LiteralPath $h.Home -PathType Container)) { continue }
    Test-Home $h.User $h.Home
  }
  Test-System

  if ($script:Found -eq 0) {
    $script:Result1 = New-Status 'OK' 'Green' ' - no traces found'
    Write-Result 'OK - no traces of the backdoored extension were found.' 'Green'
  } else {
    $script:Result1 = New-Status 'ATTENTION' 'Red' (' - {0} trace(s) found, contact the Security team' -f $script:Found)
    Write-Result ('ATTENTION - {0} trace(s) of the backdoored extension were found.' -f $script:Found) 'Red'
    Write-Step 'Do not delete anything and contact the Security team now.' 'Red'
  }
}

# ============================================================================

function Invoke-Main([string[]]$Argv) {
  $mode = 'apply'
  if ($Argv.Count -gt 1) { Show-Usage; exit 2 }
  $a = ''
  if ($Argv.Count -eq 1) { $a = [string]$Argv[0] }
  switch -CaseSensitive ($a) {
    '' { $mode = 'apply' }
    '--apply' { $mode = 'apply' }
    '--status' { $mode = 'status' }
    '--remove' { $mode = 'remove' }
    { @('-h', '--help', '/?') -contains $_ } { Show-Usage; exit 0 }
    { @('-V', '--version') -contains $_ } { Write-Out $Version; exit 0 }
    default { Show-Usage; exit 2 }
  }
  if ($env:OS -ne 'Windows_NT') {
    Write-Out '  Error: this script is for Windows. On macOS and Linux use device-tools.sh.' 'Red'
    exit 1
  }

  $script:IsAdmin = Test-Admin
  $script:Me = $env:USERNAME
  if (-not $script:Me) { $script:Me = [Environment]::UserName }
  $script:MyHome = Get-LongPath $env:USERPROFILE

  Write-Out ''
  Write-Out ('UME device tools {0} on {1}' -f $Version, (Get-OsName))
  Write-Out 'This script does two separate things, each with its own result:'
  Write-Out '  1. Claude Code extension check - looks for traces of a backdoored extension (changes nothing)'
  Write-Out '  2. Ubuntu network protection  - turns on a temporary protection (Ubuntu only)'
  if ($mode -eq 'status') { Write-Out 'Mode: --status (only checks, changes nothing)' }
  if ($mode -eq 'remove') { Write-Out 'Mode: --remove (turns off item 2 only)' }
  $script:Summary = $true

  if ($mode -eq 'remove') {
    $script:Result1 = New-Status 'not run' '' ' (--remove only turns off item 2)'
  } else {
    Invoke-ExtCheck
  }

  Write-Section "2/2  Ubuntu network protection ($Cve)"
  Write-Step 'What it does: blocks a rare kind of network traffic used to attack Ubuntu,'
  Write-Step "until Ubuntu's official fix is installed. Normal use is not affected."
  $script:Result2 = New-Status 'NOT NEEDED' '' ' - this computer does not run Ubuntu'
  Write-Result 'NOT NEEDED - this computer does not run Ubuntu.'

  Write-Summary
  if ($script:Found -gt 0) { exit 3 }
  exit 0
}

try {
  Invoke-Main $args
} catch {
  Write-Out ''
  Write-Out ('  Error: ' + $_.Exception.Message) 'Red'
  Write-Summary
  if ($script:Found -gt 0) { exit 3 }
  exit 1
}
