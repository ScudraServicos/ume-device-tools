# UME device tools

Two scripts with the same items and results: `device-tools.sh` for macOS and Linux, and
`device-tools.ps1` for Windows. They do two things:

| # | Item | Systems | What it does |
|---|---|---|---|
| 1 | **Claude Code extension check** | macOS, Linux, Windows | Looks for the traces left by the backdoored Claude Code extension (versions 2.1.312 and 2.1.313 from the Cursor extension marketplace). **Read-only:** it reports, it changes nothing. |
| 2 | **Ubuntu network protection for [CVE-2026-98432](https://ubuntu.com/security/CVE-2026-98432)** | Ubuntu | Applies Ubuntu's published mitigation for a critical Linux kernel flaw (remote code execution). |

## Run it

These commands always run the latest release.

**macOS and Linux** (Terminal). Needs `sudo` (your computer password):

```bash
f=$(mktemp) && curl -fsSL https://github.com/ScudraServicos/ume-device-tools/releases/latest/download/device-tools.sh -o "$f" && sudo bash "$f"
```

Add `--status` (check only, changes nothing) or `--remove` (undo the Ubuntu protection) at
the end of the same command:

```bash
f=$(mktemp) && curl -fsSL https://github.com/ScudraServicos/ume-device-tools/releases/latest/download/device-tools.sh -o "$f" && sudo bash "$f" --status
```

Without `sudo` (macOS and non-Ubuntu Linux only), the check covers the current user only.

**Windows** (PowerShell). Open the Start menu, type `PowerShell`, choose **Run as
administrator**, then paste:

```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12'; $f="$env:TEMP\device-tools.ps1"; iwr -UseBasicParsing https://github.com/ScudraServicos/ume-device-tools/releases/latest/download/device-tools.ps1 -OutFile $f; if ($?) { powershell -NoProfile -ExecutionPolicy Bypass -File $f }
```

It only checks; nothing is changed on Windows. Without administrator rights it checks the current
user only. `-ExecutionPolicy Bypass` applies to that one run, not to the computer's settings. The
first part turns on TLS 1.2 for that window, which older Windows PowerShell needs to download
from GitHub.

To run one exact version, use `releases/download/<tag>/device-tools.sh` (or `.ps1`) instead of
`releases/latest/download/...` (tags are listed under Releases).

## Reading the result

The two items run in separate sections, each ending with its own `Result:` line, and a
`SUMMARY` at the end repeats both:

| Item | Result | What to do |
|---|---|---|
| 1. Claude Code extension check | `OK` | Nothing. No traces found. |
| | `ATTENTION` | **Do not delete anything. Contact the Security team now.** |
| 2. Ubuntu network protection | `ACTIVE` | Nothing. When Ubuntu releases the fix: update, restart, run again with `--remove`. |
| | `NOT ACTIVE` (`--status`) | Run the command without `--status` to turn it on. |
| | `NOT NEEDED` | Nothing. The computer does not run Ubuntu (always the case on Windows). |
| | `REMOVED` (`--remove`) | Nothing, if the official fix is installed. |

| Exit code | Meaning |
|---|---|
| 0 | OK |
| 1 | Error, or (`--status`) the Ubuntu protection is not active |
| 2 | Wrong arguments |
| 3 | Traces of the backdoored extension found: **contact the Security team, delete nothing** |

## 1. Claude Code extension check

Source: [Cursor security notice](https://cursor.com/blog/claude-code-extension-security-notice) and
[Phorion's analysis](https://phorion.io/blog/offical-claude-code-vsx-compromise/).

On October 29, 2026, modified builds of the Claude Code extension (2.1.312 and 2.1.313) were served
by the Cursor extension marketplace. When the editor loads them, they add an attacker SSH key, install
a startup item, open a reverse SSH tunnel and send host details to the attacker. **Updating or
removing the extension does not remove these traces.**

The check runs for every local account when run with `sudo` (macOS, Linux) or as administrator
(Windows). It reports:

| Trace | macOS and Linux | Windows |
|---|---|---|
| Backdoored extension file (contains `134.209.82.225`) | `~/.<editor>/extensions/anthropic.claude-code-*/extension.js` | `%USERPROFILE%\.<editor>\extensions\anthropic.claude-code-*\extension.js` |
| Attacker SSH key (`svc-telemetry`, `SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk`) | `~/.ssh/authorized_keys` | `%USERPROFILE%\.ssh\authorized_keys`, `%ProgramData%\ssh\administrators_authorized_keys` |
| Startup script and tunnel key | `~/.config/.smt`, `~/.config/.smtk` | `%USERPROFILE%\.config\smt.cmd`, `%USERPROFILE%\.config\smtk` |
| Startup item | `~/Library/LaunchAgents/com.apple.sysmond.plist` (macOS), `@reboot` crontab entry (Linux) | scheduled task `SysMon` (or any task running `smt.cmd`), `sysmon.cmd` in the Startup folder |
| Tunnel key in the temporary folder | `/tmp/.stk_*`, `$TMPDIR/.stk_*` | `%TEMP%\.stk_*` |
| Running tunnel or retry loop | `ssh`/`autossh` to `134.209.82.225` or with `.stk_`/`.smtk`; shell running `.config/.smt` | `ssh.exe` to `134.209.82.225` or with `.stk_`/`smtk`; `cmd.exe` running `smt.cmd` or `sysmon.cmd` |
| Open connection to the attacker server | `134.209.82.225` | `134.209.82.225` |

Having version 2.1.312 or 2.1.313 installed is only noted, not counted: the backdoored builds came
from the Cursor marketplace, and Cursor reports no other distribution as affected, so the file
content decides.

On Windows the backdoor also tries to install and start OpenSSH Server, so the script notes when
the `sshd` service exists (not counted: many people install it on purpose). It also notes when
WSL is installed: with Cursor or VS Code connected to WSL, the extension can run inside WSL as
Linux, so run the macOS/Linux command inside WSL too.

**If anything is found, do not delete it.** The Security team handles removal and credential
rotation, and needs the traces to check whether anyone logged in through the tunnel.

## 2. Ubuntu network protection (CVE-2026-98432)

> **The real fix is an updated kernel.** This protection reduces the risk until the fixed kernel
> is installed **and running**. It does not fully prevent exploitation.

| Step | Detail |
|---|---|
| Checks | Prints the running kernel and whether its changelog lists the CVE. |
| Installs | `nftables`, if missing (the only step that needs network access). |
| Rule | Writes `/etc/cve-2026-98432.nft` and loads table `inet cve_2026_98432`: `ip protocol tcp ip hdrlength > 5 counter drop` on the input hook, priority -310. Own table: existing firewall rules are untouched. Re-running never duplicates the rule. |
| Reboot | Enables `cve-2026-98432-mitigation.service`, a oneshot unit that reloads the rule at boot. |
| `/etc/nftables.conf` | Only if `nftables.service` is already enabled: adds `include "/etc/cve-2026-98432.nft"`, so `systemctl reload/restart nftables` keeps the rule. |

`--remove` deletes the table, the rule file, the unit and the include line. It leaves the
`nftables` package installed. Hosts protected with the earlier `cve-2026-98432-mitigate.sh`
(v2026.11.04) use the same names, so this script manages them too.

**Impact:** blocks incoming IPv4 TCP packets that carry IP options. Normal IPv4 TCP, TCP options,
IPv6 and existing firewall rules keep working. TCP connections that depend on IPv4 options (rare,
e.g. CIPSO-labeled networks) break. Containers with their own network namespace need the script
run inside them too.

**Differences from the advisory steps.** The rule is the advisory's rule, unchanged. Boot
persistence uses its own systemd unit instead of enabling `nftables.service`, because that service
runs `flush ruleset` when it starts and would wipe rules managed by UFW, firewalld, Docker or
Kubernetes. The rule file starts with `table` + `delete table`, so reloading it never adds a second
copy. On Ubuntu 18.04 the `nftables` package enables `nftables.service` on install, so there the
include line is added too.

**Getting the fix.** Check the [advisory](https://ubuntu.com/security/CVE-2026-98432) for the fixed
kernel of your release. When it is published: `sudo apt update && sudo apt upgrade && sudo reboot`,
then run the script with `--remove`. Ubuntu 22.04 and newer got fixes in the `-proposed` pocket
first ([Canonical blog](https://ubuntu.com/blog/fixes-available-in-proposed-pocket-for-cve-2026-98432));
this script does not enable `-proposed`. Ubuntu 20.04 and older get fixes through Ubuntu Pro (ESM).
Disabling MPTCP is **not** a mitigation.

## Check before you run

Each release has the scripts and their SHA-256 (`device-tools.sh.sha256`,
`device-tools.ps1.sha256`) as files. macOS and Linux:

```bash
curl -fsSLO https://github.com/ScudraServicos/ume-device-tools/releases/latest/download/device-tools.sh
curl -fsSLO https://github.com/ScudraServicos/ume-device-tools/releases/latest/download/device-tools.sh.sha256
shasum -a 256 -c device-tools.sh.sha256   # sha256sum -c on Linux
less device-tools.sh                      # read it
sudo bash device-tools.sh
```

Windows (PowerShell):

```powershell
$u = 'https://github.com/ScudraServicos/ume-device-tools/releases/latest/download/device-tools.ps1'
$f = "$env:TEMP\device-tools.ps1"
iwr -UseBasicParsing $u -OutFile $f
iwr -UseBasicParsing "$u.sha256" -OutFile "$f.sha256"
(Get-FileHash $f -Algorithm SHA256).Hash -eq (Get-Content "$f.sha256").Split(' ')[0]   # must print True
notepad $f                                                                              # read it
powershell -NoProfile -ExecutionPolicy Bypass -File $f
```

## Releases

Pushing a signed tag `vYYYY.MM.DD[.N]` (only the infrasec team can push tags) runs
`.github/workflows/release.yml`. It publishes only if GitHub verifies the tag signature and the
`VERSION` of both scripts matches the tag (`device-tools.ps1` must also parse and be ASCII only),
then attaches both scripts and their SHA-256 and marks the release as latest. Releases are
immutable once published. To publish an existing tag again, run the workflow manually with that
tag.

## Tests

- `tests/ubuntu-e2e.sh [image]` runs the script in Docker: real TCP connections with and without IP
  options, re-runs, `--status`, `--remove`, non-root refused on Ubuntu, reboots under systemd, the
  extension check against planted traces (and that it leaves them untouched), and a non-Ubuntu
  system (check only). Passing on `ubuntu:18.04`, `20.04`, `22.04`, `24.04` and `26.04`. Containers
  share the Docker host's kernel, so these tests cover each release's userspace, not its kernel.
- `tests/macos-check.sh` runs the extension check with the bash 3.2 that ships with macOS, against
  fake home and temp folders.
- `tests/windows-check.ps1` tests `device-tools.ps1`. `.github/workflows/test.yml` runs it on every
  pull request that changes it: on a disposable Windows runner as administrator, with Windows
  PowerShell 5.1 and PowerShell 7 (planted files, a `SysMon` scheduled task, the startup script
  running, a decoy process), and on Linux with PowerShell 7 against fake profile folders. On a
  real Windows computer it refuses to run, because it plants traces in the profile.

## References

- Cursor notice: <https://cursor.com/blog/claude-code-extension-security-notice>
- Phorion analysis: <https://phorion.io/blog/offical-claude-code-vsx-compromise/>
- Ubuntu advisory: <https://ubuntu.com/security/CVE-2026-98432>
- Canonical blog: <https://ubuntu.com/blog/fixes-available-in-proposed-pocket-for-cve-2026-98432>
- Kernel fix: <https://git.kernel.org/linus/e3f33b0a1d89d738e2b913dab519226eaf76e15b>
