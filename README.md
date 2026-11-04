# CVE-2026-98432 mitigation for Ubuntu

One script that applies Ubuntu's published mitigation for
[CVE-2026-98432](https://ubuntu.com/security/CVE-2026-98432): a use-after-free in the
Linux kernel's IPv4 TCP connection setup that can lead to remote code execution
(Ubuntu priority **Critical**, CVSS 3.1 9.8).

> **The real fix is an updated kernel.** This mitigation reduces the risk until the
> fixed kernel is installed **and running**. It does not fully prevent exploitation.

## Run it

Needs `sudo` and Ubuntu 18.04 or later.

```bash
f=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/ScudraServicos/cve-2026-98432-mitigation/v2026.11.04/cve-2026-98432-mitigate.sh -o "$f" && sudo bash "$f"
```

Add `--status` (check only, changes nothing; exit 0 = active) or `--remove` (undo) at
the end of the same command:

```bash
f=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/ScudraServicos/cve-2026-98432-mitigation/v2026.11.04/cve-2026-98432-mitigate.sh -o "$f" && sudo bash "$f" --status
```

## What it does

| Step | Detail |
|---|---|
| Checks | Runs only as root and only on Ubuntu. Prints the running kernel and whether its changelog lists the CVE. |
| Installs | `nftables`, if missing (the only step that needs network access). |
| Rule | Writes `/etc/cve-2026-98432.nft` and loads table `inet cve_2026_98432`: `ip protocol tcp ip hdrlength > 5 counter drop` on the input hook, priority -310. Own table: existing firewall rules are untouched. Re-running never duplicates the rule. |
| Reboot | Enables `cve-2026-98432-mitigation.service`, a oneshot unit that reloads the rule at boot. |
| `/etc/nftables.conf` | Only if `nftables.service` is already enabled: adds `include "/etc/cve-2026-98432.nft"`, so `systemctl reload/restart nftables` keeps the rule. |

`--remove` deletes the table, the rule file, the unit and the include line. It leaves the
`nftables` package installed.

## Impact

- **Blocks:** incoming IPv4 TCP packets that carry IP options.
- **Keeps working:** normal IPv4 TCP, TCP options (timestamps, window scaling), IPv6, and
  all existing firewall rules.
- **Breaks:** TCP connections that depend on IPv4 options (rare, e.g. CIPSO-labeled networks).
- **Covers:** this host, including connections to itself. Containers with their own network
  namespace need the script run inside them too.

## Differences from the advisory steps

The nftables rule is the advisory's rule, unchanged. How it is installed differs on purpose:

1. **Boot persistence uses its own systemd unit instead of enabling `nftables.service`.**
   `nftables.service` runs `flush ruleset` when it starts. On hosts whose firewall is managed
   by UFW, firewalld, Docker or Kubernetes through iptables-nft, that wipes their rules. The
   advisory assumes no such tools; a one-line command cannot.
2. **The rule file is idempotent.** It starts with `table` + `delete table`, so loading it
   again (re-run, boot, nftables reload) replaces the rule instead of adding a second copy.

On Ubuntu 18.04 the `nftables` package enables `nftables.service` when it is installed
(package default, accept-all config), so there the include line is added too.

## Getting the fix

Check the [advisory](https://ubuntu.com/security/CVE-2026-98432) for the fixed kernel
version of your release and kernel flavor. When it is published:

```bash
sudo apt update && sudo apt upgrade && sudo reboot
```

Then run the script with `--remove`.

- Ubuntu 22.04 and newer: Canonical published the fixes in the `-proposed` pocket first,
  for users who run their own kernel acceptance tests
  ([Canonical blog](https://ubuntu.com/blog/fixes-available-in-proposed-pocket-for-cve-2026-98432)).
  This script does not enable `-proposed`.
- Ubuntu 20.04 and older: fixes come through Ubuntu Pro (ESM).
- Disabling MPTCP is **not** a mitigation for this CVE. The bug is not specific to MPTCP.

## Check before you run

```bash
curl -fsSLO https://raw.githubusercontent.com/ScudraServicos/cve-2026-98432-mitigation/v2026.11.04/cve-2026-98432-mitigate.sh
sha256sum cve-2026-98432-mitigate.sh   # compare with the release notes
less cve-2026-98432-mitigate.sh         # read it
sudo bash cve-2026-98432-mitigate.sh
```

## Tests

`tests/ubuntu-e2e.sh [image]` runs the script in Docker. It checks:

- Real TCP connections with and without IP options.
- That re-running never duplicates the rule.
- `--status` and `--remove`.
- That non-root users and non-Ubuntu systems are refused.
- That the rule survives a reboot under systemd, with and without `nftables.service`.

Passing on `ubuntu:18.04`, `20.04`, `22.04`, `24.04` and `26.04`. Containers share the
Docker host's kernel, so these tests cover the nftables userspace and systemd of each
release, not its kernel.

## References

- Ubuntu advisory: <https://ubuntu.com/security/CVE-2026-98432>
- Canonical blog: <https://ubuntu.com/blog/fixes-available-in-proposed-pocket-for-cve-2026-98432>
- Upstream fix: <https://git.kernel.org/linus/e3f33b0a1d89d738e2b913dab519226eaf76e15b>
