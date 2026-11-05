#!/usr/bin/env bash
# device-tools.sh - UME device check for macOS and Linux (Ubuntu).
#
# It does two things:
#
#   1. Claude Code extension check (macOS and Linux). READ-ONLY.
#      Versions 2.1.312 and 2.1.313 of the Claude Code extension published on
#      the Cursor extension marketplace carried a backdoor: it plants an SSH key,
#      adds a startup item and opens a reverse SSH tunnel. Updating or removing
#      the extension does not remove what it planted. This step only looks for
#      those traces and reports them. It changes nothing.
#        Notice: https://cursor.com/blog/claude-code-extension-security-notice
#
#   2. Ubuntu network protection for CVE-2026-98432 (Ubuntu only).
#      CVE-2026-98432 is a use-after-free in the Linux kernel's IPv4 TCP
#      connection setup that can lead to remote code execution. Until the fixed
#      kernel is installed AND running, this applies the mitigation published by
#      Ubuntu: an nftables rule that drops incoming IPv4 TCP packets carrying IP
#      options. Existing firewall rules are not touched. TCP connections that
#      depend on IPv4 options stop working; TCP options and IPv6 are not affected.
#        Advisory: https://ubuntu.com/security/CVE-2026-98432
#
# Usage:
#   sudo bash device-tools.sh            check, then apply the Ubuntu protection (default)
#   sudo bash device-tools.sh --status   check and show status, change nothing
#   sudo bash device-tools.sh --remove   remove the Ubuntu protection
# Without sudo (macOS and non-Ubuntu Linux): checks the current user only.
#
# Exit codes: 0 ok | 1 error, or (--status) Ubuntu protection not active |
#             2 usage | 3 traces of the backdoored extension found.
#
# Compatible with the bash 3.2 that ships with macOS.

set -euo pipefail

VERSION="2026.11.05"

# --- Item 1: Claude Code extension check -----------------------------------
EXT_NOTICE="https://cursor.com/blog/claude-code-extension-security-notice"
IOC_IP="134.209.82.225"
IOC_KEY="AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P"
IOC_KEY_COMMENT="svc-telemetry"
IOC_LAUNCH_AGENT="Library/LaunchAgents/com.apple.sysmond.plist"

# --- Item 2: Ubuntu network protection (names kept from v2026.11.04) --------
CVE="CVE-2026-98432"
ADVISORY="https://ubuntu.com/security/${CVE}"
TABLE="cve_2026_98432"
RULE_FILE="/etc/cve-2026-98432.nft"
UNIT="cve-2026-98432-mitigation.service"
UNIT_FILE="/etc/systemd/system/${UNIT}"
NFT_CONF="/etc/nftables.conf"
INCLUDE_LINE="include \"${RULE_FILE}\""

NFT=""
OS_KIND=""
OS_NAME=""
WORKDIR=""
FOUND=0
REPORTED="
"

# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() { if [ -n "$WORKDIR" ]; then rm -rf "$WORKDIR"; fi; }
trap cleanup EXIT

say() { printf '[+] %s\n' "$*"; }
note() { printf '[-] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
found_reminder() {
  if [ "$FOUND" -gt 0 ]; then
    printf '[!] %s\n' "Reminder: ${FOUND} trace(s) of the backdoored Claude Code extension were found (see above)." \
      "Do not delete anything. Contact the Security team right away." >&2
  fi
}
die() {
  printf '[x] %s\n' "$*" >&2
  found_reminder
  if [ "$FOUND" -gt 0 ]; then exit 3; fi
  exit 1
}

usage() {
  cat <<EOF
device-tools.sh ${VERSION} - UME device check for macOS and Linux

Usage: sudo bash device-tools.sh [--apply | --status | --remove]
  --apply    check for the backdoored Claude Code extension, then apply the
             Ubuntu network protection for ${CVE} (default)
  --status   check and show status, change nothing
  --remove   remove the Ubuntu network protection
  --help     show this help
  --version  show the script version

Exit codes: 0 ok, 1 error or protection not active (--status), 2 usage,
            3 traces of the backdoored extension found.

Claude Code extension notice: ${EXT_NOTICE}
Ubuntu advisory:              ${ADVISORY}
EOF
}

is_root() { [ "$(id -u)" -eq 0 ]; }

detect_os() {
  local id="" id_like=""
  case "$(uname -s)" in
    Darwin)
      OS_KIND="macos"
      OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null || true)"
      ;;
    Linux)
      OS_KIND="linux"
      OS_NAME="Linux"
      if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        id="$(. /etc/os-release && printf '%s' "${ID:-}")"
        # shellcheck disable=SC1091
        id_like="$(. /etc/os-release && printf '%s' "${ID_LIKE:-}")"
        # shellcheck disable=SC1091
        OS_NAME="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-Linux}")"
      fi
      case " ${id} ${id_like} " in
        *" ubuntu "*) OS_KIND="ubuntu" ;;
      esac
      ;;
    *) die "This script supports macOS and Linux only (found: $(uname -s))." ;;
  esac
}

# ============================================================================
# Item 1: Claude Code extension check (read-only)
# ============================================================================

# Report each trace once, even if two paths point to the same file.
found() {
  case "$REPORTED" in *"
$1
"*) return 0 ;; esac
  REPORTED="${REPORTED}$1
"
  FOUND=$((FOUND + 1))
  printf '[!] FOUND: %s\n' "$1"
}

# Physical path of an existing file (resolves /tmp -> /private/tmp on macOS).
real_path() { printf '%s/%s' "$(cd -P "$(dirname "$1")" 2>/dev/null && pwd -P)" "$(basename "$1")"; }

# One "user<TAB>home" line per local account. Without root: the current user only.
list_homes() {
  if ! is_root; then
    printf '%s\t%s\n' "$(id -un)" "${HOME:-}"
    return 0
  fi
  if [ "$OS_KIND" = "macos" ]; then
    dscl . -list /Users NFSHomeDirectory 2>/dev/null |
      awk '$1 == "root" || $2 ~ /^\/Users\// { print $1 "\t" $2 }' || true
  else
    { getent passwd 2>/dev/null || cat /etc/passwd; } |
      awk -F: '$3 == 0 || ($3 >= 1000 && $3 < 65534) { print $1 "\t" $6 }' || true
  fi
}

check_home() {
  local user="$1" home="$2" d f tab=""

  # Installed extension folders, in any editor (~/.cursor, ~/.vscode, ...).
  for d in "$home"/.*/extensions/anthropic.claude-code-*; do
    if [ ! -d "$d" ]; then continue; fi
    case "${d##*/}" in
      anthropic.claude-code-2.1.312* | anthropic.claude-code-2.1.313*)
        note "Affected version number installed: $d (the file check decides if it is the backdoored build)."
        ;;
    esac
    for f in "$d/extension.js" "$d/dist/extension.js"; do
      if [ -f "$f" ] && grep -qsF "$IOC_IP" "$f"; then
        found "backdoored extension file: $f"
      fi
    done
  done

  # Attacker SSH key (matched by key and by comment).
  for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
    if [ -f "$f" ] && grep -qsF -e "$IOC_KEY" -e "$IOC_KEY_COMMENT" "$f"; then
      found "attacker SSH key in $f"
    fi
  done

  # Startup script, tunnel key and (macOS) fake Apple LaunchAgent.
  for f in "$home/.config/.smt" "$home/.config/.smtk" "$home/$IOC_LAUNCH_AGENT"; do
    if [ -e "$f" ]; then
      found "backdoor file: $f"
    fi
  done

  # Linux persistence: @reboot entry in the user's crontab.
  if command -v crontab >/dev/null 2>&1; then
    if is_root; then
      tab="$(crontab -u "$user" -l 2>/dev/null || true)"
    else
      tab="$(crontab -l 2>/dev/null || true)"
    fi
    case "$tab" in
      *".config/.smt"*) found "backdoor startup entry in the crontab of user ${user}" ;;
    esac
  fi
}

check_system() {
  local f out hits line
  # Tunnel key in the temporary folder (/tmp/.stk_<hex>, $TMPDIR/.stk_<hex> on macOS).
  for f in /tmp/.stk_* /var/tmp/.stk_* /private/var/folders/*/*/T/.stk_* "${TMPDIR:-/tmp}"/.stk_*; do
    if [ -e "$f" ]; then
      found "backdoor key file: $(real_path "$f")"
    fi
  done

  # Running tunnel or retry loop.
  out="$(ps axww -o user=,pid=,command= 2>/dev/null || true)"
  hits="$(printf '%s\n' "$out" | grep -F -e "$IOC_IP" -e ".config/.smt" -e "/.stk_" || true)"
  if [ -n "$hits" ]; then
    while IFS= read -r line; do
      found "backdoor process running: $(printf '%s' "$line" | tr -s ' ' | cut -c1-160)"
    done <<EOF
$hits
EOF
  fi

  # Open connection to the attacker server.
  out=""
  if command -v ss >/dev/null 2>&1; then
    out="$(ss -tn 2>/dev/null || true)"
  elif command -v netstat >/dev/null 2>&1; then
    out="$(netstat -an 2>/dev/null || true)"
  fi
  case "$out" in
    *"$IOC_IP"*) found "open network connection to the attacker server ${IOC_IP}" ;;
  esac
}

ext_check() {
  local user home
  say "1/2 Claude Code extension check (read-only)"
  if ! is_root; then
    note "Not running as root: checking user $(id -un) only."
  fi
  while IFS=$'\t' read -r user home; do
    if [ -z "$home" ] || [ "$home" = "/" ] || [ ! -d "$home" ]; then continue; fi
    check_home "$user" "$home"
  done <<EOF
$(list_homes)
EOF
  check_system
  if [ "$FOUND" -eq 0 ]; then
    say "Claude Code extension: no traces of the backdoored version were found."
  else
    warn "Claude Code extension: ${FOUND} trace(s) of the backdoored version were found."
    warn "Do not delete anything. Contact the Security team right away."
  fi
}

# ============================================================================
# Item 2: Ubuntu network protection for CVE-2026-98432
# ============================================================================

has_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

in_container() {
  if command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --container --quiet; then
    return 0
  fi
  [ -f /.dockerenv ] || [ -f /run/.containerenv ]
}

# Informational only: Ubuntu kernel changelogs list the CVEs each build fixes.
kernel_status() {
  local krel f checked=0
  krel="$(uname -r)"
  for f in "/usr/share/doc/linux-modules-${krel}/changelog.Debian.gz" \
    "/usr/share/doc/linux-image-unsigned-${krel}/changelog.Debian.gz" \
    "/usr/share/doc/linux-image-${krel}/changelog.Debian.gz"; do
    [ -r "$f" ] || continue
    checked=1
    if zgrep -qF "$CVE" "$f"; then
      say "Running kernel ${krel}: its changelog lists ${CVE} (fix likely included)."
      return 0
    fi
  done
  if [ "$checked" -eq 1 ]; then
    warn "Running kernel ${krel}: its changelog does not list ${CVE}. Treat it as vulnerable."
  else
    warn "Running kernel ${krel}: changelog not found. Compare the version with ${ADVISORY}"
  fi
}

ensure_nft() {
  if ! command -v nft >/dev/null 2>&1; then
    say "Installing nftables (required by the protection)..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get -o DPkg::Lock::Timeout=120 update -qq ||
      warn "apt-get update reported errors; trying to install anyway."
    apt-get -o DPkg::Lock::Timeout=120 install -y -qq --no-install-recommends nftables >/dev/null ||
      die "Could not install nftables. Install it ('apt-get install nftables') and run again."
  fi
  NFT="$(command -v nft)" || die "nft not found after installing nftables."
}

table_loaded() { [ -n "$NFT" ] && "$NFT" list table inet "$TABLE" >/dev/null 2>&1; }

rule_count() {
  local n
  n="$("$NFT" list table inet "$TABLE" 2>/dev/null | grep -c 'hdrlength')" || true
  printf '%s' "${n:-0}"
}

include_present() { [ -f "$NFT_CONF" ] && grep -qxF "$INCLUDE_LINE" "$NFT_CONF"; }

drop_include() {
  local rc=0
  include_present || return 0
  grep -vxF "$INCLUDE_LINE" "$NFT_CONF" >"$WORKDIR/nftables.conf" || rc=$?
  [ "$rc" -le 1 ] || die "Could not edit ${NFT_CONF}."
  cat "$WORKDIR/nftables.conf" >"$NFT_CONF"
}

write_rule_file() {
  # The first two statements make re-loading the file idempotent: they create
  # the table if missing, then delete it, so the block below starts clean.
  cat >"$WORKDIR/rule.nft" <<EOF
# ${CVE} mitigation - ${ADVISORY}
# Drops incoming IPv4 TCP packets that carry IP options (IPv4 header longer
# than 20 bytes). Managed by device-tools.sh (--remove to undo).
table inet ${TABLE}
delete table inet ${TABLE}
table inet ${TABLE} {
	chain input {
		type filter hook input priority -310; policy accept;
		ip protocol tcp ip hdrlength > 5 counter drop
	}
}
EOF
  "$NFT" -c -f "$WORKDIR/rule.nft" ||
    die "nft rejected the rule (kernel without nf_tables support?). Nothing was changed."
  install -m 0644 -o root -g root "$WORKDIR/rule.nft" "$RULE_FILE"
}

persist() {
  local out
  if ! has_systemd; then
    warn "systemd is not running: the rule is active now but will NOT survive a reboot."
    return 0
  fi
  cat >"$WORKDIR/unit" <<EOF
[Unit]
Description=${CVE} mitigation (drop incoming IPv4 TCP packets with IP options)
Documentation=${ADVISORY}
DefaultDependencies=no
Wants=network-pre.target
After=nftables.service
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${NFT} -f ${RULE_FILE}

[Install]
WantedBy=sysinit.target
EOF
  install -m 0644 -o root -g root "$WORKDIR/unit" "$UNIT_FILE"
  systemctl daemon-reload
  if ! out="$(systemctl enable --now "$UNIT" 2>&1)"; then
    printf '%s\n' "$out" >&2
    die "Could not enable ${UNIT}. The rule is active now but will not survive a reboot."
  fi
  say "Kept after reboot by ${UNIT}."

  # Advisory method, used only where nftables.service already owns the firewall:
  # its reload/restart flushes the whole ruleset, so the rule must be in its config.
  if systemctl is-enabled --quiet nftables.service 2>/dev/null && [ -f "$NFT_CONF" ] && ! include_present; then
    if [ -n "$(tail -c1 "$NFT_CONF")" ]; then printf '\n' >>"$NFT_CONF"; fi
    printf '%s\n' "$INCLUDE_LINE" >>"$NFT_CONF"
    if "$NFT" -c -f "$NFT_CONF" >/dev/null 2>&1; then
      say "nftables.service is enabled: added the include line to ${NFT_CONF}."
    else
      drop_include
      warn "${NFT_CONF} does not pass 'nft -c'; left it unchanged. 'systemctl reload nftables' will drop the rule until the next reboot."
    fi
  fi
}

do_apply() {
  say "2/2 Ubuntu network protection for ${CVE}"
  kernel_status
  if in_container; then
    warn "Running inside a container: this only protects the container's own network. Apply it on the host too."
  fi
  ensure_nft
  write_rule_file
  "$NFT" -f "$RULE_FILE"
  persist
  [ "$(rule_count)" = "1" ] || die "Verification failed: the rule is not loaded as expected. Run with --status."
  say "Done: incoming IPv4 TCP packets with IP options are now dropped."
  say "Side effect: TCP connections that need IPv4 options will fail. TCP options and IPv6 are not affected."
  say "Containers with their own network namespace are not covered: run the script inside them too."
  say "This only reduces the risk. Install the fixed kernel when it is released ('apt update && apt upgrade'), reboot, then run with --remove."
}

show_status() {
  local active=1
  say "2/2 Ubuntu network protection for ${CVE}"
  kernel_status
  NFT="$(command -v nft || true)"
  if table_loaded && [ "$(rule_count)" -ge 1 ]; then
    active=0
    say "Protection: ACTIVE"
    "$NFT" list table inet "$TABLE" | grep 'hdrlength' | sed 's/^[[:space:]]*/    /'
  else
    warn "Protection: NOT active"
  fi
  if has_systemd && systemctl is-enabled --quiet "$UNIT" 2>/dev/null; then
    say "After reboot: kept (${UNIT} enabled)"
  else
    warn "After reboot: not kept"
  fi
  if include_present; then say "${NFT_CONF}: include line present"; fi
  return "$active"
}

do_remove() {
  if [ -f "$UNIT_FILE" ]; then
    if has_systemd; then systemctl disable --now "$UNIT" >/dev/null 2>&1 || true; fi
    rm -f "$UNIT_FILE"
    if has_systemd; then systemctl daemon-reload; fi
  fi
  drop_include
  NFT="$(command -v nft || true)"
  if table_loaded; then "$NFT" delete table inet "$TABLE"; fi
  rm -f "$RULE_FILE"
  say "Removed the ${CVE} protection (rule, ${RULE_FILE}, boot setting)."
  kernel_status
}

# ============================================================================

main() {
  local mode="apply" rc=0
  if [ "$#" -gt 1 ]; then
    usage >&2
    exit 2
  fi
  case "${1:-}" in
    "" | --apply) mode="apply" ;;
    --status) mode="status" ;;
    --remove) mode="remove" ;;
    -h | --help)
      usage
      exit 0
      ;;
    -V | --version)
      printf '%s\n' "$VERSION"
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  detect_os
  if [ "$OS_KIND" = "ubuntu" ] && ! is_root; then
    die "On Ubuntu this script must run as root. Use sudo."
  fi
  WORKDIR="$(mktemp -d)" || die "Cannot create a temporary directory (is the filesystem read-only?)."
  say "device-tools ${VERSION} on ${OS_NAME}"

  if [ "$mode" != "remove" ]; then ext_check; fi

  if [ "$OS_KIND" != "ubuntu" ]; then
    say "2/2 Ubuntu network protection for ${CVE}: not needed on this system (Ubuntu only)."
  else
    case "$mode" in
      apply) do_apply ;;
      status) show_status || rc=1 ;;
      remove) do_remove ;;
    esac
  fi

  found_reminder
  if [ "$FOUND" -gt 0 ]; then exit 3; fi
  exit "$rc"
}

# Everything above only defines functions: a truncated download runs nothing.
main "$@"
