#!/usr/bin/env bash
# device-tools.sh - UME device check for macOS and Linux (Ubuntu).
#
# It does two separate things, each with its own result:
#
#   1. Claude Code extension check (macOS and Linux). READ-ONLY.
#      Versions 2.1.312 and 2.1.313 of the Claude Code extension published on
#      the Cursor extension marketplace carried a backdoor: it plants an SSH key,
#      adds a startup item and opens a reverse SSH tunnel. Updating or removing
#      the extension does not remove what it planted. This step only looks for
#      those traces and reports them. It changes nothing.
#        Notice: https://cursor.com/blog/claude-code-extension-security-notice
#      Result: OK (no traces) or ATTENTION (traces found: contact Security).
#
#   2. Ubuntu network protection for CVE-2026-98432 (Ubuntu only).
#      CVE-2026-98432 is a use-after-free in the Linux kernel's IPv4 TCP
#      connection setup that can lead to remote code execution. Until the fixed
#      kernel is installed AND running, this applies the mitigation published by
#      Ubuntu: an nftables rule that drops incoming IPv4 TCP packets carrying IP
#      options. Existing firewall rules are not touched. TCP connections that
#      depend on IPv4 options stop working; TCP options and IPv6 are not affected.
#        Advisory: https://ubuntu.com/security/CVE-2026-98432
#      Result: ACTIVE, NOT ACTIVE, NOT NEEDED (not Ubuntu) or REMOVED.
#
# Usage:
#   sudo bash device-tools.sh            check, then turn on the Ubuntu protection (default)
#   sudo bash device-tools.sh --status   check and show status, change nothing
#   sudo bash device-tools.sh --remove   turn off the Ubuntu protection
# Without sudo (macOS and non-Ubuntu Linux): checks the current user only.
#
# Exit codes: 0 ok | 1 error, or (--status) Ubuntu protection not active |
#             2 usage | 3 traces of the backdoored extension found.
#
# Compatible with the bash 3.2 that ships with macOS.

set -euo pipefail

VERSION="2026.11.05.1"

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
REPORTED=$'\n'
BUF=""
NOTES=""
RESULT1=""
RESULT2=""
SUMMARY=0
KEPT_AFTER_RESTART=1

# Colors only on an interactive terminal.
if [ -t 1 ] && [ "${TERM:-dumb}" != "dumb" ]; then
  C_OK=$'\033[1;32m' C_BAD=$'\033[1;31m' C_WARN=$'\033[1;33m' C_B=$'\033[1m' C_0=$'\033[0m'
else
  C_OK="" C_BAD="" C_WARN="" C_B="" C_0=""
fi
LINE="------------------------------------------------------------------------"

# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() { if [ -n "$WORKDIR" ]; then rm -rf "$WORKDIR"; fi; }
trap cleanup EXIT

info() { printf '%s\n' "$*"; }
step() { printf '  %s\n' "$*"; }
warn() { printf '  %s! %s%s\n' "$C_WARN" "$*" "$C_0"; }
section() { printf '\n%s\n %s%s%s\n%s\n' "$LINE" "$C_B" "$*" "$C_0" "$LINE"; }
result() { printf '\n  %sResult: %s%s\n' "$1" "$2" "$C_0"; }

print_summary() {
  if [ "$SUMMARY" -ne 1 ]; then return 0; fi
  printf '\n%s\n %sSUMMARY%s\n' "$LINE" "$C_B" "$C_0"
  printf '   1. Claude Code extension check:  %s\n' "${RESULT1:-not run}"
  printf '   2. Ubuntu network protection:    %s\n' "${RESULT2:-not run}"
  if [ "$FOUND" -gt 0 ]; then
    printf '\n   %sACTION NEEDED (item 1): do not delete anything and contact the Security team now.%s\n' "$C_BAD" "$C_0"
  fi
  printf '%s\n' "$LINE"
}

die() {
  printf '\n  %sError: %s%s\n' "$C_BAD" "$*" "$C_0" >&2
  print_summary
  if [ "$FOUND" -gt 0 ]; then exit 3; fi
  exit 1
}

usage() {
  cat <<EOF
device-tools.sh ${VERSION} - UME device check for macOS and Linux

It does two separate things:
  1. Claude Code extension check: looks for traces of a backdoored extension.
     Only looks, changes nothing. Result: OK or ATTENTION.
  2. Ubuntu network protection for ${CVE} (Ubuntu only).
     Result: ACTIVE, NOT ACTIVE, NOT NEEDED or REMOVED.

Usage: sudo bash device-tools.sh [--apply | --status | --remove]
  --apply    run item 1, then turn on item 2 (default)
  --status   run item 1 and show the state of item 2, change nothing
  --remove   turn off item 2 (after the official Ubuntu fix is installed)
  --help     show this help
  --version  show the script version

Exit codes: 0 ok, 1 error or item 2 not active (--status), 2 usage,
            3 item 1 found traces.

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

# Record a trace once, even if two paths point to the same file.
found() {
  case "$REPORTED" in *"
$1
"*) return 0 ;; esac
  REPORTED="${REPORTED}$1
"
  FOUND=$((FOUND + 1))
  BUF="${BUF}      ${C_BAD}!${C_0} $1
"
}

# Print one line per place checked, then the traces found there.
report() {
  local n=$((FOUND - $2))
  if [ "$n" -eq 0 ]; then
    step "- ${1}: ${C_OK}nothing found${C_0}"
  else
    step "- ${1}: ${C_BAD}${n} trace(s) found${C_0}"
  fi
  printf '%s%s' "$BUF" "$NOTES"
  BUF=""
  NOTES=""
}

# PIDs of this script and its parents (the shell, sudo, ...).
own_pids() {
  local p="$$"
  while [ -n "$p" ] && [ "$p" -gt 1 ] 2>/dev/null; do
    printf '%s ' "$p"
    p="$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')"
  done
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
  local user="$1" home="$2" before="$FOUND" d f v hit tab=""

  # Installed extension folders, in any editor (~/.cursor, ~/.vscode, ...).
  for d in "$home"/.*/extensions/anthropic.claude-code-*; do
    if [ ! -d "$d" ]; then continue; fi
    hit=0
    for f in "$d/extension.js" "$d/dist/extension.js"; do
      if [ -f "$f" ] && grep -qsF "$IOC_IP" "$f"; then
        found "backdoored extension file: $f"
        hit=1
      fi
    done
    v="${d##*/anthropic.claude-code-}"
    v="${v%%-*}"
    if [ "$hit" -eq 0 ] && { [ "$v" = "2.1.312" ] || [ "$v" = "2.1.313" ]; }; then
      NOTES="${NOTES}      i extension version ${v} is installed, but its files are clean: ${d}
"
    fi
  done

  # Attacker SSH key (matched by key and by comment).
  for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
    if [ -f "$f" ] && grep -qsF -e "$IOC_KEY" -e "$IOC_KEY_COMMENT" "$f"; then
      found "attacker SSH key in $f"
    fi
  done

  # Startup script, tunnel key and (macOS) fake Apple startup item.
  for f in "$home/.config/.smt" "$home/.config/.smtk" "$home/$IOC_LAUNCH_AGENT"; do
    if [ -e "$f" ]; then
      found "backdoor file: $f"
    fi
  done

  # Linux startup entry in the user's crontab.
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

  report "user ${user}" "$before"
}

check_system() {
  local before="$FOUND" f out hits line
  # Tunnel key in the temporary folder (/tmp/.stk_<hex>, $TMPDIR/.stk_<hex> on macOS).
  for f in /tmp/.stk_* /var/tmp/.stk_* /private/var/folders/*/*/T/.stk_* "${TMPDIR:-/tmp}"/.stk_*; do
    if [ -e "$f" ]; then
      found "backdoor key file: $(real_path "$f")"
    fi
  done

  # Running tunnel (ssh/autossh to the attacker server or with its key) or the
  # shell running the startup script / retry loop. This script's own process
  # and its parents are skipped, so the shell that started it never matches.
  out="$(ps axww -o pid=,user=,command= 2>/dev/null || true)"
  hits="$(printf '%s\n' "$out" | awk -v ip="$IOC_IP" -v skip=" $(own_pids) " '
    {
      if (index(skip, " " $1 " ")) next
      cmd = $0
      sub(/^[ \t]*[0-9]+[ \t]+[^ \t]+[ \t]+/, "", cmd)
      split(cmd, w, " ")
      prog = w[1]
      sub(/.*\//, "", prog)
      if ((prog == "ssh" || prog == "autossh") &&
          (index(cmd, ip) || index(cmd, "/.stk_") || index(cmd, ".config/.smtk"))) { print; next }
      if ((prog == "sh" || prog == "bash" || prog == "dash" || prog == "zsh") &&
          (index(cmd, ".config/.smt") || index(cmd, "tunnel@" ip))) { print; next }
    }' || true)"
  if [ -n "$hits" ]; then
    while IFS= read -r line; do
      found "backdoor program running: $(printf '%s' "$line" | tr -s ' ' | cut -c1-150)"
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
    *"$IOC_IP"*) found "open connection to the attacker server ${IOC_IP}" ;;
  esac

  report "temporary files, running programs and network connections" "$before"
}

ext_check() {
  local user home
  section "1/2  Claude Code extension check"
  step "What it does: looks for the traces left by a backdoored version of the"
  step "Claude Code extension (2.1.312 and 2.1.313, from the Cursor extension store)."
  step "It only looks. Nothing is changed or deleted."
  info ""
  if is_root; then
    step "Checking every user of this computer:"
  else
    step "Checking only your own user (run with sudo to check every user):"
  fi
  while IFS=$'\t' read -r user home; do
    if [ -z "$home" ] || [ "$home" = "/" ] || [ ! -d "$home" ]; then continue; fi
    check_home "$user" "$home"
  done <<EOF
$(list_homes)
EOF
  check_system

  if [ "$FOUND" -eq 0 ]; then
    RESULT1="${C_OK}OK${C_0} - no traces found"
    result "$C_OK" "OK - no traces of the backdoored extension were found."
  else
    RESULT1="${C_BAD}ATTENTION${C_0} - ${FOUND} trace(s) found, contact the Security team"
    result "$C_BAD" "ATTENTION - ${FOUND} trace(s) of the backdoored extension were found."
    step "${C_BAD}Do not delete anything and contact the Security team now.${C_0}"
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

# Ubuntu kernel changelogs list the CVEs each build fixes. Returns 0 if fixed.
KERNEL_FIXED=1
kernel_status() {
  local krel f checked=0
  krel="$(uname -r)"
  KERNEL_FIXED=1
  for f in "/usr/share/doc/linux-modules-${krel}/changelog.Debian.gz" \
    "/usr/share/doc/linux-image-unsigned-${krel}/changelog.Debian.gz" \
    "/usr/share/doc/linux-image-${krel}/changelog.Debian.gz"; do
    [ -r "$f" ] || continue
    checked=1
    if zgrep -qF "$CVE" "$f"; then
      KERNEL_FIXED=0
      step "The running system core (kernel ${krel}) already includes the official fix."
      return 0
    fi
  done
  if [ "$checked" -eq 1 ]; then
    step "The running system core (kernel ${krel}) does not include the official fix yet."
  else
    step "Could not tell whether the running system core (kernel ${krel}) has the fix."
    step "Compare its version with ${ADVISORY}"
  fi
}

ensure_nft() {
  if ! command -v nft >/dev/null 2>&1; then
    step "Installing the firewall tool it needs (nftables)..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get -o DPkg::Lock::Timeout=120 update -qq ||
      warn "apt-get update reported errors; trying to install anyway."
    apt-get -o DPkg::Lock::Timeout=120 install -y -qq --no-install-recommends nftables >/dev/null ||
      die "Could not install nftables. Install it ('sudo apt-get install nftables') and run again."
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
    die "The firewall rejected the rule (kernel without nf_tables support?). Nothing was changed."
  install -m 0644 -o root -g root "$WORKDIR/rule.nft" "$RULE_FILE"
}

persist() {
  local out
  if ! has_systemd; then
    KEPT_AFTER_RESTART=0
    warn "systemd is not running: the protection is on now but will NOT stay on after a restart."
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
    die "Could not enable ${UNIT}. The protection is on now but will not stay on after a restart."
  fi

  # Advisory method, used only where nftables.service already owns the firewall:
  # its reload/restart flushes the whole ruleset, so the rule must be in its config.
  if systemctl is-enabled --quiet nftables.service 2>/dev/null && [ -f "$NFT_CONF" ] && ! include_present; then
    if [ -n "$(tail -c1 "$NFT_CONF")" ]; then printf '\n' >>"$NFT_CONF"; fi
    printf '%s\n' "$INCLUDE_LINE" >>"$NFT_CONF"
    if "$NFT" -c -f "$NFT_CONF" >/dev/null 2>&1; then
      step "nftables.service is enabled: added the rule to ${NFT_CONF} too."
    else
      drop_include
      warn "${NFT_CONF} does not pass 'nft -c'; left it unchanged. 'systemctl reload nftables' would drop the protection until the next restart."
    fi
  fi
}

ubuntu_intro() {
  section "2/2  Ubuntu network protection (${CVE})"
  step "What it does: blocks a rare kind of network traffic used to attack Ubuntu,"
  step "until Ubuntu's official fix is installed. Normal use is not affected."
}

do_apply() {
  info ""
  RESULT2="${C_BAD}FAILED${C_0} - see the error above"
  kernel_status
  if in_container; then
    warn "This is a container: this only protects the container itself. Run it on the host too."
  fi
  ensure_nft
  step "Turning on the protection..."
  write_rule_file
  "$NFT" -f "$RULE_FILE"
  persist
  [ "$(rule_count)" = "1" ] || die "Verification failed: the protection is not loaded as expected. Run with --status."
  if [ "$KEPT_AFTER_RESTART" -eq 1 ]; then
    RESULT2="${C_OK}ACTIVE${C_0} - stays on after a restart"
    result "$C_OK" "ACTIVE - the protection is on and stays on after a restart."
  else
    RESULT2="${C_WARN}ACTIVE until the next restart${C_0} - run it again after restarting"
    result "$C_WARN" "ACTIVE until the next restart - run it again after restarting."
  fi
  step "When Ubuntu releases the official fix: install the system updates, restart,"
  step "then run this command again with --remove at the end."
}

show_status() {
  local active=1
  info ""
  kernel_status
  NFT="$(command -v nft || true)"
  if table_loaded && [ "$(rule_count)" -ge 1 ]; then
    active=0
    if has_systemd && systemctl is-enabled --quiet "$UNIT" 2>/dev/null; then
      RESULT2="${C_OK}ACTIVE${C_0} - stays on after a restart"
      result "$C_OK" "ACTIVE - the protection is on and stays on after a restart."
    else
      RESULT2="${C_WARN}ACTIVE until the next restart${C_0}"
      result "$C_WARN" "ACTIVE until the next restart - run the command without --status to keep it on."
    fi
  else
    RESULT2="${C_WARN}NOT ACTIVE${C_0} - run the command without --status to turn it on"
    result "$C_WARN" "NOT ACTIVE - run the same command without --status to turn it on."
  fi
  return "$active"
}

do_remove() {
  info ""
  RESULT2="${C_BAD}FAILED${C_0} - see the error above"
  if [ -f "$UNIT_FILE" ]; then
    if has_systemd; then systemctl disable --now "$UNIT" >/dev/null 2>&1 || true; fi
    rm -f "$UNIT_FILE"
    if has_systemd; then systemctl daemon-reload; fi
  fi
  drop_include
  NFT="$(command -v nft || true)"
  if table_loaded; then "$NFT" delete table inet "$TABLE"; fi
  rm -f "$RULE_FILE"
  kernel_status
  RESULT2="REMOVED - the protection is off"
  result "" "REMOVED - the protection is off."
  if [ "$KERNEL_FIXED" -ne 0 ]; then
    warn "The official fix does not seem to be installed yet: this computer is not protected."
    warn "Run the command again without --remove to turn the protection back on."
  fi
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

  info ""
  info "${C_B}UME device tools ${VERSION}${C_0} on ${OS_NAME}"
  info "This script does two separate things, each with its own result:"
  info "  1. Claude Code extension check - looks for traces of a backdoored extension (changes nothing)"
  info "  2. Ubuntu network protection  - turns on a temporary protection (Ubuntu only)"
  case "$mode" in
    status) info "Mode: --status (only checks, changes nothing)" ;;
    remove) info "Mode: --remove (turns off item 2 only)" ;;
  esac
  SUMMARY=1

  if [ "$mode" = "remove" ]; then
    RESULT1="not run (--remove only turns off item 2)"
  else
    ext_check
  fi

  ubuntu_intro
  if [ "$OS_KIND" != "ubuntu" ]; then
    RESULT2="NOT NEEDED - this computer does not run Ubuntu"
    result "" "NOT NEEDED - this computer does not run Ubuntu."
  else
    case "$mode" in
      apply) do_apply ;;
      status) show_status || rc=1 ;;
      remove) do_remove ;;
    esac
  fi

  print_summary
  if [ "$FOUND" -gt 0 ]; then exit 3; fi
  exit "$rc"
}

# Everything above only defines functions: a truncated download runs nothing.
main "$@"
