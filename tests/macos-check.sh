#!/bin/bash
# Test of the Claude Code extension check on macOS, with the bash 3.2 that ships
# with macOS. Runs as the current user (no sudo) against fake home and temp
# folders, so it never reads or changes the real ones.
#   usage: tests/macos-check.sh
# shellcheck disable=SC2015  # "a && ok || fail" is the intended test idiom
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
S="${ROOT}/device-tools.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
ok() { printf '  ok   %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*"; exit 1; }
[ "$(uname -s)" = Darwin ] || { echo "macOS only"; exit 1; }

echo "=== macOS: clean home"
mkdir -p "$T/clean" "$T/clean-tmp"
rc=0; OUT="$(HOME="$T/clean" TMPDIR="$T/clean-tmp/" /bin/bash "$S" --status 2>&1)" || rc=$?
[ "$rc" = 0 ] && ok "exit 0" || { echo "$OUT"; fail "rc=$rc"; }
grep -q 'no traces of the backdoored version' <<<"$OUT" && ok "no traces reported" || fail "clean output"
grep -q 'not needed on this system' <<<"$OUT" && ok "Ubuntu protection skipped" || fail "ubuntu skip"

echo "=== macOS: published traces planted"
H="$T/home"
mkdir -p "$H/.ssh" "$H/.config" "$H/Library/LaunchAgents" "$T/tmp" \
  "$H/.cursor/extensions/anthropic.claude-code-2.1.313-darwin-arm64"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P svc-telemetry" >"$H/.ssh/authorized_keys"
echo 'ssh -N tunnel@134.209.82.225' >"$H/.config/.smt"
echo 'key' >"$H/.config/.smtk"
echo '<plist><dict><key>Label</key><string>com.apple.sysmond</string></dict></plist>' >"$H/Library/LaunchAgents/com.apple.sysmond.plist"
echo 'var h="134.209.82.225";' >"$H/.cursor/extensions/anthropic.claude-code-2.1.313-darwin-arm64/extension.js"
echo 'key' >"$T/tmp/.stk_0123456789"
rc=0; OUT="$(HOME="$H" TMPDIR="$T/tmp/" /bin/bash "$S" --status 2>&1)" || rc=$?
[ "$rc" = 3 ] && ok "exit 3" || { echo "$OUT"; fail "rc=$rc"; }
grep -q '6 trace(s)' <<<"$OUT" && ok "all 6 traces reported (key, .smt, .smtk, LaunchAgent, extension.js, .stk_)" || { echo "$OUT"; fail "trace count"; }
[ -f "$H/Library/LaunchAgents/com.apple.sysmond.plist" ] && [ -f "$T/tmp/.stk_0123456789" ] && ok "read-only: traces left untouched" || fail "changed files"
rc=0; HOME="$H" TMPDIR="$T/tmp/" /bin/bash "$S" --remove >/dev/null 2>&1 || rc=$?
[ "$rc" = 0 ] && ok "--remove on macOS: nothing to do, exit 0" || fail "--remove rc=$rc"
echo "=== All macOS tests passed"
