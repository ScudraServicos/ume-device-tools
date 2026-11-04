#!/usr/bin/env bash
# End-to-end test of cve-2026-98432-mitigate.sh in disposable Ubuntu containers.
#   usage: tests/ubuntu-e2e.sh [image]      (default ubuntu:24.04)
# Phase 1: plain container (no systemd). Installs nftables through the script,
#          proves real TCP connections with IP options are dropped, re-apply is
#          idempotent, --status / --remove work, non-root and non-Ubuntu refuse.
# Phase 2: container booted with systemd. Restarting the container is a reboot
#          (fresh network namespace): the rule must come back, with and without
#          nftables.service, and must be gone after --remove.
# shellcheck disable=SC2015  # "a && ok || fail" is the intended test idiom
set -euo pipefail
IMAGE="${1:-ubuntu:24.04}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="cve-2026-98432-mitigate.sh"

echo "=== Phase 1: ${IMAGE} (no systemd)"
docker run --rm -i --cap-add NET_ADMIN -v "${ROOT}:/src:ro" "${IMAGE}" bash -s <<'IN_CONTAINER'
# shellcheck disable=SC2015  # "a && ok || fail" is the intended test idiom
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq python3 >/dev/null
S=/src/cve-2026-98432-mitigate.sh
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
bash $S --status >/dev/null 2>&1 && fail "--status says active before apply" || ok "--status exit 1 before apply"

bash $S >/tmp/apply.log 2>&1 || { cat /tmp/apply.log; fail "apply"; }
ok "apply (installed nftables: $(nft --version))"
[ "$(probe plain)" = connected ] && ok "after: TCP without IP options connects" || fail "plain TCP broken"
[ "$(probe opts)" = blocked ] && ok "after: TCP with IP options blocked" || fail "options not blocked"
nft list table inet cve_2026_98432 | grep -q 'counter packets [1-9]' && ok "drop counter > 0" || fail "counter"

bash $S >/dev/null 2>&1 && bash $S >/dev/null 2>&1
[ "$(nft list table inet cve_2026_98432 | grep -c hdrlength)" = 1 ] && ok "re-apply x2: still one rule" || fail "duplicate rules"
bash $S --status >/dev/null 2>&1 && ok "--status exit 0 when active" || fail "--status"

bash $S --remove >/dev/null 2>&1 || fail "--remove"
nft list table inet cve_2026_98432 >/dev/null 2>&1 && fail "table still loaded" || ok "remove: table gone"
[ ! -e /etc/cve-2026-98432.nft ] && ok "remove: rule file gone" || fail "rule file left"
[ "$(probe opts)" = connected ] && ok "remove: TCP with IP options connects again" || fail "still blocked"
IN_CONTAINER

echo "=== Phase 1b: non-Ubuntu refuses"
OUT="$(docker run --rm -v "${ROOT}:/src:ro" debian:12 bash "/src/${SCRIPT}" 2>&1 || true)"
if grep -q 'supports Ubuntu only' <<<"${OUT}"; then
  echo "  ok   debian:12 refused"
else
  echo "  FAIL debian:12 not refused"; exit 1
fi

echo "=== Phase 2: ${IMAGE} booted with systemd"
TAG="cve-2026-98432-e2e-systemd:${IMAGE//[:\/]/-}"
NAME="cve-2026-98432-e2e-$$"
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
