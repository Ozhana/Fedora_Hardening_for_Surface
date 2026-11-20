#!/usr/bin/bash
set -Eeuo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
SCRIPT="$HERE/../aegis-network.sh"
T=$(mktemp -d /root/aegis-apply-sim.XXXXXXXX)
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/etc/firewalld/zones" "$T/etc/sysctl.d" "$T/etc/NetworkManager/conf.d" "$T/state" "$T/run"
chmod 0755 "$T" "$T/etc" "$T/etc/firewalld" "$T/etc/firewalld/zones" "$T/etc/sysctl.d" "$T/etc/NetworkManager" "$T/etc/NetworkManager/conf.d"
chmod 0700 "$T/state"
printf '# vendor\nDefaultZone=FedoraWorkstation\nFirewallBackend=nftables\n' > "$T/etc/firewalld/firewalld-workstation.conf"
chmod 0644 "$T/etc/firewalld/firewalld-workstation.conf"
ln -s firewalld-workstation.conf "$T/etc/firewalld/firewalld.conf"
printf 'FedoraWorkstation\n' > "$T/fw-default"
printf '0\n' > "$T/fw-loaded"
printf '\n' > "$T/profile-zone"
printf 'default\n' > "$T/profile-llmnr"
printf 'default\n' > "$T/profile-mdns"
: > "$T/sysctl.db"

cat > "$T/bin/firewall-cmd" <<'EOF'
#!/bin/sh
set -eu
T=${MOCK_ROOT:?}
case "$*" in
 --get-services) echo 'dhcpv6-client mdns ipp-client ws-discovery-client';;
 *"--service=dhcpv6-client --get-ports") echo '546/udp';;
 *"--service=dhcpv6-client --get-source-ports") echo '';;
 *"--service=dhcpv6-client --get-destinations") echo 'ipv6:fe80::/64';;
 *"--service=dhcpv6-client --get-protocols") echo '';;
 *"--service=mdns --get-ports") echo '5353/udp';;
 *"--service=mdns --get-source-ports") echo '';;
 *"--service=mdns --get-destinations") echo 'ipv4:224.0.0.251 ipv6:ff02::fb';;
 *"--service=mdns --get-protocols") echo '';;
 *"--service=ipp-client --get-ports") echo '631/udp';;
 *"--service=ipp-client --get-source-ports"|*"--service=ipp-client --get-destinations"|*"--service=ipp-client --get-protocols") echo '';;
 *"--service=ws-discovery-client --get-ports"|*"--service=ws-discovery-client --get-destinations"|*"--service=ws-discovery-client --get-protocols") echo '';;
 *"--service=ws-discovery-client --get-source-ports") echo '3702/udp';;
 --get-default-zone) cat "$T/fw-default";;
 --get-zones) if [ "$(cat "$T/fw-loaded")" = 1 ]; then echo 'aegis-public aegis-lan FedoraWorkstation'; else echo 'FedoraWorkstation'; fi;;
 *"--permanent --zone=aegis-public --get-target"|*"--permanent --zone=aegis-lan --get-target") echo 'default';;
 *"--zone=aegis-public --list-all") if [ -e "$T/runtime-target-bad" ]; then printf 'aegis-public\n  target: DROP\n  services: dhcpv6-client\n'; else printf 'aegis-public\n  target: default\n  services: dhcpv6-client\n'; fi;;
 *"--zone=aegis-lan --list-all") if [ -e "$T/runtime-target-bad" ]; then printf 'aegis-lan\n  target: DROP\n  services: dhcpv6-client ipp-client mdns ws-discovery-client\n'; else printf 'aegis-lan\n  target: default\n  services: dhcpv6-client ipp-client mdns ws-discovery-client\n'; fi;;
 *"--zone=aegis-public --list-ports"|*"--zone=aegis-lan --list-ports") if [ -e "$T/runtime-drift" ]; then echo '9999/tcp'; else echo ''; fi;;
 *"--zone=aegis-public --list-source-ports"|*"--zone=aegis-lan --list-source-ports"|*"--zone=aegis-public --list-protocols"|*"--zone=aegis-lan --list-protocols"|*"--zone=aegis-public --list-forward-ports"|*"--zone=aegis-lan --list-forward-ports"|*"--zone=aegis-public --list-rich-rules"|*"--zone=aegis-lan --list-rich-rules"|*"--zone=aegis-public --list-sources"|*"--zone=aegis-lan --list-sources"|*"--zone=aegis-public --list-icmp-blocks"|*"--zone=aegis-lan --list-icmp-blocks") echo '';;
 *"--zone=aegis-public --query-masquerade"|*"--zone=aegis-lan --query-masquerade"|*"--zone=aegis-public --query-icmp-block-inversion"|*"--zone=aegis-lan --query-icmp-block-inversion") exit 1;;
 *"--zone=aegis-public --list-services") echo 'dhcpv6-client';;
 *"--zone=aegis-lan --list-services") echo 'mdns ws-discovery-client dhcpv6-client ipp-client';;
 *"--query-forward") exit 1;;
 *"--get-zone-of-interface=wlan0") z=$(cat "$T/profile-zone"); [ -n "$z" ] && echo "$z" || cat "$T/fw-default";;
 --check-config) exit 0;;
 --reload)
   z=$(awk -F= '$1=="DefaultZone"{print $2}' "$T/etc/firewalld/firewalld.conf")
   printf '%s\n' "$z" > "$T/fw-default"
   if [ -f "$T/etc/firewalld/zones/aegis-public.xml" ] && [ -f "$T/etc/firewalld/zones/aegis-lan.xml" ]; then echo 1 > "$T/fw-loaded"; else echo 0 > "$T/fw-loaded"; fi
   ;;
 --state) echo running;;
 *) echo "unexpected firewall-cmd: $*" >&2; exit 8;;
esac
EOF

cat > "$T/bin/firewall-offline-cmd" <<'EOF'
#!/bin/sh
case "${1-}" in
 --check-config) exit 0;;
 *) echo "unexpected firewall-offline-cmd: $*" >&2; exit 8;;
esac
EOF

cat > "$T/bin/nmcli" <<'EOF'
#!/bin/sh
set -eu
T=${MOCK_ROOT:?}
case "$*" in
 *"-f UUID,TYPE,DEVICE connection show --active"*) echo '11111111-1111-4111-8111-111111111111:802-11-wireless:wlan0';;
 *"-f UUID,TYPE connection show"*) echo '11111111-1111-4111-8111-111111111111:802-11-wireless';;
 *"-g connection.zone connection show uuid"*) [ ! -e "$T/nm-prop-fail" ] || exit 9; cat "$T/profile-zone";;
 *"-g connection.llmnr connection show uuid"*) [ ! -e "$T/nm-prop-fail" ] || exit 9; cat "$T/profile-llmnr";;
 *"-g connection.mdns connection show uuid"*) [ ! -e "$T/nm-prop-fail" ] || exit 9; cat "$T/profile-mdns";;
 *"connection modify uuid"*)
   shift 4
   while [ "$#" -ge 2 ]; do
     case "$1" in
      connection.zone) printf '%s\n' "$2" > "$T/profile-zone";;
      connection.llmnr) printf '%s\n' "$2" > "$T/profile-llmnr";;
      connection.mdns) printf '%s\n' "$2" > "$T/profile-mdns";;
      *) echo "unexpected property $1" >&2; exit 8;;
     esac
     shift 2
   done
   ;;
 *"general reload conf") :;;
 *"device reapply wlan0") :;;
 *"-t -f UUID connection show --active") echo '11111111-1111-4111-8111-111111111111';;
 *"-f UUID,DEVICE connection show --active") echo '11111111-1111-4111-8111-111111111111:wlan0';;
 *"-t -f DEVICE,STATE device status") echo 'wlan0:connected';;
 *) echo "unexpected nmcli: $*" >&2; exit 8;;
esac
EOF

cat > "$T/bin/sysctl" <<'EOF'
#!/bin/sh
set -eu
T=${MOCK_ROOT:?}; db="$T/sysctl.db"
getval() {
  k=$1
  v=$(awk -F '\t' -v k="$k" '$1==k{v=$2} END{print v}' "$db")
  if [ -n "$v" ]; then echo "$v"; return; fi
  case "$k" in
    *accept_source_route) case "$k" in net/ipv6/*|net.ipv6.*) echo 0;; *) echo 0;; esac;;
    *rp_filter) echo 2;;
    *accept_redirects|*secure_redirects|*send_redirects) echo 1;;
    *icmp_echo_ignore_broadcasts|*icmp_ignore_bogus_error_responses|*tcp_syncookies) echo 1;;
    *) echo 0;;
  esac
}
setval() {
  k=$1; v=$2; tmp="$db.tmp"
  awk -F '\t' -v k="$k" '$1!=k' "$db" > "$tmp" || true
  printf '%s\t%s\n' "$k" "$v" >> "$tmp"; mv "$tmp" "$db"
}
case "${1-}" in
 -n) [ "$2" = -- ]; getval "$3";;
 --load=*)
   f=${1#--load=}
   while IFS='=' read -r k v; do
     k=$(printf '%s' "$k" | sed 's/[[:space:]]*$//'); v=$(printf '%s' "$v" | sed 's/^[[:space:]]*//')
     case "$k" in ''|'#'*) continue;; esac
     setval "$k" "$v"
   done < "$f"
   ;;
 -q)
   shift
   [ "$1" = -w ]; shift
   for kv in "$@"; do k=${kv%%=*}; v=${kv#*=}; setval "$k" "$v"; done
   ;;
 -w)
   shift
   for kv in "$@"; do k=${kv%%=*}; v=${kv#*=}; setval "$k" "$v"; done
   ;;
 *) echo "unexpected sysctl: $*" >&2; exit 8;;
esac
EOF

cat > "$T/bin/nft" <<'EOF'
#!/bin/sh
T=${MOCK_ROOT:?}
case "$*" in
 'list table inet firewalld') exit 0;;
 'list chain inet firewalld filter_FORWARD')
   if [ "$(cat "$T/fw-loaded")" = 1 ]; then echo 'chain filter_FORWARD { ct status dnat jump filter_FORWARD_dnat; }'; else echo 'chain filter_FORWARD { ct status dnat accept; }'; fi;;
 *) echo "unexpected nft: $*" >&2; exit 8;;
esac
EOF
cat > "$T/bin/systemctl" <<'EOF'
#!/bin/sh
set -eu
T=${MOCK_ROOT:?}
case "$*" in
 'is-active --quiet firewalld.service') [ ! -e "$T/fw-inactive" ];;
 'is-active --quiet NetworkManager.service') exit 0;;
 'is-active --quiet nftables.service'|'is-active --quiet aegis-firewall-lockdown.service'|'is-active --quiet docker.service'|'is-active --quiet docker.socket') exit 1;;
 'is-enabled --quiet aegis-firewall-lockdown.service') exit 1;;
 'restart firewalld.service'|'start firewalld.service')
   rm -f "$T/fw-inactive"
   z=$(awk -F= '$1=="DefaultZone"{print $2}' "$T/etc/firewalld/firewalld.conf")
   printf '%s
' "$z" > "$T/fw-default"
   if [ -f "$T/etc/firewalld/zones/aegis-public.xml" ] && [ -f "$T/etc/firewalld/zones/aegis-lan.xml" ]; then echo 1 > "$T/fw-loaded"; else echo 0 > "$T/fw-loaded"; fi
   ;;
 *) exit 0;;
esac
EOF
cat > "$T/bin/ip" <<'EOF'
#!/bin/sh
case "$*" in
 '-4 route show default'|'route show default') echo 'default via 192.0.2.1 dev wlan0';;
 '-6 route show default') exit 0;;
 *) exit 0;;
esac
EOF
cat > "$T/bin/restorecon" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$T/bin/"*

MOCK_ROOT="$T" TEST_BIN="$T/bin" SCRIPT="$SCRIPT" /usr/bin/bash -p -c '
  source "$SCRIPT"
  PATH="$TEST_BIN:/usr/bin:/bin"; export MOCK_ROOT
  ANCHOR="$MOCK_ROOT"; INSTALL_PATH="$SCRIPT"; SELF_PATH="$SCRIPT"
  FWDIR="$MOCK_ROOT/etc/firewalld"; FIREWALL_CONF="$FWDIR/firewalld.conf"
  PUBLIC_ZONE_FILE="$FWDIR/zones/aegis-public.xml"; LAN_ZONE_FILE="$FWDIR/zones/aegis-lan.xml"
  SYSCTL_FILE="$MOCK_ROOT/etc/sysctl.d/91-aegis-network-hardening.conf"
  NM_CONF_FILE="$MOCK_ROOT/etc/NetworkManager/conf.d/90-aegis-network-hardening.conf"
  STATE_ROOT="$MOCK_ROOT/state"; TX_ROOT="$STATE_ROOT/transactions"; MANAGED_ROOT="$STATE_ROOT/managed"; LOCK_FILE="$MOCK_ROOT/run/lock"
  require_platform(){ :; }; require_local_recovery_session(){ :; }; require_installed_runtime(){ :; }; confirm_apply(){ :; }; schedule_guard(){ GUARD_UNIT=mock-guard; }; cancel_guard(){ :; }
  touch "$MOCK_ROOT/nm-prop-fail"
  set +e
  ( select_profile ) >/dev/null 2>&1
  nm_fail_rc=$?
  set -e
  rm -f "$MOCK_ROOT/nm-prop-fail"
  [[ $nm_fail_rc == 2 ]]
  apply_hardening
  [[ -f "$FIREWALL_CONF" && ! -L "$FIREWALL_CONF" ]]
  [[ $(cat "$MOCK_ROOT/fw-default") == aegis-public ]]
  [[ $(cat "$MOCK_ROOT/profile-zone") == aegis-lan ]]
  [[ $(cat "$MOCK_ROOT/profile-llmnr") == no ]]
  [[ $(cat "$MOCK_ROOT/profile-mdns") == resolve ]]
  [[ $(<"$TX_DIR/status") == COMMITTED ]]
  [[ -f "$MANAGED_ROOT/profile.uuid" && -f "$MANAGED_ROOT/profile.device" && -f "$MANAGED_ROOT/latest-transaction" ]]
  tx=$TX_DIR
  emergency_restore "$tx" systemd-guard 0
  [[ $(<"$tx/status") == COMMITTED ]]
  before_count=$(find "$TX_ROOT" -mindepth 1 -maxdepth 1 -type d -name T-\* | wc -l)
  apply_hardening
  after_count=$(find "$TX_ROOT" -mindepth 1 -maxdepth 1 -type d -name T-\* | wc -l)
  [[ $before_count == "$after_count" ]]
  [[ $(<"$tx/status") == COMMITTED ]]
  touch "$MOCK_ROOT/runtime-drift"
  set +e
  verify_hardening >/dev/null 2>&1
  runtime_rc=$?
  set -e
  [[ $runtime_rc == 3 ]]
  rm -f "$MOCK_ROOT/runtime-drift"
  printf "\n# post-commit drift\n" >> "$LAN_ZONE_FILE"
  set +e
  emergency_restore "$tx" manual 1
  conflict_rc=$?
  set -e
  [[ $conflict_rc == 1 && $(<"$tx/status") == COMMITTED ]]
  cp -- "$PLAN_DIR/aegis-lan.xml" "$LAN_ZONE_FILE"
  chmod 0644 "$LAN_ZONE_FILE"
  touch "$MOCK_ROOT/fw-inactive"
  ROLLBACK_IN_PROGRESS=1
  emergency_restore "$tx" manual 1
  [[ ! -e "$MOCK_ROOT/fw-inactive" ]]
  [[ -L "$FIREWALL_CONF" && $(readlink "$FIREWALL_CONF") == firewalld-workstation.conf ]]
  [[ $(cat "$MOCK_ROOT/fw-default") == FedoraWorkstation ]]
  [[ -z $(cat "$MOCK_ROOT/profile-zone") ]]
  [[ $(cat "$MOCK_ROOT/profile-llmnr") == default ]]
  [[ $(cat "$MOCK_ROOT/profile-mdns") == default ]]
  [[ ! -e "$MANAGED_ROOT/profile.uuid" && ! -e "$MANAGED_ROOT/profile.device" && ! -e "$MANAGED_ROOT/latest-transaction" ]]
  [[ $(<"$tx/status") == ROLLED_BACK ]]

  # A verify failure before COMMIT must not publish managed identity. Simulate
  # the exact class of rc2 bug: runtime target observation disagrees.
  touch "$MOCK_ROOT/runtime-target-bad"
  set +e
  apply_hardening >/dev/null 2>&1
  failed_apply_rc=$?
  set -e
  [[ $failed_apply_rc == 3 ]]
  [[ ! -e "$MANAGED_ROOT/profile.uuid" && ! -e "$MANAGED_ROOT/profile.device" && ! -e "$MANAGED_ROOT/latest-transaction" ]]
  failed_tx=$TX_DIR
  ROLLBACK_IN_PROGRESS=1
  emergency_restore "$failed_tx" local-exit-handler 0
  ROLLBACK_IN_PROGRESS=0
  rm -f "$MOCK_ROOT/runtime-target-bad"
  [[ $(<"$failed_tx/status") == ROLLED_BACK ]]
  [[ ! -e "$MANAGED_ROOT/profile.uuid" && ! -e "$MANAGED_ROOT/profile.device" && ! -e "$MANAGED_ROOT/latest-transaction" ]]

  echo APPLY_VERIFY_ROLLBACK_SIM_PASS
'
