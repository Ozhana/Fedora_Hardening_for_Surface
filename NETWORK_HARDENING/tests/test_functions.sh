#!/usr/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
SCRIPT="$HERE/../aegis-network.sh"
source "$SCRIPT"

T=$(mktemp -d "${TMPDIR:-/tmp}/aegis-network-functions.XXXXXXXX")
trap 'rm -rf -- "$T"' EXIT

write_public_zone "$T/public.xml"
write_lan_zone "$T/lan.xml"
write_sysctl_policy "$T/network.conf"
write_nm_policy "$T/nm.conf"

python3 - "$T/public.xml" "$T/lan.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET
public = ET.parse(sys.argv[1]).getroot()
lan = ET.parse(sys.argv[2]).getroot()
assert public.tag == 'zone' and lan.tag == 'zone'
assert 'target' not in public.attrib and 'target' not in lan.attrib
assert public.find('forward') is None and lan.find('forward') is None
assert {x.attrib['name'] for x in public.findall('service')} == {'dhcpv6-client'}
assert {x.attrib['name'] for x in lan.findall('service')} == {
    'dhcpv6-client', 'mdns', 'ipp-client', 'ws-discovery-client'
}
for root in (public, lan):
    assert not root.findall('port')
    assert not root.findall('icmp-block')
PY

grep -Fqx 'connection.llmnr=0' "$T/nm.conf"
grep -Fqx 'connection.mdns=0' "$T/nm.conf"
! grep -Eq 'ip_forward|forwarding|tcp_congestion_control|default_qdisc|tcp_mtu_probing|accept_ra|src_valid_mark' "$T/network.conf"
for line in \
  'net.ipv4.conf.*.accept_redirects = 0' \
  'net.ipv4.conf.*.secure_redirects = 0' \
  'net.ipv4.conf.*.send_redirects = 0' \
  'net.ipv4.conf.*.accept_source_route = 0' \
  'net.ipv6.conf.*.accept_redirects = 0' \
  'net.ipv6.conf.*.accept_source_route = -1'
do
  grep -Fqx -- "$line" "$T/network.conf"
done

cat > "$T/firewalld-workstation.conf" <<'EOF'
# firewalld config file
DefaultZone=FedoraWorkstation
IPv6_rpfilter=loose
IndividualCalls=no
LogDenied=off
FirewallBackend=nftables
StrictForwardPorts=no
NftablesCounters=no
NftablesTableOwner=yes
EOF
FIREWALL_CONF="$T/firewalld.conf"
FWDIR="$T"
rewrite_firewalld_conf "$T/firewalld-workstation.conf" "$T/first.conf"
rewrite_firewalld_conf "$T/first.conf" "$T/second.conf"
cmp -s "$T/first.conf" "$T/second.conf"
grep -Fqx 'DefaultZone=aegis-public' "$T/first.conf"
grep -Fqx 'StrictForwardPorts=yes' "$T/first.conf"
grep -Fqx 'NftablesTableOwner=yes' "$T/first.conf"
grep -Fqx 'LogDenied=off' "$T/first.conf"
! grep -q '^Lockdown=' "$T/first.conf"

# Local direct/policy extensions are explicit blockers.
validate_local_firewalld_extensions
printf '<direct/>\n' > "$T/direct.xml"
set +e
( validate_local_firewalld_extensions ) >/dev/null 2>&1
rc=$?
set -e
[[ $rc == 2 ]]
rm -f "$T/direct.xml"
mkdir -p "$T/policies"
printf '<policy/>\n' > "$T/policies/foreign.xml"
set +e
( validate_local_firewalld_extensions ) >/dev/null 2>&1
rc=$?
set -e
[[ $rc == 2 ]]
rm -rf "$T/policies"

wordset_equals 'mdns ipp-client dhcpv6-client ws-discovery-client' 'dhcpv6-client ipp-client mdns ws-discovery-client'
! wordset_equals 'mdns ipp-client' 'mdns ipp-client dhcpv6-client'
[[ $(normalize_nm_enum '-1 (default)') == default ]]
[[ $(normalize_nm_enum '1 (resolve)') == resolve ]]
[[ $(normalize_nm_zone --) == '' ]]

# Current service semantics: exact ports/destinations/source-port, no broad substitutions.
mkdir -p "$T/bin"
cat > "$T/bin/firewall-cmd" <<'EOF'
#!/bin/sh
case "$*" in
  --get-services) echo 'dhcpv6-client mdns ipp-client ws-discovery-client';;
  *'--service=dhcpv6-client --get-ports') echo '546/udp';;
  *'--service=dhcpv6-client --get-source-ports') echo '';;
  *'--service=dhcpv6-client --get-destinations') echo 'ipv6:fe80::/64';;
  *'--service=dhcpv6-client --get-protocols') echo '';;
  *'--service=mdns --get-ports') echo '5353/udp';;
  *'--service=mdns --get-source-ports') echo '';;
  *'--service=mdns --get-destinations') echo 'ipv4:224.0.0.251 ipv6:ff02::fb';;
  *'--service=mdns --get-protocols') echo '';;
  *'--service=ipp-client --get-ports') echo '631/udp';;
  *'--service=ipp-client --get-source-ports'|*'--service=ipp-client --get-destinations'|*'--service=ipp-client --get-protocols') echo '';;
  *'--service=ws-discovery-client --get-ports'|*'--service=ws-discovery-client --get-destinations'|*'--service=ws-discovery-client --get-protocols') echo '';;
  *'--service=ws-discovery-client --get-source-ports') echo '3702/udp';;
  *) exit 8;;
esac
EOF
chmod 0755 "$T/bin/firewall-cmd"
OLD_PATH=$PATH
PATH="$T/bin:/usr/bin:/bin"
require_firewalld_services
# Tamper must be blocked.
sed -i 's/5353\/udp/5354\/udp/' "$T/bin/firewall-cmd"
set +e
( require_firewalld_services ) >/dev/null 2>&1
rc=$?
set -e
[[ $rc == 2 ]]
PATH=$OLD_PATH

# Local recovery-session gate: one active non-remote Wayland session passes; remote-only fails.
printf '1000\n' > "$T/loginuid"
LOGINUID_PATH="$T/loginuid"
cat > "$T/bin/loginctl" <<'EOF'
#!/bin/sh
case "$*" in
  'list-sessions --no-legend') echo '7 1000 testuser seat0 tty2';;
  'show-session 7 -p Active --value') echo yes;;
  'show-session 7 -p Remote --value') echo no;;
  'show-session 7 -p Type --value') echo wayland;;
  'show-session 7 -p Class --value') echo user;;
  *) exit 1;;
esac
EOF
chmod 0755 "$T/bin/loginctl"
PATH="$T/bin:/usr/bin:/bin"
require_local_recovery_session
sed -i 's/echo no/echo yes/' "$T/bin/loginctl"
set +e
( require_local_recovery_session ) >/dev/null 2>&1
rc=$?
set -e
[[ $rc == 2 ]]
PATH=$OLD_PATH

# Protected snapshot/restore including a changed vendor symlink target.
if (( EUID == 0 )); then
    R=$(mktemp -d /root/aegis-network-restore.XXXXXXXX)
    trap 'rm -rf -- "$T" "$R"' EXIT
    chmod 0755 "$R"
    mkdir -p "$R/etc/firewalld" "$R/tx/before"
    chmod 0755 "$R/etc" "$R/etc/firewalld"
    chmod 0700 "$R/tx" "$R/tx/before"
    ANCHOR="$R"; TX_DIR="$R/tx"
    printf 'vendor-before\n' > "$R/etc/firewalld/firewalld-workstation.conf"
    chmod 0644 "$R/etc/firewalld/firewalld-workstation.conf"
    ln -s firewalld-workstation.conf "$R/etc/firewalld/firewalld.conf"
    snapshot_path "$R/etc/firewalld/firewalld.conf" firewalld-conf
    printf 'vendor-after\n' > "$R/etc/firewalld/firewalld-workstation.conf"
    rm "$R/etc/firewalld/firewalld.conf"
    printf 'managed\n' > "$R/etc/firewalld/firewalld.conf"
    restore_path "$R/etc/firewalld/firewalld.conf" firewalld-conf
    [[ -f $R/etc/firewalld/firewalld.conf && ! -L $R/etc/firewalld/firewalld.conf ]]
    grep -Fqx 'vendor-before' "$R/etc/firewalld/firewalld.conf"
fi

echo FUNCTION_TESTS_PASS
