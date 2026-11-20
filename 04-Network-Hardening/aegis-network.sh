#!/usr/bin/bash -p
# AEGIS Network Hardening 0.7.0-rc4 -- transactional Fedora 44 end-station firewall hardening.
# One runtime script: audit, deterministic plan, apply, verify, rollback, status and private export.
# Native stack: firewalld+nftables and NetworkManager; no iptables/direct rules, persistent daemon or Python.
# Policy: restrictive default zone, printer-capable reviewed LAN zone, strict container-DNAT gate,
# LLMNR reduction, bounded network sysctls, durable snapshots and an independent timed rollback guard.
if (( BASH_VERSINFO[0] < 5 )); then
    printf 'STOP: Bash 5 or newer is required.\n' >&2
    exit 2
fi
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit
umask 077
VERSION='0.7.0-rc4'
INSTALL_DIR='/usr/local/libexec/aegis/network-hardening'
INSTALL_PATH="$INSTALL_DIR/aegis-network.sh"
REPORT_NAME='Network-hardening-audit.txt'
SELF_PATH='' EXPORT_TMP='' PLAN_DIR=''
STATE_ROOT='/var/lib/aegis/network-hardening'
TX_ROOT="$STATE_ROOT/transactions"
MANAGED_ROOT="$STATE_ROOT/managed"
LOCK_FILE='/run/lock/aegis-network-hardening.lock'
FIREWALL_CONF='/etc/firewalld/firewalld.conf'
PUBLIC_ZONE_FILE='/etc/firewalld/zones/aegis-public.xml'
LAN_ZONE_FILE='/etc/firewalld/zones/aegis-lan.xml'
SYSCTL_FILE='/etc/sysctl.d/91-aegis-network-hardening.conf'
NM_CONF_FILE='/etc/NetworkManager/conf.d/90-aegis-network-hardening.conf'
PUBLIC_ZONE='aegis-public' LAN_ZONE='aegis-lan'
PROFILE_UUID='' PROFILE_DEVICE='' PROFILE_OLD_ZONE='' PROFILE_OLD_LLMNR='' PROFILE_OLD_MDNS=''
PROFILE_OPT='' APPROVE='' PLAN_HASH='' PLAN_JSON=''
TX_ACTIVE=0 TX_ID='' TX_DIR='' GUARD_UNIT='' ROLLBACK_IN_PROGRESS=0 LOCK_HELD=0
ROLLBACK_SECONDS=180
LOGINUID_PATH='/proc/self/loginuid'
LIMIT=262144 COMMAND_SECONDS=8 KILL_AFTER=2
AS_KIB=786432 CPU_SECONDS=15 CPU_HARD_SECONDS=17
ROOT_UID=0 ANCHOR='/'
PROBLEMS=0 OBSERVATIONS=0 CAPTURED='' JSON='' OWNER=''
READ_DATA='' READ_RC=0 READ_TRUNCATED=0 READ_BINARY=0
FWOWNER='' NMOWNER='' RESOWNER=''
DEFAULT_ZONE='' LOG_DENIED=''
FWDIR='/etc/firewalld'
FIREWALL_BUS='org.fedoraproject.FirewallD1'
FWPATH='/org/fedoraproject/FirewallD1'
NMBUS='org.freedesktop.NetworkManager'
NMPATH='/org/freedesktop/NetworkManager'
PROP='org.freedesktop.DBus.Properties'
declare -a NAMES=()
say() { printf '%s\n' "$*"; }
die() { printf 'STOP: %s\n' "$*" >&2; exit 2; }
warn() { printf 'OBSERVATION_WARNING: %s\n' "$*"; PROBLEMS=$((PROBLEMS+1)); }
need() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }
section() { printf '\n=== %s ===\n' "$1"; }
emit() { LC_ALL=C sed -n 'l 0' | LC_ALL=C sed 's/^/| /'; }

bounded_cmd() { timeout --signal=TERM --kill-after="${KILL_AFTER}s" "${COMMAND_SECONDS}s" "$@"; }

read_bounded() {
    local maximum=$1 data rc=0; shift
    READ_DATA='' READ_RC=0 READ_TRUNCATED=0 READ_BINARY=0
    [[ $maximum =~ ^[1-9][0-9]{0,8}$ ]] || die 'Invalid byte bound'
    if data=$(
        set +e
        bounded_cmd "$@" 2>&1 | head -c "$((maximum+1))" | tr '\000' '\001'
        pipeline_rc=$?
        printf '.'
        exit "$pipeline_rc"
    ); then :; else rc=$?; fi
    # A killed substitution may not emit the framing sentinel.
    if [[ $data != *. ]]; then READ_RC=2; return 0; fi
    data=${data%.}
    if (( ${#data} > maximum )); then READ_TRUNCATED=1; fi
    if [[ $data == *$'\001'* ]]; then READ_BINARY=1; fi
    READ_RC=$rc
    if (( READ_TRUNCATED || READ_BINARY )); then
        (( READ_RC != 0 )) || READ_RC=3
        return 0
    fi
    READ_DATA=$data
}

# Resource ceilings are per process, not RSS, cgroup memory or a thermal budget.
# No inherited soft/hard limit is raised. CAP_SYS_RESOURCE can still defeat
# hard limits in a privileged caller; the supplied service excludes that cap.
limit_pair() {
    local flag=$1 soft_cap=$2 hard_cap=$3 soft hard new_soft new_hard
    soft=$(ulimit -S -"$flag") || die 'Cannot inspect soft resource limit'
    hard=$(ulimit -H -"$flag") || die 'Cannot inspect hard resource limit'
    [[ $soft == unlimited || $soft =~ ^[0-9]+$ ]] || die 'Invalid soft limit'
    [[ $hard == unlimited || $hard =~ ^[0-9]+$ ]] || die 'Invalid hard limit'
    new_hard=$hard_cap
    if [[ $hard != unlimited ]] && (( hard < new_hard )); then new_hard=$hard; fi
    new_soft=$soft_cap
    if [[ $soft != unlimited ]] && (( soft < new_soft )); then new_soft=$soft; fi
    if (( new_hard < new_soft )); then new_soft=$new_hard; fi
    # Lower soft before hard; lowering hard below the old soft would fail.
    ulimit -S -"$flag" "$new_soft" || die 'Cannot lower soft resource limit'
    ulimit -H -"$flag" "$new_hard" || die 'Cannot lower hard resource limit'
    [[ $(ulimit -S -"$flag") == "$new_soft" && $(ulimit -H -"$flag") == "$new_hard" ]] || die 'Resource limit verification failed'
}
resource_limits() {
    limit_pair v "$AS_KIB" "$AS_KIB"
    # Two CPU seconds of escalation space where inherited limits allow it.
    # SIGXCPU handling is best effort; equal/tighter inherited caps are preserved.
    limit_pair t "$CPU_SECONDS" "$CPU_HARD_SECONDS"
    limit_pair c 0 0
}

check_dir() {
    local p=$1 cur=$ANCHOR part data uid mode
    local -a parts=()
    [[ $p == /* && $p != *$'\n'* && $p != *$'\r'* && $p != *$'\t'* ]] || return 1
    [[ $ANCHOR == / || $p == "$ANCHOR" || $p == "$ANCHOR/"* ]] || return 1
    [[ -d $cur && ! -L $cur ]] || return 1
    read_bounded 128 stat -c '%u %a' -- "$cur"
    (( READ_RC == 0 )) || return 1
    data=$READ_DATA
    IFS=' ' read -r uid mode <<< "$data"
    [[ $uid == "$ROOT_UID" && $mode =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 0022) == 0 )) || return 1
    IFS=/ read -r -a parts <<< "${p#"$ANCHOR"}"
    for part in "${parts[@]}"; do
        [[ -n $part ]] || continue
        [[ $part != . && $part != .. ]] || return 1
        cur=${cur%/}/$part
        [[ -d $cur && ! -L $cur ]] || return 1
        read_bounded 128 stat -c '%u %a' -- "$cur"
        (( READ_RC == 0 )) || return 1
        data=$READ_DATA
        IFS=' ' read -r uid mode <<< "$data"
        [[ $uid == "$ROOT_UID" && $mode =~ ^[0-7]{3,4}$ ]] || return 1
        (( (8#$mode & 0022) == 0 )) || return 1
    done
}

check_file() {
    local data uid mode links size
    check_dir "${1%/*}" || return 1
    [[ -f $1 && ! -L $1 ]] || return 1
    read_bounded 256 stat -c '%u %a %h %s' -- "$1"
    (( READ_RC == 0 )) || return 1
    data=$READ_DATA
    IFS=' ' read -r uid mode links size <<< "$data"
    [[ $uid == "$ROOT_UID" && $links == 1 && $mode =~ ^[0-7]{3,4}$ && $size =~ ^[0-9]+$ ]] || return 1
    (( (8#$mode & 07022) == 0 && size <= LIMIT ))
}

# Fedora Workstation ships /etc/firewalld/firewalld.conf as a package-owned
# relative symlink to firewalld-workstation.conf. General symlink following
# remains forbidden. Only this exact vendor layout is accepted after checking
# the protected parent, link ownership/link-count and the final regular file.
resolve_config_file() {
    local path=$1 data uid links target resolved
    RESOLVED_CONFIG=''
    if check_file "$path"; then
        RESOLVED_CONFIG=$path
        return 0
    fi
    [[ $path == "$FWDIR/firewalld.conf" ]] || return 1
    check_dir "$FWDIR" || return 1
    [[ -L $path ]] || return 1
    read_bounded 128 stat -c '%u %h' -- "$path"
    (( READ_RC == 0 )) || return 1
    data=$READ_DATA
    IFS=' ' read -r uid links <<< "$data"
    [[ $uid == "$ROOT_UID" && $links == 1 ]] || return 1
    read_bounded 256 readlink -n -- "$path"
    (( READ_RC == 0 )) || return 1
    target=$READ_DATA
    [[ $target == firewalld-workstation.conf ]] || return 1
    resolved="$FWDIR/$target"
    check_file "$resolved" || return 1
    RESOLVED_CONFIG=$resolved
    return 0
}

cleanup() {
    local rc=$?
    trap - EXIT ERR INT TERM HUP PIPE XCPU
    if (( TX_ACTIVE == 1 && ROLLBACK_IN_PROGRESS == 0 )); then
        printf 'FAIL-SAFE: incomplete hardening transaction %s; attempting immediate rollback.\n' "$TX_ID" >&2
        ROLLBACK_IN_PROGRESS=1
        if emergency_restore "$TX_DIR" 'local-exit-handler' 0 >&2; then
            cancel_guard
        else
            rc=1
        fi
        TX_ACTIVE=0
    fi
    if [[ -n ${EXPORT_TMP-} && -e $EXPORT_TMP ]]; then
        rm -f -- "$EXPORT_TMP" 2>/dev/null || rc=2
        EXPORT_TMP=''
    fi
    if [[ -n ${PLAN_DIR-} && -d $PLAN_DIR ]]; then
        rm -rf -- "$PLAN_DIR" 2>/dev/null || rc=2
        PLAN_DIR=''
    fi
    if (( rc != 0 && rc != 3 )); then
        printf 'Operation interrupted/failed (exit %d); any report may be incomplete.\n' "$rc" >&2
    fi
    exit "$rc"
}

install_traps() {
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    trap 'exit 141' PIPE
    trap 'exit 152' XCPU
}

# Failed/truncated output is never made available to a parser.
# Report is LOCAL and potentially identifying: IPs, routes, UUIDs, rules remain.
capture() {
    local label=$1; shift
    section "$label"; CAPTURED=''; OBSERVATIONS=$((OBSERVATIONS+1))
    if ! command -v "$1" >/dev/null 2>&1; then warn "Missing tool: $1"; return 0; fi
    read_bounded "$LIMIT" "$@"
    if (( READ_RC != 0 )); then
        warn "Observation failed or exceeded bounds (exit $READ_RC; truncated=$READ_TRUNCATED; binary=$READ_BINARY); content omitted"
        return 0
    fi
    CAPTURED=$READ_DATA
    printf '%s' "$CAPTURED" | emit
}

# A single JSON response, not a stream. A malformed response is not trusted.
accept_json() {
    local input=$1
    JSON=''
    if ! printf '%s' "$input" | jq -e -s 'length == 1 and (.[0] | type == "object")' >/dev/null 2>&1; then
        warn 'Malformed/multiple JSON messages; response omitted'; return 1
    fi
    JSON=$input
}

# Only known read methods are admissible. This is an application guard, not
# confinement of a modified script or a compromised privileged environment.
read_method_allowed() {
    case "$1:$2" in
        org.freedesktop.DBus:GetNameOwner|\
        org.freedesktop.DBus.Properties:Get|\
        org.freedesktop.DBus.Properties:GetAll|\
        org.fedoraproject.FirewallD1:getDefaultZone|\
        org.fedoraproject.FirewallD1:getLogDenied|\
        org.fedoraproject.FirewallD1:queryPanicMode|\
        org.fedoraproject.FirewallD1.zone:getActiveZones|\
        org.fedoraproject.FirewallD1.zone:getZones|\
        org.fedoraproject.FirewallD1.zone:getZoneSettings2|\
        org.fedoraproject.FirewallD1.policy:getPolicies|\
        org.fedoraproject.FirewallD1.policy:getPolicySettings|\
        org.fedoraproject.FirewallD1.config:listZones|\
        org.fedoraproject.FirewallD1.config:listPolicies|\
        org.fedoraproject.FirewallD1.config.zone:getSettings2|\
        org.fedoraproject.FirewallD1.config.policy:getSettings|\
        org.freedesktop.NetworkManager.Settings.Connection:GetSettings) return 0;;
        *) return 1;;
    esac
}

bus_read() {
    local destination=$1 path=$2 interface=$3 method=$4; shift 4
    JSON=''; OBSERVATIONS=$((OBSERVATIONS+1))
    [[ $destination == org.freedesktop.DBus || $destination =~ ^:[0-9]+\.[0-9]+$ ]] || die 'Unpinned bus destination'
    [[ $path =~ ^/[A-Za-z0-9_/]+$ ]] || die 'Unsafe D-Bus object path'
    read_method_allowed "$interface" "$method" || die 'Write/unknown D-Bus method refused'
    if ! command -v busctl >/dev/null 2>&1; then warn 'busctl unavailable'; return 1; fi
    # Both pin to the acquired unique bus name and prohibit auto-activation.
    read_bounded "$LIMIT" busctl --system --no-pager --auto-start=no \
        --allow-interactive-authorization=no --timeout=6s --json=short \
        call "$destination" "$path" "$interface" "$method" "$@"
    if (( READ_RC != 0 )); then
        warn "D-Bus observation unavailable: $interface.$method (exit $READ_RC)"
        return 1
    fi
    accept_json "$READ_DATA"
}

resolve_owner() {
    local name=$1 v
    OWNER=''
    if ! bus_read org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetNameOwner s "$name"; then
        warn "No current owner for $name; NOT started"; return 1
    fi
    if ! v=$(printf '%s' "$JSON" | jq -er 'select(.type=="s" and (.data|length)==1) | .data[0] | select(type=="string")'); then
        warn 'Invalid bus owner response'; return 1
    fi
    [[ $v =~ ^:[0-9]+\.[0-9]+$ ]] || { warn 'Not a unique bus owner'; return 1; }
    OWNER=$v
}

show_json() { printf '%s' "$JSON" | jq . | emit; }
show_bus() {
    local label=$1; shift
    section "$label"
    if bus_read "$@"; then show_json; fi
}

array_response() {
    local signature=$1 kind=$2 maximum=$3 values item
    NAMES=()
    if ! values=$(printf '%s' "$JSON" | jq -er --arg t "$signature" --argjson m "$maximum" '
      if .type==$t and (.data|type)=="array" and (.data|length)==1 and (.data[0]|type)=="array"
         and (.data[0]|length)<=$m and all(.data[0][]; type=="string" and length>0 and (explode | all(.[]; .>=32 and .!=127)))
      then .data[0] | join("\n") else error("invalid/bounded array") end'); then
        warn 'Unexpected or oversized array; entries omitted'; return 1
    fi
    [[ -z $values ]] && return 0
    while IFS= read -r item; do
        case $kind in
            name) [[ $item =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { warn 'Unusual policy/zone name'; NAMES=(); return 1; };;
            path) [[ $item =~ ^/[A-Za-z0-9_/]+$ ]] || { warn 'Invalid object path'; NAMES=(); return 1; };;
            *) die 'Invalid array mode';;
        esac
        NAMES+=("$item")
    done <<< "$values"
}

read_config_file() {
    local path=$1 optional=${2:-no} source
    section "On-disk file: $path (not proof of effective state)"
    if [[ ! -e $path && ! -L $path && $optional == yes ]]; then say 'ABSENT (optional)'; return 0; fi
    if ! resolve_config_file "$path"; then warn 'Unsafe/missing/oversized config file; not read'; return 0; fi
    source=$RESOLVED_CONFIG
    if [[ $source != "$path" ]]; then
        say "ACCEPTED_FEDORA_VENDOR_SYMLINK_LAYOUT: $path -> ${source##*/}"
    fi
    read_bounded "$LIMIT" head -c "$((LIMIT+1))" -- "$source"
    if (( READ_RC != 0 )); then warn 'Config read failed/truncated/binary'; return 0; fi
    # These are selected firewall files, NOT VPN profiles, keyfiles or credentials.
    printf '%s' "$READ_DATA" | emit
}

package_inventory() {
    local pkg
    section 'Packages (one bounded query per package; no installs)'
    if ! command -v rpm >/dev/null 2>&1; then
        warn 'Missing tool: rpm; package versions unavailable'
        return 0
    fi
    for pkg in firewalld NetworkManager nftables iproute jq systemd procps-ng rpm; do
        OBSERVATIONS=$((OBSERVATIONS+1))
        read_bounded 1024 rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' "$pkg"
        if (( READ_RC != 0 )); then
            warn "Package unavailable or query failed: $pkg (exit $READ_RC)"
            continue
        fi
        printf '%s' "$READ_DATA" | emit
    done
}

firewalld_package_evidence() {
    local path raw filtered managed=0
    local -a paths=("$FWDIR/firewalld.conf")
    section 'firewalld package ownership/integrity evidence (read only)'
    if ! command -v rpm >/dev/null 2>&1; then warn 'Missing tool: rpm; vendor ownership/integrity not checked'; return 0; fi
    if [[ -e $FWDIR/firewalld-workstation.conf || -L $FWDIR/firewalld.conf ]]; then paths+=("$FWDIR/firewalld-workstation.conf"); fi
    for path in "${paths[@]}"; do
        OBSERVATIONS=$((OBSERVATIONS+1)); read_bounded 1024 rpm -qf "$path"
        if (( READ_RC != 0 )); then warn "RPM owner unavailable for $path (exit $READ_RC)"; else printf 'OWNER %s: %s\n' "$path" "${READ_DATA%$'\n'}" | emit; fi
    done
    if [[ -f $FWDIR/firewalld.conf && ! -L $FWDIR/firewalld.conf ]] && head -n 1 -- "$FWDIR/firewalld.conf" | grep -Fqx '# AEGIS Network Hardening managed local override.'; then managed=1; fi
    OBSERVATIONS=$((OBSERVATIONS+1)); read_bounded "$LIMIT" rpm -V --noscripts --nodeps firewalld
    raw=$READ_DATA
    if (( READ_TRUNCATED || READ_BINARY || READ_RC > 1 )); then
        warn "firewalld RPM verification unavailable (exit $READ_RC)"
        [[ -z $raw ]] || printf '%s' "$raw" | emit
        return 0
    fi
    if (( managed )); then
        filtered=$(printf '%s\n' "$raw" | grep -vE '[[:space:]]/etc/firewalld/firewalld\.conf$' || true)
        if [[ -z $filtered ]]; then
            say 'RPM_VERIFY=expected local AEGIS firewalld.conf override; other firewalld package files clean'
        else
            warn 'firewalld package files differ beyond the expected AEGIS firewalld.conf override'
            printf '%s' "$filtered" | emit
        fi
    elif (( READ_RC == 0 )) && [[ -z $raw ]]; then
        say 'RPM_VERIFY=clean (package files reported no differences)'
    else
        warn 'firewalld RPM verification differed'
        printf '%s' "$raw" | emit
    fi
    say 'RPM evidence supports package state only; it is not publisher authentication or proof of effective runtime rules.'
}

scalar_string() {
    local allowed=$1 value
    SCALAR=''
    if ! value=$(printf '%s' "$JSON" | jq -er '
        select(.type=="s" and (.data|type)=="array" and (.data|length)==1)
        | .data[0] | select(type=="string")'); then
        warn 'Unexpected scalar response'; return 1
    fi
    [[ $value =~ $allowed ]] || { warn 'Unrecognized scalar value'; return 1; }
    SCALAR=$value
}

firewall_inventory() {
    local name path kind initial='' final=''
    local -a entries=()
    section 'Pinned firewalld bus owner (no daemon activation)'
    if ! resolve_owner "$FIREWALL_BUS"; then return 0; fi
    FWOWNER=$OWNER; initial=$OWNER; say "OWNER=$FWOWNER"
    show_bus 'Runtime default zone' "$FWOWNER" "$FWPATH" "$FIREWALL_BUS" getDefaultZone
    DEFAULT_ZONE=''
    if [[ -n $JSON ]] && scalar_string '^[A-Za-z0-9_-]{1,64}$'; then DEFAULT_ZONE=$SCALAR; fi
    show_bus 'Runtime LogDenied' "$FWOWNER" "$FWPATH" "$FIREWALL_BUS" getLogDenied
    LOG_DENIED=''
    if [[ -n $JSON ]] && scalar_string '^(off|all|unicast|broadcast|multicast)$'; then LOG_DENIED=$SCALAR; fi
    if [[ $LOG_DENIED == all ]]; then warn 'LogDenied=all observed: review log volume; no setting changed'; fi
    show_bus 'Panic status' "$FWOWNER" "$FWPATH" "$FIREWALL_BUS" queryPanicMode
    show_bus 'Active zone bindings (interfaces and sources)' "$FWOWNER" "$FWPATH" "$FIREWALL_BUS.zone" getActiveZones
    if bus_read "$FWOWNER" "$FWPATH" "$FIREWALL_BUS.zone" getZones && array_response as name 32; then
        entries=("${NAMES[@]}")
        for name in "${entries[@]}"; do
            show_bus "Runtime zone: $name" "$FWOWNER" "$FWPATH" "$FIREWALL_BUS.zone" getZoneSettings2 s "$name"
        done
    fi
    if bus_read "$FWOWNER" "$FWPATH" "$FIREWALL_BUS.policy" getPolicies && array_response as name 32; then
        entries=("${NAMES[@]}")
        for name in "${entries[@]}"; do
            show_bus "Runtime policy: $name" "$FWOWNER" "$FWPATH" "$FIREWALL_BUS.policy" getPolicySettings s "$name"
        done
    fi
    for kind in Zones Policies; do
        if bus_read "$FWOWNER" "$FWPATH/config" "$FIREWALL_BUS.config" "list$kind" && array_response ao path 32; then
            entries=("${NAMES[@]}")
            for path in "${entries[@]}"; do
                [[ $path == "$FWPATH/config/"* ]] || { warn 'Foreign permanent object path omitted'; continue; }
                if [[ $kind == Zones ]]; then
                    show_bus 'Permanent zone (daemon view)' "$FWOWNER" "$path" "$FIREWALL_BUS.config.zone" getSettings2
                else
                    show_bus 'Permanent policy (daemon view)' "$FWOWNER" "$path" "$FIREWALL_BUS.config.policy" getSettings
                fi
            done
        fi
    done
    section 'firewalld owner at end'
    if resolve_owner "$FIREWALL_BUS"; then final=$OWNER; fi
    [[ $initial == "$final" ]] || warn 'firewalld owner changed/disappeared; readings are inconsistent'
    say 'A stable owner does NOT prove rules stayed unchanged; this is not an atomic snapshot.'
}

# Deliberately excludes SSID, connection.id, VPN data, secrets, MAC and stable-id.
profile_summary() {
    jq -e '
      if .type!="a{sa{sv}}" or (.data|length)!=1 or (.data[0]|type)!="object" then error("profile schema") else
        .data[0] as $d |
        {connection: ($d.connection | with_entries(select(.key=="uuid" or .key=="type" or .key=="zone"))),
         ipv4: (($d.ipv4 // {}) | with_entries(select(.key=="method" or .key=="ignore-auto-dns" or .key=="never-default"))),
         ipv6: (($d.ipv6 // {}) | with_entries(select(.key=="method" or .key=="ignore-auto-dns" or .key=="never-default")))} end'
}

networkmanager_inventory() {
    local active path profile obj final=''
    local -a entries=()
    section 'NetworkManager active profile/zone mapping (no GetSecrets)'
    if ! resolve_owner "$NMBUS"; then return 0; fi
    NMOWNER=$OWNER
    if ! bus_read "$NMOWNER" "$NMPATH" "$PROP" Get ss "$NMBUS" ActiveConnections; then return 0; fi
    # A Get response wraps the array in a variant. Normalize only after validation.
    if ! obj=$(printf '%s' "$JSON" | jq -e 'select(.type=="v" and (.data|length)==1 and .data[0].type=="ao") | {type:"ao",data:[.data[0].data]}'); then
        warn 'Unexpected ActiveConnections variant'; return 0
    fi
    JSON=$obj
    if ! array_response ao path 16; then return 0; fi
    entries=("${NAMES[@]}")
    for path in "${entries[@]}"; do
        [[ $path == "$NMPATH/ActiveConnection/"* ]] || { warn 'Unexpected active connection path'; continue; }
        if ! bus_read "$NMOWNER" "$path" "$PROP" GetAll s "$NMBUS.Connection.Active"; then continue; fi
        active=$JSON
        section 'Active connection identity (UUID, not human name)'
        if ! printf '%s' "$active" | jq -e 'select(.type=="a{sv}" and (.data|length)==1) | .data[0] |
          with_entries(select(.key=="Uuid" or .key=="Type" or .key=="State" or .key=="Default" or .key=="Default6" or .key=="Devices"))' | emit; then
            warn 'Malformed active properties'; continue
        fi
        if ! profile=$(printf '%s' "$active" | jq -er '.data[0].Connection | select(.type=="o") | .data'); then
            warn 'Active profile path unavailable'; continue
        fi
        [[ $profile =~ ^/org/freedesktop/NetworkManager/Settings/[0-9]+$ ]] || { warn 'Unexpected profile path'; continue; }
        if bus_read "$NMOWNER" "$profile" "$NMBUS.Settings.Connection" GetSettings; then
            section 'Saved profile policy fields (not a live firewall verification)'
            if ! printf '%s' "$JSON" | profile_summary | emit; then warn 'Profile schema unexpected'; fi
        fi
    done
    if resolve_owner "$NMBUS"; then final=$OWNER; fi
    [[ $NMOWNER == "$final" ]] || warn 'NetworkManager owner changed/disappeared'
    say 'Only active profiles were inspected. Missing zone means default-zone selection, not automatic safety.'
}

resolver_inventory() {
    local initial final=''
    section 'Resolver manager (no DNS query or cache flush)'
    if ! resolve_owner org.freedesktop.resolve1; then return 0; fi
    RESOWNER=$OWNER; initial=$OWNER
    if bus_read "$RESOWNER" /org/freedesktop/resolve1 "$PROP" GetAll s org.freedesktop.resolve1.Manager; then
        if ! printf '%s' "$JSON" | jq -e 'select(.type=="a{sv}" and (.data|length)==1) | .data[0] |
           with_entries(select(.key=="DNS" or .key=="DNSEx" or .key=="FallbackDNS" or .key=="DNSOverTLS" or .key=="DNSSEC" or .key=="LLMNR" or .key=="MulticastDNS"))' | emit; then
            warn 'Unexpected resolver response'
        fi
    fi
    if resolve_owner org.freedesktop.resolve1; then final=$OWNER; fi
    [[ $initial == "$final" ]] || warn 'Resolver owner changed/disappeared'
    say 'Manager fields are not per-link proof of encrypted DNS. Browser/VPN DNS is outside this observation.'
}

# One bounded observation per key: an absent IPv6/optional key must not hide
# valid IPv4/TCP fields. Values are observed, never ranked as universally safe.
observe_sysctl_keys() {
    local label=$1 key value; shift
    section "$label"
    if ! command -v sysctl >/dev/null 2>&1; then warn 'Missing tool: sysctl'; return 0; fi
    for key in "$@"; do
        OBSERVATIONS=$((OBSERVATIONS+1))
        read_bounded 256 sysctl -n -- "$key"
        if (( READ_RC != 0 )); then warn "Unavailable sysctl: $key (exit $READ_RC)"; continue; fi
        value=${READ_DATA%$'\n'}
        if [[ ! $value =~ ^-?[A-Za-z0-9_]{1,32}$ ]]; then
            warn "Invalid scalar sysctl: $key"; continue
        fi
        printf '%s = %s\n' "$key" "$value" | emit
    done
}

sysctl_packet_and_speed_inventory() {
    observe_sysctl_keys 'Global/default TCP and packet-policy values (read only, not a score)' \
        net.ipv4.tcp_congestion_control net.core.default_qdisc \
        net.ipv4.tcp_fastopen net.ipv4.tcp_mtu_probing net.ipv4.tcp_syncookies \
        net.ipv4.tcp_rfc1337 net.ipv4.ip_forward \
        net.ipv6.conf.all.forwarding net.ipv6.conf.all.disable_ipv6 \
        net.ipv6.conf.default.disable_ipv6 \
        net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter \
        net.ipv4.conf.all.src_valid_mark net.ipv4.conf.default.src_valid_mark \
        net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects \
        net.ipv4.conf.all.secure_redirects net.ipv4.conf.default.secure_redirects \
        net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects \
        net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route \
        net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.icmp_ignore_bogus_error_responses \
        net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects \
        net.ipv6.conf.all.accept_source_route net.ipv6.conf.default.accept_source_route \
        net.ipv6.conf.all.accept_ra net.ipv6.conf.default.accept_ra
    say 'conf/default values are templates; conf/all has key-specific semantics, not one universal effective value.'
}

interface_sysctl_inventory() {
    local names name
    section 'Per-interface packet policy (at most 16 observed links; no writes)'
    if ! command -v ip >/dev/null 2>&1; then warn 'Missing tool: ip'; return 0; fi
    OBSERVATIONS=$((OBSERVATIONS+1))
    read_bounded "$LIMIT" ip -j link show
    if (( READ_RC != 0 )); then warn 'Link inventory unavailable'; return 0; fi
    if ! names=$(printf '%s' "$READ_DATA" | jq -ser '
      if length==1 and (.[0]|type)=="array" and (.[0]|length)<=16
        and all(.[0][]; type=="object" and (.ifname|type)=="string"
          and (.ifname|test("^[A-Za-z0-9_.:-]{1,15}$")))
      then .[0] | map(.ifname) | join("\n") else error("unsupported link list") end'); then
        warn 'Malformed/oversized/unsupported link names; interface values omitted'; return 0
    fi
    [[ -n $names ]] || { warn 'No links observed in this namespace'; return 0; }
    while IFS= read -r name; do
        [[ $name != . && $name != .. ]] || { warn 'Unsafe link name omitted'; continue; }
        # Slash notation preserves a dot inside a real interface name.
        observe_sysctl_keys "Interface: $name (may change during collection)" \
            "net/ipv4/conf/$name/rp_filter" "net/ipv4/conf/$name/src_valid_mark" \
            "net/ipv4/conf/$name/accept_redirects" "net/ipv4/conf/$name/secure_redirects" \
            "net/ipv4/conf/$name/send_redirects" "net/ipv4/conf/$name/accept_source_route" \
            "net/ipv6/conf/$name/accept_redirects" "net/ipv6/conf/$name/accept_source_route" \
            "net/ipv6/conf/$name/accept_ra" "net/ipv6/conf/$name/forwarding" \
            "net/ipv6/conf/$name/disable_ipv6"
    done <<< "$names"
    say 'A device can disappear between reads; this is not an atomic network snapshot.'
}

advisory_plan() {
    section 'HARDENING ARCHITECTURE'
    say '1. aegis-public is the restrictive default for unclassified/new connections.'
    say '2. The reviewed active physical profile is pinned by UUID to aegis-lan.'
    say '3. aegis-lan permits only DHCPv6-client and bounded printer discovery/client services.'
    say '4. SSH, Samba/NetBIOS and blanket TCP/UDP 1025-65535 inbound access are absent.'
    say '5. firewalld remains the sole nftables owner; nftables.service and legacy lockdown stay inactive.'
    say '6. StrictForwardPorts blocks implicit Docker-published DNAT until a later explicit Docker policy allows it.'
    say '7. LLMNR defaults off; mDNS defaults off except resolve-only on the reviewed printer LAN profile.'
    say '8. Redirect/source-route sysctls are disabled without owning forwarding, BBR, MTU, RA or VPN marks.'
    say '9. Apply is protected by durable snapshots and a transient systemd rollback timer.'
}

unit_inventory() {
    local unit
    for unit in firewalld.service NetworkManager.service systemd-resolved.service docker.service docker.socket \
                nftables.service iptables.service aegis-firewall-lockdown.service \
                cups.service avahi-daemon.service; do
        capture "Unit observation: $unit" systemctl --system --no-pager show "$unit" \
            -p LoadState -p ActiveState -p SubState -p UnitFileState -p Result -p InvocationID \
            -p FragmentPath -p DropInPaths -p After -p Before -p Wants -p Conflicts
        if [[ $unit == aegis-firewall-lockdown.service && $CAPTURED == *'LoadState=loaded'* ]]; then
            warn 'Legacy lockdown unit is installed. Inspect its enablement/order; this audit does not disable it.'
        fi
    done
    say 'Single-file release: no persistent AEGIS network service is installed or required.'
    say 'Direct execution has no systemd cgroup/seccomp/IPAddressDeny sandbox; the trusted script still runs as root.'
}

audit() {
    say "AEGIS Network Hardening $VERSION -- READ-ONLY LOCAL REPORT"
    say 'Audit performs no rule/profile/sysctl mutation, packet probe, DNS lookup or speed test.'
    say 'PRIVATE REPORT: IPs, UUIDs, routes, rule comments/labels and file paths remain. Review before sharing.'
    capture 'Kernel' uname -srmo
    package_inventory
    unit_inventory
    read_config_file "$FWDIR/firewalld.conf"
    firewalld_package_evidence
    read_config_file "$PUBLIC_ZONE_FILE" yes
    read_config_file "$LAN_ZONE_FILE" yes
    read_config_file "$SYSCTL_FILE" yes
    read_config_file "$NM_CONF_FILE" yes
    read_config_file "$FWDIR/zones/aegis-secure.xml" yes
    read_config_file "$FWDIR/lockdown-whitelist.xml" yes
    firewall_inventory
    networkmanager_inventory
    resolver_inventory
    capture 'Host addresses; numeric output' ip -brief address show
    capture 'IPv4 routes' ip -4 route show table all
    capture 'IPv6 routes' ip -6 route show table all
    capture 'Policy routing IPv4' ip -4 rule show
    capture 'Policy routing IPv6' ip -6 rule show
    capture 'Listening sockets (not proof of remote reachability)' ss -H -lntu
    capture 'nftables numeric ruleset; host namespace only' nft -nn list ruleset
    sysctl_packet_and_speed_inventory
    interface_sysctl_inventory
    capture 'Queue disciplines; not a benchmark' tc -s qdisc show
    say 'Docker API is NOT contacted (avoids socket activation/context/credential side effects).'
    say 'Rootless containers, VPN leaks and remote port reachability are not proved by this host report.'
    section 'Summary'
    say "OBSERVATIONS=$OBSERVATIONS OBSERVATION_WARNINGS=$PROBLEMS"
    say 'NO SECURITY SCORE / PERFORMANCE PERCENTAGE / ATOMIC SNAPSHOT.'
    return 0
}

packages_report() {
    local c missing=0
    local -a required=(timeout head cat tr sed awk stat readlink jq sha256sum flock mktemp mkdir install cp mv rm chmod chown sync date grep sort)
    local -a observed=(rpm systemctl systemd-run systemd-detect-virt loginctl busctl uname ip ss nft sysctl tc nmcli firewall-cmd firewall-offline-cmd getenforce restorecon)
    local -a report_tools=(getent sudo xdg-user-dir)
    say "AEGIS Network Hardening $VERSION | dependency report | nothing is installed automatically"
    section 'Mandatory runtime commands'
    for c in "${required[@]}"; do
        if command -v "$c" >/dev/null 2>&1; then printf '  %-24s PRESENT
' "$c"; else printf '  %-24s MISSING
' "$c"; missing=$((missing+1)); fi
    done
    section 'Fedora/firewall/network commands'
    for c in "${observed[@]}"; do
        if command -v "$c" >/dev/null 2>&1; then printf '  %-24s PRESENT
' "$c"; else printf '  %-24s MISSING
' "$c"; missing=$((missing+1)); fi
    done
    section 'Private report helpers'
    for c in "${report_tools[@]}"; do
        if command -v "$c" >/dev/null 2>&1; then printf '  %-24s PRESENT
' "$c"; else printf '  %-24s MISSING/OPTIONAL
' "$c"; fi
    done
    say 'Fedora package families: bash, coreutils, gawk, jq, util-linux, systemd, rpm, iproute, nftables, procps-ng, firewalld, NetworkManager, policycoreutils, xdg-user-dirs.'
    say 'packages never downloads, installs, enables, restarts, reloads, allows or blocks anything.'
    (( missing == 0 )) || return 3
}

require_installed_runtime() {
    local data uid gid mode links
    [[ $SELF_PATH == "$INSTALL_PATH" ]] || die "Run audit/plan from the installed copy: $INSTALL_PATH"
    check_file "$INSTALL_PATH" || die 'Installed runtime is missing or fails protected-path checks'
    read_bounded 256 stat -c '%u %g %a %h' -- "$INSTALL_PATH"
    (( READ_RC == 0 )) || die 'Cannot inspect installed runtime metadata'
    data=$READ_DATA
    IFS=' ' read -r uid gid mode links <<< "$data"
    [[ $uid == 0 && $gid == 0 && $mode == 755 && $links == 1 ]] || \
        die 'Installed runtime must be root:root, mode 0755, one hard link'
}

verify_install() {
    local data uid gid mode links size installed_hash source_hash installed_version
    section 'Installed single-file runtime verification'
    if ! check_file "$INSTALL_PATH"; then
        warn "Installed runtime is missing or unsafe: $INSTALL_PATH"
        return 0
    fi
    read_bounded 256 stat -c '%u %g %a %h %s' -- "$INSTALL_PATH"
    if (( READ_RC != 0 )); then
        warn 'Cannot read installed runtime metadata'
        return 0
    fi
    data=$READ_DATA
    IFS=' ' read -r uid gid mode links size <<< "$data"
    [[ $uid == 0 && $gid == 0 ]] || warn 'Installed runtime must be owned by root:root'
    [[ $mode == 755 ]] || warn "Installed runtime mode is $mode; expected 755"
    [[ $links == 1 ]] || warn 'Installed runtime must have exactly one hard link'

    read_bounded 256 sha256sum -- "$INSTALL_PATH"
    if (( READ_RC != 0 )); then
        warn 'Cannot hash installed runtime'
    else
        installed_hash=${READ_DATA%% *}
        say "INSTALLED_SHA256=$installed_hash"
    fi

    read_bounded 256 /usr/bin/bash -p -- "$INSTALL_PATH" version
    if (( READ_RC != 0 )); then
        warn 'Installed runtime did not report its version'
    else
        installed_version=${READ_DATA%$'\n'}
        say "INSTALLED_VERSION=$installed_version"
        [[ $installed_version == "$VERSION" ]] || warn "Installed version differs from this source: $VERSION"
    fi

    if [[ $SELF_PATH != "$INSTALL_PATH" ]]; then
        read_bounded 256 sha256sum -- "$SELF_PATH"
        if (( READ_RC != 0 )); then
            warn 'Cannot hash current source file'
        else
            source_hash=${READ_DATA%% *}
            say "SOURCE_SHA256=$source_hash"
            if [[ -n ${installed_hash-} && $source_hash != "$installed_hash" ]]; then
                warn 'Current source and installed runtime differ'
            fi
        fi
    fi
    (( PROBLEMS == 0 )) && say 'VERIFIED_INSTALL: root-owned single-file runtime matches the checked source/version.'
    return 0
}

export_report() {
    local tool user_name passwd_hash passwd_uid passwd_gid gecos home shell desktop dir final uid mode links rc=0
    (( EUID != 0 )) || die 'Run export WITHOUT sudo; only the collector will request sudo'
    [[ $SELF_PATH == "$INSTALL_PATH" ]] || die "Export must be run from the installed copy: $INSTALL_PATH"
    for tool in getent mkdir mktemp mv rm chmod stat sudo; do need "$tool"; done

    read_bounded 4096 getent passwd "$UID"
    (( READ_RC == 0 )) || die 'Cannot resolve the invoking user from passwd database'
    IFS=: read -r user_name passwd_hash passwd_uid passwd_gid gecos home shell <<< "${READ_DATA%$'\n'}"
    [[ $passwd_uid == "$UID" && $home == /* && -d $home && -O $home ]] || die 'Unsafe or inconsistent user home'
    [[ $home != *$'\n'* && $home != *$'\r'* && $home != *$'\t'* ]] || die 'Control character in home path'

    HOME=$home
    export HOME
    if command -v xdg-user-dir >/dev/null 2>&1; then
        read_bounded 4096 xdg-user-dir DESKTOP
        (( READ_RC == 0 )) || die 'Cannot resolve the desktop directory'
        desktop=${READ_DATA%$'\n'}
    else
        desktop=$home/Desktop
    fi
    [[ $desktop == /* && $desktop != *$'\n'* && $desktop != *$'\r'* && $desktop != *$'\t'* ]] || die 'Unsafe desktop path'

    dir=$desktop/LOG_FILES
    [[ ! -L $dir ]] || die 'Refusing symlink LOG_FILES directory'
    mkdir -p -- "$dir" || die 'Cannot create LOG_FILES directory'
    [[ -d $dir && -O $dir ]] || die 'LOG_FILES directory must belong to the invoking user'
    read_bounded 256 stat -c '%u %a' -- "$dir"
    (( READ_RC == 0 )) || die 'Cannot inspect LOG_FILES directory'
    IFS=' ' read -r uid mode <<< "$READ_DATA"
    [[ $uid == "$UID" && $mode =~ ^[0-7]{3,4}$ ]] || die 'Unexpected LOG_FILES ownership/mode'
    (( (8#$mode & 0022) == 0 )) || die 'LOG_FILES must not be group/world writable'

    final=$dir/$REPORT_NAME
    [[ ! -L $final ]] || die 'Refusing symlink report path'
    if [[ -e $final ]]; then
        [[ -f $final && -O $final ]] || die 'Existing report must be a user-owned regular file'
        read_bounded 256 stat -c '%u %a %h' -- "$final"
        (( READ_RC == 0 )) || die 'Cannot inspect existing report'
        IFS=' ' read -r uid mode links <<< "$READ_DATA"
        [[ $uid == "$UID" && $links == 1 && $mode =~ ^[0-7]{3,4}$ ]] || die 'Unsafe existing report metadata'
        (( (8#$mode & 0022) == 0 )) || die 'Existing report must not be group/world writable'
    fi

    EXPORT_TMP=$(mktemp "$dir/.network-audit.XXXXXXXX") || die 'Cannot create temporary report'
    chmod 0600 -- "$EXPORT_TMP" || die 'Cannot protect temporary report'
    if sudo -- /usr/bin/bash -p -- "$INSTALL_PATH" audit >"$EXPORT_TMP" 2>&1; then
        rc=0
    else
        rc=$?
    fi
    mv -T -- "$EXPORT_TMP" "$final" || die 'Cannot publish report atomically'
    EXPORT_TMP=''
    chmod 0600 -- "$final" || die 'Cannot protect final report'
    printf 'Report: %s\nCollector exit: %s\n' "$final" "$rc"
    say 'PRIVATE: IPs, UUIDs, routes, rules and paths remain. Review before sharing.'
    say 'Exit 3 means incomplete observations, not proof of an attack.'
    return "$rc"
}

# -------------------------- MUTATION ENGINE --------------------------

safe_tx_id() { [[ $1 =~ ^T-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$ ]]; }
safe_uuid() { [[ $1 =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]]; }
safe_iface() { [[ $1 =~ ^[A-Za-z0-9_.:-]{1,15}$ && $1 != . && $1 != .. ]]; }

acquire_lock() {
    local wait=${1:-0}
    (( LOCK_HELD == 0 )) || return 0
    install -d -o root -g root -m 0755 /run/lock
    exec 9>"$LOCK_FILE"
    if (( wait > 0 )); then
        flock -w "$wait" 9 || die 'Timed out waiting for the AEGIS Network transaction lock'
    else
        flock -n 9 || die 'Another AEGIS Network transaction is active'
    fi
    LOCK_HELD=1
}

require_platform() {
    local id='' version='' arch virt selinux
    [[ -r /etc/os-release ]] || die 'Cannot identify operating system'
    id=$(awk -F= '$1=="ID"{gsub(/^"|"$/,"",$2); print $2}' /etc/os-release)
    version=$(awk -F= '$1=="VERSION_ID"{gsub(/^"|"$/,"",$2); print $2}' /etc/os-release)
    arch=$(uname -m)
    [[ $id == fedora && $version == 44 ]] || die 'Mutation supports only traditional Fedora 44'
    [[ $arch == x86_64 || $arch == aarch64 ]] || die 'Unsupported architecture'
    [[ ! -e /run/ostree-booted && ! -e /run/bootc ]] || die 'Atomic/bootc Fedora is not supported for writes'
    virt=$(systemd-detect-virt 2>/dev/null || true)
    [[ $virt == none || -z $virt ]] || die "Mutation requires a native host; detected virtualization: $virt"
    [[ $(systemctl is-system-running 2>/dev/null || true) != offline ]] || die 'Local systemd is unavailable'
    selinux=$(getenforce 2>/dev/null || true)
    [[ $selinux == Enforcing ]] || die "SELinux Enforcing required; observed: ${selinux:-unknown}"
    systemctl is-active --quiet firewalld.service || die 'firewalld.service must already be active'
    systemctl is-active --quiet NetworkManager.service || die 'NetworkManager.service must already be active'
    systemctl is-active --quiet nftables.service && die 'nftables.service must not compete with firewalld'
    if systemctl is-active --quiet aegis-firewall-lockdown.service || systemctl is-enabled --quiet aegis-firewall-lockdown.service 2>/dev/null; then
        die 'Legacy aegis-firewall-lockdown.service is active/enabled; inspect and remove it before mutation'
    fi
    [[ ! -e $FWDIR/lockdown-whitelist.xml && ! -L $FWDIR/lockdown-whitelist.xml ]] || die 'Legacy lockdown-whitelist.xml exists; archive and remove it after review before mutation'
    [[ ! -e $FWDIR/zones/aegis-secure.xml && ! -L $FWDIR/zones/aegis-secure.xml ]] || die 'Legacy aegis-secure.xml exists; archive and remove it after review before mutation'
    firewall-cmd --state >/dev/null || die 'firewalld D-Bus state is unavailable'
    nft list table inet firewalld >/dev/null 2>&1 || die 'firewalld is not using the expected native nftables table'
}

require_local_recovery_session() {
    local login_uid sid uid user seat tty active remote type class found=0
    [[ -r $LOGINUID_PATH ]] || die 'Cannot establish the invoking login identity'
    login_uid=$(<"$LOGINUID_PATH")
    [[ $login_uid =~ ^[0-9]+$ && $login_uid != 4294967295 ]] || die 'Apply requires an attributable local login session'
    while IFS=' ' read -r sid uid user seat tty _; do
        [[ $uid == "$login_uid" && -n $sid ]] || continue
        active=$(loginctl show-session "$sid" -p Active --value 2>/dev/null || true)
        remote=$(loginctl show-session "$sid" -p Remote --value 2>/dev/null || true)
        type=$(loginctl show-session "$sid" -p Type --value 2>/dev/null || true)
        class=$(loginctl show-session "$sid" -p Class --value 2>/dev/null || true)
        if [[ $active == yes && $remote == no && $class == user && $type =~ ^(wayland|x11|tty)$ ]]; then
            found=1
            break
        fi
    done < <(loginctl list-sessions --no-legend 2>/dev/null || true)
    (( found == 1 )) || die 'Apply requires an active local Wayland/X11/TTY recovery session; remote-only mutation is refused'
}

refuse_active_docker_for_apply() {
    if systemctl is-active --quiet docker.service || systemctl is-active --quiet docker.socket; then
        die 'Docker is active. StrictForwardPorts deliberately changes published-port behavior; integrate the Docker isolation layer first.'
    fi
}

normalize_nm_zone() {
    case ${1-} in ''|'--') printf '%s' '';; *) printf '%s' "$1";; esac
}
normalize_nm_enum() {
    case ${1-} in
      ''|'--'|default|-1|'-1 (default)') printf '%s' 'default';;
      no|0|'0 (no)') printf '%s' 'no';;
      resolve|1|'1 (resolve)') printf '%s' 'resolve';;
      yes|2|'2 (yes)') printf '%s' 'yes';;
      *) printf '%s' "$1";;
    esac
}

# NetworkManager 1.56 no longer exposes connection.read-only through nmcli;
# the D-Bus setting is deprecated and has no meaning.  Critical reads are
# therefore explicit/fail-closed instead of being hidden inside substitutions.
NM_VALUE=''
nm_profile_property_read() {
    local property=$1 uuid=$2 value
    safe_uuid "$uuid" || return 2
    case $property in
      connection.zone|connection.llmnr|connection.mdns) ;;
      *) return 2;;
    esac
    if ! value=$(timeout 20 nmcli -g "$property" connection show uuid "$uuid" 2>/dev/null); then
        return 1
    fi
    [[ ${#value} -le 4096 && $value != *$'\n'* && $value != *$'\r'* ]] || return 1
    NM_VALUE=$value
    return 0
}
nm_profile_property_or_die() {
    local property=$1 uuid=$2
    nm_profile_property_read "$property" "$uuid" ||
        die "NetworkManager cannot read $property for the selected profile"
}

select_profile() {
    local uuid type dev count=0 found_uuid='' found_dev='' rows
    [[ -z $PROFILE_OPT ]] || safe_uuid "$PROFILE_OPT" || die 'Invalid --connection-uuid'
    if ! rows=$(timeout 20 nmcli -t -e no -f UUID,TYPE,DEVICE connection show --active 2>/dev/null); then
        die 'NetworkManager active-connection inventory failed'
    fi
    while IFS=: read -r uuid type dev; do
        [[ -n $uuid ]] || continue
        case $type in 802-11-wireless|802-3-ethernet) ;; *) continue;; esac
        safe_uuid "$uuid" || continue
        safe_iface "$dev" || continue
        [[ -z $PROFILE_OPT || $uuid == "$PROFILE_OPT" ]] || continue
        count=$((count+1)); found_uuid=$uuid; found_dev=$dev
    done <<< "$rows"
    if [[ -n $PROFILE_OPT && $count == 0 ]]; then die 'Requested UUID is not an active physical connection'; fi
    (( count == 1 )) || die 'Exactly one active physical connection is required; use --connection-uuid when multiple are active'
    PROFILE_UUID=$found_uuid
    PROFILE_DEVICE=$found_dev

    nm_profile_property_or_die connection.zone "$PROFILE_UUID"
    PROFILE_OLD_ZONE=$(normalize_nm_zone "$NM_VALUE")
    nm_profile_property_or_die connection.llmnr "$PROFILE_UUID"
    PROFILE_OLD_LLMNR=$(normalize_nm_enum "$NM_VALUE")
    nm_profile_property_or_die connection.mdns "$PROFILE_UUID"
    PROFILE_OLD_MDNS=$(normalize_nm_enum "$NM_VALUE")
}

validate_other_profiles() {
    local uuid type zone blockers='' rows
    if ! rows=$(timeout 20 nmcli -t -e no -f UUID,TYPE connection show 2>/dev/null); then
        die 'NetworkManager saved-profile inventory failed'
    fi
    while IFS=: read -r uuid type; do
        [[ -n $uuid ]] || continue
        case $type in 802-11-wireless|802-3-ethernet) ;; *) continue;; esac
        safe_uuid "$uuid" || continue
        [[ $uuid != "$PROFILE_UUID" ]] || continue
        nm_profile_property_or_die connection.zone "$uuid"
        zone=$(normalize_nm_zone "$NM_VALUE")
        case $zone in ''|aegis-public|aegis-lan) ;;
          *) blockers+="$uuid:$zone"$'\n';;
        esac
    done <<< "$rows"
    [[ -z $blockers ]] || die "Other saved physical profiles have explicit foreign zones; classify them before apply: ${blockers%$'\n'}"
}

write_public_zone() {
    cat >"$1" <<'ZONE'
<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>AEGIS Public</short>
  <description>Restrictive fallback for unclassified networks. Native default target accepts ICMP and rejects all unmatched application traffic.</description>
  <service name="dhcpv6-client"/>
</zone>
ZONE
}

write_lan_zone() {
    cat >"$1" <<'ZONE'
<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>AEGIS Printer LAN</short>
  <description>Bounded printer discovery/client profile: DHCPv6 client, mDNS, IPP client and WS-Discovery client only.</description>
  <service name="dhcpv6-client"/>
  <service name="mdns"/>
  <service name="ipp-client"/>
  <service name="ws-discovery-client"/>
</zone>
ZONE
}

write_sysctl_policy() {
    cat >"$1" <<'SYSCTL'
# Managed by AEGIS Network Hardening; use the tool's rollback before editing.
# Forwarding, BBR, MTU, RA, DNS, queue disciplines and Docker sysctls are deliberately out of scope.
# Loose RPF is the default for future interfaces; the selected physical device is set live.
# net.ipv4.conf.all.rp_filter is deliberately not owned to avoid VPN/container policy conflicts.
net.ipv4.conf.default.rp_filter = 2
# all/default set functional/global policy and defaults. The wildcard entries
# persist the same redirect/source-route policy on every concrete interface,
# including lo and interfaces that appear after early boot; systemd-sysctl
# reapplies network-interface globs when interfaces are added.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.*.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.*.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.*.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.*.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.*.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = -1
net.ipv6.conf.default.accept_source_route = -1
net.ipv6.conf.*.accept_source_route = -1
SYSCTL
}

write_nm_policy() {
    cat >"$1" <<'NMCONF'
# Managed by AEGIS Network Hardening.
# Unclassified profiles do not advertise/resolve via LLMNR or mDNS by default.
[connection]
connection.llmnr=0
connection.mdns=0
NMCONF
}

rewrite_firewalld_conf() {
    local src=$1 out=$2 first
    [[ -f $src && ! -L $src ]] || die 'Resolved firewalld.conf source is not a regular file'
    first=$(head -n 1 -- "$src" 2>/dev/null || true)
    if [[ $FIREWALL_CONF != "$src" && $src == "$FWDIR/firewalld-workstation.conf" ]]; then :
    elif [[ $first == '# AEGIS Network Hardening managed local override.' ]]; then :
    else
        die 'A non-vendor, non-AEGIS firewalld.conf already exists; refusing to overwrite foreign policy'
    fi
    cat >"$out" <<'CONF'
# AEGIS Network Hardening managed local override.
# Deterministic Fedora 44 firewalld configuration; rollback before manual editing.
DefaultZone=aegis-public
CleanupOnExit=yes
CleanupModulesOnExit=no
IPv6_rpfilter=loose
IndividualCalls=no
LogDenied=off
FirewallBackend=nftables
FlushAllOnReload=yes
ReloadPolicy=INPUT:DROP,FORWARD:DROP,OUTPUT:DROP
RFC3964_IPv4=yes
StrictForwardPorts=yes
NftablesFlowtable=off
NftablesCounters=no
NftablesTableOwner=yes
CONF
}

validate_managed_destinations() {
    local p header
    for p in "$PUBLIC_ZONE_FILE" "$LAN_ZONE_FILE" "$SYSCTL_FILE" "$NM_CONF_FILE"; do
        if [[ -L $p ]]; then die "Refusing managed-path symlink: $p"; fi
        if [[ -e $p ]]; then
            check_file "$p" || die "Unsafe existing managed path: $p"
            header=$(head -n 4 -- "$p" 2>/dev/null || true)
            case $p in
              "$PUBLIC_ZONE_FILE"|"$LAN_ZONE_FILE") [[ $header == *AEGIS* ]] || die "Foreign zone already uses reserved AEGIS name: $p";;
              "$SYSCTL_FILE"|"$NM_CONF_FILE") [[ $header == *AEGIS* ]] || die "Foreign configuration already uses reserved AEGIS path: $p";;
            esac
        fi
    done
}

remove_plan_dir() {
    if [[ -n ${PLAN_DIR-} && -d $PLAN_DIR ]]; then rm -rf -- "$PLAN_DIR"; fi
    PLAN_DIR=''
}

validate_local_firewalld_extensions() {
    [[ ! -e $FWDIR/direct.xml && ! -L $FWDIR/direct.xml ]] || die 'Permanent firewalld direct.xml exists; native zone ownership cannot be proved'
    if compgen -G "$FWDIR/policies/*.xml" >/dev/null; then
        die 'Local permanent firewalld policy XML exists; review/remove foreign policy before AEGIS apply'
    fi
}

build_candidates() {
    local resolved
    remove_plan_dir
    PLAN_DIR=$(mktemp -d /run/aegis-network-plan.XXXXXXXX) || die 'Cannot create private plan directory'
    chmod 0700 "$PLAN_DIR"
    resolve_config_file "$FIREWALL_CONF" || die 'Current firewalld.conf is unsafe or unsupported'
    resolved=$RESOLVED_CONFIG
    rewrite_firewalld_conf "$resolved" "$PLAN_DIR/firewalld.conf"
    write_public_zone "$PLAN_DIR/aegis-public.xml"
    write_lan_zone "$PLAN_DIR/aegis-lan.xml"
    write_sysctl_policy "$PLAN_DIR/91-aegis-network-hardening.conf"
    write_nm_policy "$PLAN_DIR/90-aegis-network-hardening.conf"
    chmod 0600 "$PLAN_DIR"/*
}

service_semantics_equal() {
    local name=$1 ports=$2 source_ports=$3 destinations=$4 protocols=${5-} actual
    actual=$(timeout 15 firewall-cmd --permanent --service="$name" --get-ports) || return 1
    wordset_equals "$actual" "$ports" || return 1
    actual=$(timeout 15 firewall-cmd --permanent --service="$name" --get-source-ports) || return 1
    wordset_equals "$actual" "$source_ports" || return 1
    actual=$(timeout 15 firewall-cmd --permanent --service="$name" --get-destinations) || return 1
    wordset_equals "$actual" "$destinations" || return 1
    actual=$(timeout 15 firewall-cmd --permanent --service="$name" --get-protocols) || return 1
    wordset_equals "$actual" "$protocols"
}

require_firewalld_services() {
    local services s
    services=$(timeout 15 firewall-cmd --get-services) || die 'Cannot enumerate firewalld services'
    for s in dhcpv6-client mdns ipp-client ws-discovery-client; do
        [[ " $services " == *" $s "* ]] || die "Required Fedora firewalld service is unavailable: $s"
    done
    service_semantics_equal dhcpv6-client '546/udp' '' 'ipv6:fe80::/64' || die 'dhcpv6-client service semantics differ from the reviewed current definition'
    service_semantics_equal mdns '5353/udp' '' 'ipv4:224.0.0.251 ipv6:ff02::fb' || die 'mdns service semantics differ from the reviewed current definition'
    service_semantics_equal ipp-client '631/udp' '' '' || die 'ipp-client service semantics differ from the reviewed current definition'
    service_semantics_equal ws-discovery-client '' '3702/udp' '' || die 'ws-discovery-client service semantics differ from the reviewed current definition'
}

hash_file() { sha256sum -- "$1" | awk '{print $1}'; }
current_hash_or_absent() {
    if [[ -f $1 && ! -L $1 ]]; then hash_file "$1"
    elif [[ -L $1 ]]; then printf 'symlink:%s' "$(readlink -- "$1")"
    else printf 'absent'
    fi
}

collect_runtime_fingerprint() {
    local out=$1 key value dir iface chain default_zone zone llmnr mdns
    : >"$out"
    default_zone=$(firewall-cmd --get-default-zone) || die 'Cannot read firewalld default zone'
    nm_profile_property_or_die connection.zone "$PROFILE_UUID"; zone=$NM_VALUE
    nm_profile_property_or_die connection.llmnr "$PROFILE_UUID"; llmnr=$NM_VALUE
    nm_profile_property_or_die connection.mdns "$PROFILE_UUID"; mdns=$NM_VALUE
    printf 'default_zone=%s\n' "$default_zone" >>"$out"
    printf 'profile_zone=%s\nprofile_llmnr=%s\nprofile_mdns=%s\n' "$zone" "$llmnr" "$mdns" >>"$out"
    while IFS= read -r key; do
        value=$(sysctl -n -- "$key" 2>/dev/null || printf UNAVAILABLE)
        printf '%s=%s\n' "$key" "$value" >>"$out"
    done <<'KEYS'
net.ipv4.conf.default.rp_filter
net.ipv4.conf.all.accept_redirects
net.ipv4.conf.default.accept_redirects
net.ipv4.conf.all.secure_redirects
net.ipv4.conf.default.secure_redirects
net.ipv4.conf.all.send_redirects
net.ipv4.conf.default.send_redirects
net.ipv4.conf.all.accept_source_route
net.ipv4.conf.default.accept_source_route
net.ipv4.icmp_echo_ignore_broadcasts
net.ipv4.icmp_ignore_bogus_error_responses
net.ipv4.tcp_syncookies
net.ipv6.conf.all.accept_redirects
net.ipv6.conf.default.accept_redirects
net.ipv6.conf.all.accept_source_route
net.ipv6.conf.default.accept_source_route
KEYS
    for dir in /proc/sys/net/ipv4/conf/*; do
        [[ -d $dir ]] || continue; iface=${dir##*/}; safe_iface "$iface" || continue
        for key in rp_filter accept_redirects secure_redirects send_redirects accept_source_route; do
            value=$(sysctl -n -- "net/ipv4/conf/$iface/$key" 2>/dev/null || printf UNAVAILABLE)
            printf 'net/ipv4/conf/%s/%s=%s\n' "$iface" "$key" "$value" >>"$out"
        done
    done
    for dir in /proc/sys/net/ipv6/conf/*; do
        [[ -d $dir ]] || continue; iface=${dir##*/}; safe_iface "$iface" || continue
        for key in accept_redirects accept_source_route; do
            value=$(sysctl -n -- "net/ipv6/conf/$iface/$key" 2>/dev/null || printf UNAVAILABLE)
            printf 'net/ipv6/conf/%s/%s=%s\n' "$iface" "$key" "$value" >>"$out"
        done
    done
    chain=$(nft list chain inet firewalld filter_FORWARD 2>/dev/null || true)
    printf 'forward_chain_sha256=%s\n' "$(printf '%s' "$chain" | sha256sum | awk '{print $1}')" >>"$out"
}

wordset_equals() {
    local actual=$1 expected=$2
    [[ $(tr ' ' '\n' <<<"$actual" | sed '/^$/d' | LC_ALL=C sort | tr '\n' ' ') == \
       $(tr ' ' '\n' <<<"$expected" | sed '/^$/d' | LC_ALL=C sort | tr '\n' ' ') ]]
}

zone_runtime_target() {
    local zone=$1 data target count
    data=$(firewall-cmd --zone="$zone" --list-all) || return 1
    target=$(awk '
      $1=="target:" { value=$2; count++ }
      END { if (count==1 && value ~ /^(default|ACCEPT|DROP|REJECT)$/) print value; else exit 1 }
    ' <<<"$data") || return 1
    printf '%s' "$target"
}

zone_permanent_target() {
    local zone=$1 target
    target=$(firewall-cmd --permanent --zone="$zone" --get-target) || return 1
    [[ $target =~ ^(default|ACCEPT|DROP|REJECT)$ ]] || return 1
    printf '%s' "$target"
}

runtime_matches_desired() {
    local key value dir iface services chain z actual
    [[ " $(firewall-cmd --get-zones) " == *" $PUBLIC_ZONE "* && " $(firewall-cmd --get-zones) " == *" $LAN_ZONE "* ]] || return 1
    [[ $(firewall-cmd --get-default-zone) == "$PUBLIC_ZONE" ]] || return 1
    for z in "$PUBLIC_ZONE" "$LAN_ZONE"; do
        [[ $(zone_permanent_target "$z") == default ]] || return 1
        [[ $(zone_runtime_target "$z") == default ]] || return 1
        [[ -z $(firewall-cmd --zone="$z" --list-ports) ]] || return 1
        for value in --list-source-ports --list-protocols --list-forward-ports --list-rich-rules --list-sources --list-icmp-blocks; do
            actual=$(firewall-cmd --zone="$z" "$value") || return 1
            [[ -z $actual ]] || return 1
        done
        firewall-cmd --zone="$z" --query-forward >/dev/null && return 1
        firewall-cmd --zone="$z" --query-masquerade >/dev/null && return 1
        firewall-cmd --zone="$z" --query-icmp-block-inversion >/dev/null && return 1
    done
    nm_profile_property_read connection.zone "$PROFILE_UUID" || return 1
    [[ $(normalize_nm_zone "$NM_VALUE") == "$LAN_ZONE" ]] || return 1
    nm_profile_property_read connection.llmnr "$PROFILE_UUID" || return 1
    [[ $(normalize_nm_enum "$NM_VALUE") == no ]] || return 1
    nm_profile_property_read connection.mdns "$PROFILE_UUID" || return 1
    [[ $(normalize_nm_enum "$NM_VALUE") == resolve ]] || return 1
    [[ $(firewall-cmd --get-zone-of-interface="$PROFILE_DEVICE") == "$LAN_ZONE" ]] || return 1
    services=$(firewall-cmd --zone="$PUBLIC_ZONE" --list-services); wordset_equals "$services" 'dhcpv6-client' || return 1
    services=$(firewall-cmd --zone="$LAN_ZONE" --list-services); wordset_equals "$services" 'dhcpv6-client ipp-client mdns ws-discovery-client' || return 1
    firewall-cmd --zone="$PUBLIC_ZONE" --query-forward >/dev/null && return 1
    firewall-cmd --zone="$LAN_ZONE" --query-forward >/dev/null && return 1
    while IFS='=' read -r key value; do
        key=${key% }; value=${value# }
        [[ -n $key && $key != \#* ]] || continue
        [[ $key == *'*'* || $key == *'?'* || $key == *'['* ]] && continue
        [[ $(sysctl -n -- "$key" 2>/dev/null) == "$value" ]] || return 1
    done <"$PLAN_DIR/91-aegis-network-hardening.conf"
    [[ $(sysctl -n -- "net/ipv4/conf/$PROFILE_DEVICE/rp_filter") == 2 ]] || return 1
    for dir in /proc/sys/net/ipv4/conf/*; do
        [[ -d $dir ]] || continue; iface=${dir##*/}; safe_iface "$iface" || continue
        for key in accept_redirects secure_redirects send_redirects accept_source_route; do
            [[ $(sysctl -n -- "net/ipv4/conf/$iface/$key") == 0 ]] || return 1
        done
    done
    for dir in /proc/sys/net/ipv6/conf/*; do
        [[ -d $dir ]] || continue; iface=${dir##*/}; safe_iface "$iface" || continue
        [[ $(sysctl -n -- "net/ipv6/conf/$iface/accept_redirects") == 0 ]] || return 1
        [[ $(sysctl -n -- "net/ipv6/conf/$iface/accept_source_route") == -1 ]] || return 1
    done
    chain=$(nft list chain inet firewalld filter_FORWARD 2>/dev/null || true)
    [[ $chain != *'ct status dnat accept'* && $chain != *'ct status 0x20 accept'* ]] || return 1
}

build_plan() {
    local current_default no_op=true runtime_hash managed_uuid='' managed_device=''
    select_profile
    validate_other_profiles
    require_firewalld_services
    validate_local_firewalld_extensions
    validate_managed_destinations
    build_candidates
    current_default=$(firewall-cmd --get-default-zone)
    collect_runtime_fingerprint "$PLAN_DIR/current-runtime.txt"
    runtime_hash=$(hash_file "$PLAN_DIR/current-runtime.txt")
    [[ $(current_hash_or_absent "$FIREWALL_CONF") == "$(hash_file "$PLAN_DIR/firewalld.conf")" ]] || no_op=false
    [[ $(current_hash_or_absent "$PUBLIC_ZONE_FILE") == "$(hash_file "$PLAN_DIR/aegis-public.xml")" ]] || no_op=false
    [[ $(current_hash_or_absent "$LAN_ZONE_FILE") == "$(hash_file "$PLAN_DIR/aegis-lan.xml")" ]] || no_op=false
    [[ $(current_hash_or_absent "$SYSCTL_FILE") == "$(hash_file "$PLAN_DIR/91-aegis-network-hardening.conf")" ]] || no_op=false
    [[ $(current_hash_or_absent "$NM_CONF_FILE") == "$(hash_file "$PLAN_DIR/90-aegis-network-hardening.conf")" ]] || no_op=false
    runtime_matches_desired || no_op=false
    if managed_identity_is_committed; then
        [[ -f $MANAGED_ROOT/profile.uuid && ! -L $MANAGED_ROOT/profile.uuid ]] && managed_uuid=$(<"$MANAGED_ROOT/profile.uuid")
        [[ -f $MANAGED_ROOT/profile.device && ! -L $MANAGED_ROOT/profile.device ]] && managed_device=$(<"$MANAGED_ROOT/profile.device")
    fi
    [[ $managed_uuid == "$PROFILE_UUID" && $managed_device == "$PROFILE_DEVICE" ]] || no_op=false

    PLAN_JSON=$PLAN_DIR/plan.json
    jq -n -S \
      --arg version "$VERSION" --arg uuid "$PROFILE_UUID" --arg device "$PROFILE_DEVICE" \
      --arg old_default "$current_default" --arg old_zone "$PROFILE_OLD_ZONE" --arg old_llmnr "$PROFILE_OLD_LLMNR" --arg old_mdns "$PROFILE_OLD_MDNS" \
      --arg firewall "$(hash_file "$PLAN_DIR/firewalld.conf")" --arg public "$(hash_file "$PLAN_DIR/aegis-public.xml")" \
      --arg lan "$(hash_file "$PLAN_DIR/aegis-lan.xml")" --arg sysctl "$(hash_file "$PLAN_DIR/91-aegis-network-hardening.conf")" \
      --arg nm "$(hash_file "$PLAN_DIR/90-aegis-network-hardening.conf")" --arg runtime "$runtime_hash" --argjson noop "$no_op" \
      '{version:$version,profile:{uuid:$uuid,device:$device,old_default_zone:$old_default,old_connection_zone:$old_zone,old_llmnr:$old_llmnr,old_mdns:$old_mdns},desired:{default_zone:"aegis-public",connection_zone:"aegis-lan",llmnr:"no",mdns:"resolve",firewalld_conf_sha256:$firewall,public_zone_sha256:$public,lan_zone_sha256:$lan,sysctl_sha256:$sysctl,nm_conf_sha256:$nm},runtime_fingerprint_sha256:$runtime,no_op:$noop}' >"$PLAN_JSON"
    PLAN_HASH=$(sha256sum -- "$PLAN_JSON" | awk '{print $1}')
}

print_plan() {
    local noop
    noop=$(jq -r '.no_op' "$PLAN_JSON")
    say "AEGIS Network Hardening $VERSION | PLAN_SHA256=$PLAN_HASH"
    say "Selected physical profile UUID: $PROFILE_UUID"
    say "Selected device: $PROFILE_DEVICE"
    say "Default zone: $(jq -r '.profile.old_default_zone' "$PLAN_JSON") -> $PUBLIC_ZONE"
    say "Selected profile zone: ${PROFILE_OLD_ZONE:-<default>} -> $LAN_ZONE"
    say "Name resolution: LLMNR ${PROFILE_OLD_LLMNR:-default} -> no; mDNS ${PROFILE_OLD_MDNS:-default} -> resolve-only"
    section 'REAL HARDENING CHANGES'
    say '- Install two AEGIS-owned native firewalld zones. Unmatched application traffic is rejected; ICMP remains available.'
    say '- Remove blanket high ports, SSH and Samba/NetBIOS from the selected physical profile.'
    say '- Preserve printer discovery/client traffic only: mDNS, IPP-client and WS-Discovery-client.'
    say '- Make aegis-public the fallback/default and bind only the reviewed profile UUID to aegis-lan.'
    say '- Keep firewalld+nftables as sole owner; StrictForwardPorts blocks implicit container-published DNAT.'
    say '- Disable denied-packet flood logging/counters; preserve combined restore calls and conservative flowtable=off.'
    say '- Disable NetworkManager/systemd-resolved LLMNR by default and use mDNS resolve-only on the reviewed profile; Avahi remains for printer discovery.'
    say '- Harden redirect/source-route sysctls and apply loose RPF only to the selected/default physical path without owning forwarding, BBR, MTU, RA or VPN marks.'
    say "- Start an independent ${ROLLBACK_SECONDS}-second systemd rollback guard before publishing changes."
    section 'INTENTIONALLY NOT DONE'
    say '- No legacy lockdown whitelist, iptables/direct rules, ICMP blackout, Docker start, DNS-over-TLS claim or speed benchmark.'
    say '- No outbound application allowlist: that requires a separate application-egress policy and inventory.'
    [[ $noop == true ]] && say 'NO-OP: files, runtime state and managed profile identity already match.'
    return 0
}

confirm_apply() {
    local expected="APPLY $PLAN_HASH" answer
    if [[ -n $APPROVE ]]; then [[ $APPROVE == "$PLAN_HASH" ]] || die 'Approval digest differs from the current plan'; return 0; fi
    [[ -r /dev/tty && -w /dev/tty ]] || die 'No controlling terminal; use --approve with the reviewed PLAN_SHA256'
    printf 'Type exactly "%s" to continue: ' "$expected" >/dev/tty
    IFS= read -r answer </dev/tty || die 'Cannot read confirmation'
    [[ $answer == "$expected" ]] || die 'Cancelled; no configuration changes made'
}

prepare_state_root() {
    install -d -o root -g root -m 0700 "$STATE_ROOT" "$TX_ROOT" "$MANAGED_ROOT"
    restorecon -RF "$STATE_ROOT" >/dev/null 2>&1 || true
}

snapshot_path() {
    local path=$1 label=$2 kind target
    install -d -m 0700 "$TX_DIR/before"
    if [[ -L $path ]]; then
        kind=symlink; target=$(readlink -- "$path")
        printf '%s\n' "$kind" >"$TX_DIR/before/$label.kind"
        printf '%s\n' "$target" >"$TX_DIR/before/$label.target"
        if [[ $label == firewalld-conf ]]; then
            local resolved
            resolved=$(readlink -f -- "$path")
            check_file "$resolved" || die 'Cannot snapshot resolved vendor firewalld.conf'
            cp --preserve=mode,ownership,timestamps -- "$resolved" "$TX_DIR/before/$label.resolved"
        fi
    elif [[ -f $path ]]; then
        printf 'regular\n' >"$TX_DIR/before/$label.kind"
        cp --preserve=mode,ownership,timestamps -- "$path" "$TX_DIR/before/$label.file"
    elif [[ ! -e $path ]]; then
        printf 'absent\n' >"$TX_DIR/before/$label.kind"
    else
        die "Unsupported managed path type: $path"
    fi
}

ensure_secure_parent() {
    local parent=$1
    if [[ -d $parent && ! -L $parent ]]; then
        check_dir "$parent" || return 1
    elif [[ ! -e $parent && ! -L $parent ]]; then
        install -d -o root -g root -m 0755 "$parent" || return 1
        check_dir "$parent" || return 1
    else
        return 1
    fi
}

atomic_publish() {
    local src=$1 dest=$2 mode=$3 parent tmp
    parent=${dest%/*}
    ensure_secure_parent "$parent" || return 1
    tmp=$(mktemp "$parent/.aegis-network.XXXXXXXX") || return 1
    install -o root -g root -m "$mode" -- "$src" "$tmp" || { rm -f -- "$tmp"; return 1; }
    restorecon "$tmp" >/dev/null 2>&1 || true
    sync -f "$tmp" || { rm -f -- "$tmp"; return 1; }
    mv -Tf -- "$tmp" "$dest" || { rm -f -- "$tmp"; return 1; }
    restorecon "$dest" >/dev/null 2>&1 || true
    sync -f "$parent"
}

restore_path() {
    local path=$1 label=$2 kind target parent tmp
    kind=$(<"$TX_DIR/before/$label.kind")
    parent=${path%/*}; ensure_secure_parent "$parent" || return 1
    case $kind in
      absent) rm -f -- "$path";;
      regular)
        tmp=$(mktemp "$parent/.aegis-restore.XXXXXXXX") || return 1
        cp --preserve=mode,ownership,timestamps -- "$TX_DIR/before/$label.file" "$tmp" || { rm -f -- "$tmp"; return 1; }
        sync -f "$tmp" || { rm -f -- "$tmp"; return 1; }
        mv -Tf -- "$tmp" "$path" || { rm -f -- "$tmp"; return 1; }
        ;;
      symlink)
        target=$(<"$TX_DIR/before/$label.target")
        [[ $target != /* && $target != *'..'* && $target != *$'\n'* ]] || return 1
        if [[ -f $TX_DIR/before/$label.resolved ]] && { [[ ! -f $parent/$target ]] || [[ $(hash_file "$parent/$target") != $(hash_file "$TX_DIR/before/$label.resolved") ]]; }; then
            tmp=$(mktemp "$parent/.aegis-restore.XXXXXXXX") || return 1
            cp --preserve=mode,ownership,timestamps -- "$TX_DIR/before/$label.resolved" "$tmp" || { rm -f -- "$tmp"; return 1; }
            sync -f "$tmp" || { rm -f -- "$tmp"; return 1; }
            mv -Tf -- "$tmp" "$path" || { rm -f -- "$tmp"; return 1; }
        else
            tmp=$(mktemp "$parent/.aegis-link.XXXXXXXX") || return 1
            rm -f -- "$tmp" || return 1
            ln -s -- "$target" "$tmp" || return 1
            mv -Tf -- "$tmp" "$path" || { rm -f -- "$tmp"; return 1; }
        fi
        ;;
      *) return 1;;
    esac
    restorecon "$path" >/dev/null 2>&1 || true
    sync -f "$parent"
}

snapshot_sysctls() {
    local key value dir iface
    : >"$TX_DIR/before/sysctl-live.tsv"
    while IFS= read -r key; do
        value=$(sysctl -n -- "$key") || die "Cannot snapshot sysctl $key"
        printf '%s\t%s\n' "$key" "$value" >>"$TX_DIR/before/sysctl-live.tsv"
    done <<'KEYS'
net.ipv4.conf.default.rp_filter
net.ipv4.conf.all.accept_redirects
net.ipv4.conf.default.accept_redirects
net.ipv4.conf.all.secure_redirects
net.ipv4.conf.default.secure_redirects
net.ipv4.conf.all.send_redirects
net.ipv4.conf.default.send_redirects
net.ipv4.conf.all.accept_source_route
net.ipv4.conf.default.accept_source_route
net.ipv4.icmp_echo_ignore_broadcasts
net.ipv4.icmp_ignore_bogus_error_responses
net.ipv4.tcp_syncookies
net.ipv6.conf.all.accept_redirects
net.ipv6.conf.default.accept_redirects
net.ipv6.conf.all.accept_source_route
net.ipv6.conf.default.accept_source_route
KEYS
    for dir in /proc/sys/net/ipv4/conf/*; do
        [[ -d $dir ]] || continue; iface=${dir##*/}; safe_iface "$iface" || continue
        for key in rp_filter accept_redirects secure_redirects send_redirects accept_source_route; do
            value=$(sysctl -n -- "net/ipv4/conf/$iface/$key") || die 'Cannot snapshot interface IPv4 sysctl'
            printf 'net/ipv4/conf/%s/%s\t%s\n' "$iface" "$key" "$value" >>"$TX_DIR/before/sysctl-live.tsv"
        done
    done
    for dir in /proc/sys/net/ipv6/conf/*; do
        [[ -d $dir ]] || continue; iface=${dir##*/}; safe_iface "$iface" || continue
        for key in accept_redirects accept_source_route; do
            value=$(sysctl -n -- "net/ipv6/conf/$iface/$key") || die 'Cannot snapshot interface IPv6 sysctl'
            printf 'net/ipv6/conf/%s/%s\t%s\n' "$iface" "$key" "$value" >>"$TX_DIR/before/sysctl-live.tsv"
        done
    done
}

write_tx_status() {
    local value=$1 tmp
    [[ -n $TX_DIR && -d $TX_DIR ]] || return 1
    tmp=$(mktemp "$TX_DIR/.status.XXXXXXXX") || return 1
    printf '%s\n' "$value" >"$tmp"
    chmod 0600 "$tmp"; chown root:root "$tmp"; sync -f "$tmp"
    mv -Tf "$tmp" "$TX_DIR/status"; sync -f "$TX_DIR"
}

ensure_no_incomplete_transactions() {
    local d st
    for d in "$TX_ROOT"/.prepare-*; do
        [[ -e $d ]] || continue
        die "Unpublished transaction preparation remains: $d"
    done
    for d in "$TX_ROOT"/T-*; do
        [[ -d $d ]] || continue
        if [[ -r $d/status ]]; then st=$(<"$d/status"); else st=UNKNOWN; fi
        case $st in COMMITTED|ROLLED_BACK) ;; *) die "Unresolved transaction $d status=$st; inspect/rollback before a new apply";; esac
    done
}

snapshot_transaction() {
    local now rand_full rand prepare final
    now=$(date -u +%Y%m%dT%H%M%SZ)
    rand_full=$(head -c 32 /dev/urandom | sha256sum | awk '{print $1}')
    rand=${rand_full:0:12}
    TX_ID="T-$now-$rand"; safe_tx_id "$TX_ID" || die 'Generated unsafe transaction id'
    prepare="$TX_ROOT/.prepare-$TX_ID"; final="$TX_ROOT/$TX_ID"
    install -d -o root -g root -m 0700 "$prepare"
    TX_DIR=$prepare
    printf '%s\n' "$PLAN_HASH" >"$TX_DIR/plan.sha256"
    cp -- "$PLAN_JSON" "$TX_DIR/plan.json"
    printf '%s\n' "$PROFILE_UUID" >"$TX_DIR/profile.uuid"
    printf '%s\n' "$PROFILE_DEVICE" >"$TX_DIR/profile.device"
    printf '%s\n' "$PROFILE_OLD_ZONE" >"$TX_DIR/profile.old-zone"
    printf '%s\n' "$PROFILE_OLD_LLMNR" >"$TX_DIR/profile.old-llmnr"
    printf '%s\n' "$PROFILE_OLD_MDNS" >"$TX_DIR/profile.old-mdns"
    printf '%s\n' "$(cat /proc/sys/kernel/random/boot_id)" >"$TX_DIR/boot-id"
    printf '%s\n' "$$" >"$TX_DIR/owner.pid"
    snapshot_path "$FIREWALL_CONF" firewalld-conf
    snapshot_path "$PUBLIC_ZONE_FILE" public-zone
    snapshot_path "$LAN_ZONE_FILE" lan-zone
    snapshot_path "$SYSCTL_FILE" sysctl-file
    snapshot_path "$NM_CONF_FILE" nm-conf
    snapshot_path "$MANAGED_ROOT/profile.uuid" managed-profile-uuid
    snapshot_path "$MANAGED_ROOT/profile.device" managed-profile-device
    snapshot_path "$MANAGED_ROOT/latest-transaction" managed-latest-transaction
    snapshot_sysctls
    write_tx_status PREPARED
    sync -f "$TX_DIR"
    mv -T "$prepare" "$final"
    sync -f "$TX_ROOT"
    TX_DIR=$final
    TX_ACTIVE=1
}

schedule_guard() {
    GUARD_UNIT="aegis-network-rollback-${TX_ID#T-}"
    GUARD_UNIT=${GUARD_UNIT//[^A-Za-z0-9_.-]/-}
    timeout 15 systemd-run --quiet --collect --unit="$GUARD_UNIT" --on-active="${ROLLBACK_SECONDS}s" \
      --property=Type=oneshot --property=TimeoutStartSec=120 --property=UMask=0077 \
      --property=NoNewPrivileges=yes --property=ProtectHome=yes --property=PrivateTmp=yes \
      /usr/bin/bash -p -- "$INSTALL_PATH" emergency-rollback "$TX_ID" || die 'Cannot schedule independent rollback guard'
    printf '%s\n' "$GUARD_UNIT" >"$TX_DIR/guard.unit"
}

cancel_guard() {
    [[ -n $GUARD_UNIT ]] || return 0
    systemctl stop "$GUARD_UNIT.timer" "$GUARD_UNIT.service" >/dev/null 2>&1 || true
    systemctl reset-failed "$GUARD_UNIT.timer" "$GUARD_UNIT.service" >/dev/null 2>&1 || true
}

apply_interface_sysctls() {
    local dir iface key value
    # /etc/sysctl.d is parsed at boot by systemd-sysctl, which supports globs
    # and reapplies network-interface patterns when links appear. procps sysctl
    # --load is not used for this generated file because its loader is not the
    # persistence authority for systemd's glob semantics. Apply exact keys now,
    # then explicitly cover every currently present interface below.
    while IFS='=' read -r key value; do
        key=${key% }; value=${value# }
        [[ -n $key && $key != \#* ]] || continue
        [[ $key == *'*'* || $key == *'?'* || $key == *'['* ]] && continue
        sysctl -q -w "$key=$value"
    done <"$SYSCTL_FILE"
    sysctl -q -w "net/ipv4/conf/$PROFILE_DEVICE/rp_filter=2"
    for dir in /proc/sys/net/ipv4/conf/*; do
        [[ -d $dir ]] || continue; iface=${dir##*/}; safe_iface "$iface" || continue
        sysctl -q -w "net/ipv4/conf/$iface/accept_redirects=0" \
          "net/ipv4/conf/$iface/secure_redirects=0" \
          "net/ipv4/conf/$iface/send_redirects=0" \
          "net/ipv4/conf/$iface/accept_source_route=0"
    done
    for dir in /proc/sys/net/ipv6/conf/*; do
        [[ -d $dir ]] || continue; iface=${dir##*/}; safe_iface "$iface" || continue
        sysctl -q -w "net/ipv6/conf/$iface/accept_redirects=0" \
          "net/ipv6/conf/$iface/accept_source_route=-1"
    done
}

publish_candidates() {
    atomic_publish "$PLAN_DIR/firewalld.conf" "$FIREWALL_CONF" 0644
    atomic_publish "$PLAN_DIR/aegis-public.xml" "$PUBLIC_ZONE_FILE" 0644
    atomic_publish "$PLAN_DIR/aegis-lan.xml" "$LAN_ZONE_FILE" 0644
    atomic_publish "$PLAN_DIR/91-aegis-network-hardening.conf" "$SYSCTL_FILE" 0644
    atomic_publish "$PLAN_DIR/90-aegis-network-hardening.conf" "$NM_CONF_FILE" 0644
    timeout 20 firewall-cmd --check-config >/dev/null
}

activate_policy() {
    timeout 45 firewall-cmd --reload >/dev/null
    systemctl is-active --quiet firewalld.service || return 1
    timeout 20 nmcli general reload conf
    timeout 20 nmcli connection modify uuid "$PROFILE_UUID" connection.zone "$LAN_ZONE" connection.llmnr no connection.mdns resolve
    timeout 30 nmcli --wait 20 device reapply "$PROFILE_DEVICE"
    apply_interface_sysctls
}

write_managed_file() {
    local path=$1 value=$2 tmp
    tmp=$(mktemp "$MANAGED_ROOT/.state.XXXXXXXX") || return 1
    printf '%s\n' "$value" >"$tmp"
    chmod 0600 "$tmp"; chown root:root "$tmp"; sync -f "$tmp"
    mv -Tf "$tmp" "$path"; sync -f "$MANAGED_ROOT"
}

managed_identity_is_committed() {
    local id status
    [[ -f $MANAGED_ROOT/latest-transaction && ! -L $MANAGED_ROOT/latest-transaction ]] || return 1
    id=$(<"$MANAGED_ROOT/latest-transaction")
    safe_tx_id "$id" || return 1
    [[ -f $TX_ROOT/$id/status && ! -L $TX_ROOT/$id/status ]] || return 1
    status=$(<"$TX_ROOT/$id/status")
    [[ $status == COMMITTED ]]
}

save_managed_identity() {
    write_managed_file "$MANAGED_ROOT/profile.uuid" "$PROFILE_UUID"
    write_managed_file "$MANAGED_ROOT/profile.device" "$PROFILE_DEVICE"
    write_managed_file "$MANAGED_ROOT/latest-transaction" "$TX_ID"
}

read_managed_identity() {
    managed_identity_is_committed || die 'No committed AEGIS Network profile identity exists'
    [[ -f $MANAGED_ROOT/profile.uuid && ! -L $MANAGED_ROOT/profile.uuid && -f $MANAGED_ROOT/profile.device && ! -L $MANAGED_ROOT/profile.device ]] || die 'Committed managed profile identity files are missing/unsafe'
    PROFILE_UUID=$(<"$MANAGED_ROOT/profile.uuid"); PROFILE_DEVICE=$(<"$MANAGED_ROOT/profile.device")
    safe_uuid "$PROFILE_UUID" && safe_iface "$PROFILE_DEVICE" || die 'Managed profile identity is corrupt'
}

verify_file_hash() { [[ -f $2 && ! -L $2 && $(hash_file "$2") == "$(hash_file "$1")" ]]; }

active_device_for_uuid() {
    local uuid dev rows
    if ! rows=$(timeout 20 nmcli -t -e no -f UUID,DEVICE connection show --active 2>/dev/null); then
        return 2
    fi
    while IFS=: read -r uuid dev; do
        [[ $uuid == "$PROFILE_UUID" ]] || continue
        safe_iface "$dev" || return 2
        printf '%s' "$dev"
        return 0
    done <<< "$rows"
    return 1
}

verify_hardening() {
    local fail=0 entry expected actual z services ports target value dir iface chain active_device
    require_platform
    if [[ -z $PROFILE_UUID || -z $PROFILE_DEVICE ]]; then
        read_managed_identity
    else
        safe_uuid "$PROFILE_UUID" && safe_iface "$PROFILE_DEVICE" || die 'In-memory managed profile identity is corrupt'
    fi
    require_firewalld_services
    timeout 20 firewall-cmd --check-config >/dev/null || die 'Permanent firewalld configuration failed native validation'
    build_candidates
    section 'Managed file verification'
    while IFS='|' read -r expected actual; do
        if verify_file_hash "$expected" "$actual"; then say "OK $actual"; else say "FAIL $actual"; fail=1; fi
    done <<EOF_FILES
$PLAN_DIR/firewalld.conf|$FIREWALL_CONF
$PLAN_DIR/aegis-public.xml|$PUBLIC_ZONE_FILE
$PLAN_DIR/aegis-lan.xml|$LAN_ZONE_FILE
$PLAN_DIR/91-aegis-network-hardening.conf|$SYSCTL_FILE
$PLAN_DIR/90-aegis-network-hardening.conf|$NM_CONF_FILE
EOF_FILES
    section 'firewalld and profile verification'
    [[ $(firewall-cmd --get-default-zone) == "$PUBLIC_ZONE" ]] || { say 'FAIL default zone'; fail=1; }
    for z in "$PUBLIC_ZONE" "$LAN_ZONE"; do
        if target=$(zone_permanent_target "$z"); then
            [[ $target == default ]] || { say "FAIL $z permanent target=$target"; fail=1; }
        else
            say "FAIL $z permanent target unreadable"; fail=1
        fi
        if target=$(zone_runtime_target "$z"); then
            [[ $target == default ]] || { say "FAIL $z runtime target=$target"; fail=1; }
        else
            say "FAIL $z runtime target unreadable"; fail=1
        fi
        ports=$(firewall-cmd --zone="$z" --list-ports)
        [[ -z $ports ]] || { say "FAIL $z unexpected ports: $ports"; fail=1; }
        if firewall-cmd --zone="$z" --query-forward >/dev/null; then say "FAIL $z intra-zone forward enabled"; fail=1; fi
        for value in --list-source-ports --list-protocols --list-forward-ports --list-rich-rules --list-sources --list-icmp-blocks; do
            actual=$(firewall-cmd --zone="$z" "$value")
            [[ -z $actual ]] || { say "FAIL $z unexpected runtime $value: $actual"; fail=1; }
        done
        if firewall-cmd --zone="$z" --query-masquerade >/dev/null; then say "FAIL $z masquerade enabled"; fail=1; fi
        if firewall-cmd --zone="$z" --query-icmp-block-inversion >/dev/null; then say "FAIL $z ICMP inversion enabled"; fail=1; fi
    done
    services=$(firewall-cmd --zone="$PUBLIC_ZONE" --list-services)
    wordset_equals "$services" 'dhcpv6-client' || { say "FAIL public services: $services"; fail=1; }
    services=$(firewall-cmd --zone="$LAN_ZONE" --list-services)
    wordset_equals "$services" 'dhcpv6-client ipp-client mdns ws-discovery-client' || { say "FAIL LAN services: $services"; fail=1; }
    if nm_profile_property_read connection.zone "$PROFILE_UUID"; then
        [[ $(normalize_nm_zone "$NM_VALUE") == "$LAN_ZONE" ]] || { say 'FAIL profile zone'; fail=1; }
    else say 'FAIL cannot read profile zone'; fail=1; fi
    if nm_profile_property_read connection.llmnr "$PROFILE_UUID"; then
        [[ $(normalize_nm_enum "$NM_VALUE") == no ]] || { say 'FAIL profile LLMNR'; fail=1; }
    else say 'FAIL cannot read profile LLMNR'; fail=1; fi
    if nm_profile_property_read connection.mdns "$PROFILE_UUID"; then
        [[ $(normalize_nm_enum "$NM_VALUE") == resolve ]] || { say 'FAIL profile mDNS'; fail=1; }
    else say 'FAIL cannot read profile mDNS'; fail=1; fi
    local active_rc=0
    if active_device=$(active_device_for_uuid); then
        :
    else
        active_rc=$?
        active_device=''
        if (( active_rc == 2 )); then say 'FAIL NetworkManager active-connection inventory'; fail=1; fi
    fi
    if [[ -n $active_device ]]; then
        PROFILE_DEVICE=$active_device
        [[ $(firewall-cmd --get-zone-of-interface="$PROFILE_DEVICE") == "$LAN_ZONE" ]] || { say 'FAIL active device zone'; fail=1; }
    else
        say 'INFO: managed LAN profile is currently inactive; persistent UUID policy is verified and active connections fall back to aegis-public unless explicitly classified.'
    fi
    chain=$(nft list chain inet firewalld filter_FORWARD 2>/dev/null || true)
    [[ $chain != *'ct status dnat accept'* && $chain != *'ct status 0x20 accept'* ]] || { say 'FAIL generic DNAT accept remains; StrictForwardPorts is not effective'; fail=1; }
    section 'sysctl verification'
    while IFS='=' read -r expected actual; do
        expected=${expected% }; actual=${actual# }
        [[ -n $expected && $expected != \#* ]] || continue
        [[ $expected == *'*'* || $expected == *'?'* || $expected == *'['* ]] && continue
        [[ $(sysctl -n -- "$expected") == "$actual" ]] || { say "FAIL $expected"; fail=1; }
    done <"$SYSCTL_FILE"
    if [[ -n $active_device && -e /proc/sys/net/ipv4/conf/$PROFILE_DEVICE/rp_filter ]]; then
        [[ $(sysctl -n -- "net/ipv4/conf/$PROFILE_DEVICE/rp_filter") == 2 ]] || { say "FAIL $PROFILE_DEVICE rp_filter"; fail=1; }
    fi
    for dir in /proc/sys/net/ipv4/conf/*; do
        [[ -d $dir ]] || continue; iface=${dir##*/}; safe_iface "$iface" || continue
        for value in accept_redirects secure_redirects send_redirects accept_source_route; do
            [[ $(sysctl -n -- "net/ipv4/conf/$iface/$value") == 0 ]] || { say "FAIL $iface $value"; fail=1; }
        done
    done
    for dir in /proc/sys/net/ipv6/conf/*; do
        [[ -d $dir ]] || continue; iface=${dir##*/}; safe_iface "$iface" || continue
        [[ $(sysctl -n -- "net/ipv6/conf/$iface/accept_redirects") == 0 ]] || { say "FAIL $iface IPv6 redirect"; fail=1; }
        [[ $(sysctl -n -- "net/ipv6/conf/$iface/accept_source_route") == -1 ]] || { say "FAIL $iface IPv6 source route"; fail=1; }
    done
    if [[ -n $active_device ]]; then
        nmcli -t -f DEVICE,STATE device status | grep -Fqx "$PROFILE_DEVICE:connected" || { say 'FAIL selected device is not connected'; fail=1; }
        { ip -4 route show default | grep -Fq "dev $PROFILE_DEVICE" || ip -6 route show default | grep -Fq "dev $PROFILE_DEVICE"; } || { say 'FAIL selected device has no default route'; fail=1; }
    fi
    if (( fail == 0 )); then say 'VERIFIED: AEGIS zones, profile binding, strict DNAT gate and managed sysctls are active/persistent.'; return 0; fi
    return 3
}

restore_nm_property() {
    local property=$1 value=$2
    case $property in
      connection.zone) timeout 20 nmcli connection modify uuid "$PROFILE_UUID" "$property" "$value";;
      connection.llmnr|connection.mdns) timeout 20 nmcli connection modify uuid "$PROFILE_UUID" "$property" "${value:-default}";;
      *) return 1;;
    esac
}

restore_live_sysctls() {
    local key value
    [[ -f $TX_DIR/before/sysctl-live.tsv ]] || return 1
    while IFS=$'\t' read -r key value; do
        [[ $key =~ ^net[./][A-Za-z0-9_./:-]+$ && $value =~ ^-?[0-9]+$ ]] || return 1
        sysctl -q -w "$key=$value" || return 1
    done <"$TX_DIR/before/sysctl-live.tsv"
}

emergency_restore() {
    local dir=$1 reason=${2:-manual} allow_committed=${3:-0} status uuid device old_zone old_llmnr old_mdns rc=0
    [[ -d $dir && ! -L $dir ]] || return 1
    TX_DIR=$dir
    if [[ -r $TX_DIR/status ]]; then status=$(<"$TX_DIR/status"); else status=UNKNOWN; fi
    case $status in
      ROLLED_BACK) return 0;;
      COMMITTED)
        (( allow_committed == 1 )) || return 0
        check_rollback_conflicts || { printf 'ROLLBACK_CONFLICT: managed files/profile changed after commit.\n' >&2; return 1; }
        ;;
      PREPARED|APPLYING|FAILED|ROLLING_BACK) ;;
      *) return 1;;
    esac
    write_tx_status ROLLING_BACK
    uuid=$(<"$TX_DIR/profile.uuid"); device=$(<"$TX_DIR/profile.device")
    safe_uuid "$uuid" && safe_iface "$device" || return 1
    PROFILE_UUID=$uuid; PROFILE_DEVICE=$device
    old_zone=$(<"$TX_DIR/profile.old-zone"); old_llmnr=$(<"$TX_DIR/profile.old-llmnr"); old_mdns=$(<"$TX_DIR/profile.old-mdns")
    restore_path "$FIREWALL_CONF" firewalld-conf || rc=1
    restore_path "$PUBLIC_ZONE_FILE" public-zone || rc=1
    restore_path "$LAN_ZONE_FILE" lan-zone || rc=1
    restore_path "$SYSCTL_FILE" sysctl-file || rc=1
    restore_path "$NM_CONF_FILE" nm-conf || rc=1
    restore_path "$MANAGED_ROOT/profile.uuid" managed-profile-uuid || rc=1
    restore_path "$MANAGED_ROOT/profile.device" managed-profile-device || rc=1
    restore_path "$MANAGED_ROOT/latest-transaction" managed-latest-transaction || rc=1
    timeout 20 firewall-offline-cmd --check-config >/dev/null 2>&1 || rc=1
    if systemctl is-active --quiet firewalld.service; then
        timeout 45 firewall-cmd --reload >/dev/null 2>&1 || timeout 45 systemctl restart firewalld.service || rc=1
    else
        timeout 45 systemctl start firewalld.service || rc=1
    fi
    timeout 20 nmcli general reload conf || rc=1
    restore_nm_property connection.zone "$old_zone" || rc=1
    restore_nm_property connection.llmnr "$old_llmnr" || rc=1
    restore_nm_property connection.mdns "$old_mdns" || rc=1
    if nmcli -t -f UUID connection show --active | grep -Fqx "$PROFILE_UUID"; then
        timeout 30 nmcli --wait 20 device reapply "$PROFILE_DEVICE" || rc=1
    fi
    restore_live_sysctls || rc=1
    printf '%s\n' "$reason" >"$TX_DIR/rollback.reason"
    if (( rc == 0 )); then write_tx_status ROLLED_BACK; else write_tx_status FAILED; fi
    return "$rc"
}

save_after_state() {
    install -d -o root -g root -m 0700 "$TX_DIR/after"
    hash_file "$FIREWALL_CONF" >"$TX_DIR/after/firewalld-conf.sha256"
    hash_file "$PUBLIC_ZONE_FILE" >"$TX_DIR/after/public-zone.sha256"
    hash_file "$LAN_ZONE_FILE" >"$TX_DIR/after/lan-zone.sha256"
    hash_file "$SYSCTL_FILE" >"$TX_DIR/after/sysctl-file.sha256"
    hash_file "$NM_CONF_FILE" >"$TX_DIR/after/nm-conf.sha256"
    printf '%s\n' "$LAN_ZONE" >"$TX_DIR/after/profile.zone"
    printf 'no\n' >"$TX_DIR/after/profile.llmnr"
    printf 'resolve\n' >"$TX_DIR/after/profile.mdns"
    sync -f "$TX_DIR"
}

check_rollback_conflicts() {
    local path label expected
    while IFS='|' read -r path label; do
        [[ -f $path && ! -L $path ]] || return 1
        expected=$(<"$TX_DIR/after/$label.sha256")
        [[ $(hash_file "$path") == "$expected" ]] || return 1
    done <<EOF_CONFLICT
$FIREWALL_CONF|firewalld-conf
$PUBLIC_ZONE_FILE|public-zone
$LAN_ZONE_FILE|lan-zone
$SYSCTL_FILE|sysctl-file
$NM_CONF_FILE|nm-conf
EOF_CONFLICT
    nm_profile_property_read connection.zone "$PROFILE_UUID" || return 1
    [[ $(normalize_nm_zone "$NM_VALUE") == "$(<"$TX_DIR/after/profile.zone")" ]] || return 1
    nm_profile_property_read connection.llmnr "$PROFILE_UUID" || return 1
    [[ $(normalize_nm_enum "$NM_VALUE") == "$(<"$TX_DIR/after/profile.llmnr")" ]] || return 1
    nm_profile_property_read connection.mdns "$PROFILE_UUID" || return 1
    [[ $(normalize_nm_enum "$NM_VALUE") == "$(<"$TX_DIR/after/profile.mdns")" ]] || return 1
}

apply_hardening() {
    local noop
    require_platform
    require_local_recovery_session
    refuse_active_docker_for_apply
    require_installed_runtime
    acquire_lock
    prepare_state_root
    ensure_no_incomplete_transactions
    build_plan
    print_plan
    noop=$(jq -r '.no_op' "$PLAN_JSON")
    if [[ $noop == true ]]; then
        say 'NO-OP: no snapshot, file replacement, firewall reload or profile rewrite.'
        verify_hardening
        return
    fi
    confirm_apply
    snapshot_transaction
    write_tx_status APPLYING
    schedule_guard
    publish_candidates
    activate_policy
    save_after_state
    if verify_hardening; then
        save_managed_identity
        write_tx_status COMMITTED
        cancel_guard
        TX_ACTIVE=0
        say "COMMITTED: $TX_ID"
    else
        return 3
    fi
}

plan_hardening() {
    require_platform
    require_installed_runtime
    acquire_lock
    prepare_state_root
    ensure_no_incomplete_transactions
    build_plan
    print_plan
    if systemctl is-active --quiet docker.service || systemctl is-active --quiet docker.socket; then
        say 'BLOCKER: Docker is active; apply will refuse until the Docker isolation layer is integrated.'
    fi
}

status_hardening() {
    local tx='none' st='none'
    if [[ -f $MANAGED_ROOT/latest-transaction ]]; then tx=$(<"$MANAGED_ROOT/latest-transaction"); fi
    if safe_tx_id "$tx" && [[ -f $TX_ROOT/$tx/status ]]; then st=$(<"$TX_ROOT/$tx/status"); fi
    say "VERSION=$VERSION"
    say "LATEST_TRANSACTION=$tx"
    say "TRANSACTION_STATUS=$st"
    [[ -f $MANAGED_ROOT/profile.uuid ]] && say "PROFILE_UUID=$(<"$MANAGED_ROOT/profile.uuid")"
    [[ -f $MANAGED_ROOT/profile.device ]] && say "PROFILE_DEVICE=$(<"$MANAGED_ROOT/profile.device")"
    say "DEFAULT_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || printf UNKNOWN)"
}

history_hardening() {
    local d st
    [[ -d $TX_ROOT ]] || { say 'NO TRANSACTIONS'; return 0; }
    for d in "$TX_ROOT"/T-*; do
        [[ -d $d ]] || continue
        if [[ -r $d/status ]]; then st=$(<"$d/status"); else st=UNKNOWN; fi
        printf '%s %s\n' "${d##*/}" "$st"
    done | LC_ALL=C sort
}

require_rollback_host() {
    local id=''
    [[ -r /etc/os-release ]] || die 'Cannot identify rollback host'
    id=$(awk -F= '$1=="ID"{gsub(/^"|"$/,"",$2); print $2}' /etc/os-release)
    [[ $id == fedora ]] || die 'Rollback is restricted to a traditional Fedora host'
    [[ ! -e /run/ostree-booted && ! -e /run/bootc ]] || die 'Rollback does not support atomic/bootc hosts'
}

manual_rollback() {
    local id=${1-} dir hash expected answer
    require_rollback_host
    require_installed_runtime
    acquire_lock
    if [[ -z $id ]]; then
        [[ -f $MANAGED_ROOT/latest-transaction ]] || die 'No latest transaction'
        id=$(<"$MANAGED_ROOT/latest-transaction")
    fi
    safe_tx_id "$id" || die 'Invalid transaction id'
    dir=$TX_ROOT/$id; [[ -d $dir ]] || die 'Transaction not found'
    hash=$(sha256sum -- "$dir/plan.json" | awk '{print $1}')
    if systemctl is-active --quiet docker.service || systemctl is-active --quiet docker.socket; then
        say 'WARNING: Docker is active. Restoring the former firewalld policy can change published-port exposure; review the original plan before confirming.'
    fi
    expected="ROLLBACK $id $hash"
    if [[ -n $APPROVE ]]; then [[ $APPROVE == "$hash" ]] || die 'Rollback approval digest mismatch'; else
        [[ -r /dev/tty && -w /dev/tty ]] || die 'No controlling terminal for rollback confirmation'
        printf 'Type exactly "%s" to restore this transaction: ' "$expected" >/dev/tty
        IFS= read -r answer </dev/tty || die 'Cannot read rollback confirmation'
        [[ $answer == "$expected" ]] || die 'Rollback cancelled'
    fi
    ROLLBACK_IN_PROGRESS=1
    if emergency_restore "$dir" 'manual' 1; then say "ROLLED BACK: $id"; else die 'Rollback incomplete; inspect transaction evidence'; fi
    ROLLBACK_IN_PROGRESS=0
}

emergency_rollback_action() {
    local id=$1 dir pid boot cmd i
    safe_tx_id "$id" || exit 2
    dir=$TX_ROOT/$id
    [[ -d $dir && ! -L $dir ]] || exit 2
    if [[ -r $dir/boot-id ]]; then boot=$(<"$dir/boot-id"); else boot=''; fi
    [[ $boot == "$(cat /proc/sys/kernel/random/boot_id)" ]] || exit 2
    if [[ -r $dir/owner.pid ]]; then pid=$(<"$dir/owner.pid"); else pid=''; fi
    if [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/cmdline ]]; then
        cmd=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
        if [[ $cmd == *"$INSTALL_PATH"* && $cmd == *' apply'* ]]; then
            kill -TERM "$pid" 2>/dev/null || true
            for i in 1 2 3 4 5; do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    acquire_lock 30
    ROLLBACK_IN_PROGRESS=1
    emergency_restore "$dir" 'systemd-guard' 0
}

usage() {
    cat <<'HELP'
AEGIS Network Hardening 0.7.0-rc4 — transactional Fedora 44 network hardening

Usage:
  /usr/bin/bash -p -- ./aegis-network.sh version|packages|verify-install
  sudo /usr/bin/bash -p -- /usr/local/libexec/aegis/network-hardening/aegis-network.sh audit
  sudo /usr/bin/bash -p -- /usr/local/libexec/aegis/network-hardening/aegis-network.sh plan [--connection-uuid UUID]
  sudo /usr/bin/bash -p -- /usr/local/libexec/aegis/network-hardening/aegis-network.sh apply [--connection-uuid UUID] [--approve PLAN_SHA256]
  sudo /usr/bin/bash -p -- /usr/local/libexec/aegis/network-hardening/aegis-network.sh verify|status|history
  sudo /usr/bin/bash -p -- /usr/local/libexec/aegis/network-hardening/aegis-network.sh rollback [TX_ID] [--approve PLAN_JSON_SHA256]
  /usr/bin/bash -p -- /usr/local/libexec/aegis/network-hardening/aegis-network.sh export

Result:
  - restrictive aegis-public default zone;
  - reviewed active physical profile bound by UUID to printer-capable aegis-lan;
  - no SSH, Samba/NetBIOS or blanket TCP/UDP 1025-65535 inbound allowance;
  - StrictForwardPorts=yes, firewalld-owned nftables table, no legacy lockdown whitelist;
  - NetworkManager/systemd-resolved LLMNR off by default and mDNS resolve-only on the reviewed profile;
  - bounded redirect/source-route sysctls and compatibility-aware loose RPF without owning forwarding, BBR, MTU, RA or VPN marks;
  - durable snapshots, automatic timed rollback, verify and manual rollback.

Exit: 0 success; 2 invocation/platform/safety refusal; 3 verification/incomplete observation; signals 129/130/143.
HELP
}

main() {
    [[ $- == *p* ]] || die 'Use /usr/bin/bash -p'
    if [[ ${1-} != --internal-clean ]]; then
        local self=$0 self_dir self_base
        [[ $self == /* ]] || self=$PWD/$self
        [[ -f $self && ! -L $self ]] || die 'Entrypoint must be a regular non-symlink file'
        self_dir=${self%/*}; self_base=${self##*/}
        self_dir=$(cd -P -- "$self_dir" && pwd -P) || die 'Cannot canonicalize entrypoint directory'
        self=$self_dir/$self_base
        [[ -f $self && ! -L $self ]] || die 'Canonical entrypoint is unsafe'
        exec -c /usr/bin/bash -p -- "$self" --internal-clean "$@"
    fi
    shift

    local names name c envfd first action rollback_id=''
    names=$(compgen -e) || die 'Cannot enumerate environment'
    while IFS= read -r name; do case $name in PWD|SHLVL|_) ;; *) die 'Unexpected exported environment';; esac; done <<< "$names"
    exec {envfd}< /proc/self/environ || die 'Cannot inspect initial environment'
    if IFS= read -r -d '' -n 1 first <&"$envfd"; then exec {envfd}<&-; die 'Unexpected inherited environment'; fi
    exec {envfd}<&-

    export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC SYSTEMD_PAGER=cat SYSTEMD_COLORS=0 SYSTEMD_URLIFY=0
    SELF_PATH=$0
    [[ $SELF_PATH == /* && -f $SELF_PATH && ! -L $SELF_PATH ]] || die 'Internal entrypoint state is unsafe'
    install_traps
    action=${1:-audit}; shift || true
    while (( $# )); do
        case $1 in
          --connection-uuid) (( $# >= 2 )) || die 'Missing UUID'; PROFILE_OPT=$2; shift 2;;
          --approve) (( $# >= 2 )) || die 'Missing approval hash'; APPROVE=$2; shift 2;;
          --help|-h) usage; return 0;;
          *)
            if [[ ( $action == rollback || $action == emergency-rollback ) && -z $rollback_id ]]; then rollback_id=$1; shift
            else die "Unknown argument: $1"
            fi
            ;;
        esac
    done

    case $action in
      --help|-h) usage; return 0;;
      --version|version) say "$VERSION"; return 0;;
      packages) packages_report; return;;
      verify-install)
        for c in timeout head tr stat sha256sum; do need "$c"; done
        resource_limits; verify_install; (( PROBLEMS == 0 )) || return 3; return 0;;
      export)
        for c in timeout head tr stat; do need "$c"; done
        resource_limits; export_report; return;;
      emergency-rollback)
        (( EUID == 0 )) || die 'Root required'; [[ -n $rollback_id ]] || die 'Missing transaction id'
        for c in timeout head cat tr grep awk stat readlink sha256sum flock mktemp install cp mv rm chmod chown sync sleep systemctl nmcli firewall-cmd firewall-offline-cmd sysctl restorecon; do need "$c"; done
        emergency_rollback_action "$rollback_id"; return;;
      audit|plan|apply|verify|status|history|rollback) ;;
      *) die 'Unknown action';;
    esac

    (( EUID == 0 )) || die 'Root required'
    for c in timeout head cat tr sed awk stat readlink jq sha256sum flock mktemp install cp mv rm chmod chown sync date grep sort systemctl systemd-run systemd-detect-virt loginctl nmcli firewall-cmd firewall-offline-cmd sysctl nft ip getenforce restorecon; do need "$c"; done
    resource_limits
    case $action in
      audit) require_installed_runtime; audit; (( PROBLEMS == 0 )) || return 3;;
      plan) plan_hardening;;
      apply) apply_hardening;;
      verify) require_installed_runtime; acquire_lock; prepare_state_root; verify_hardening;;
      status) require_installed_runtime; status_hardening;;
      history) require_installed_runtime; history_hardening;;
      rollback) manual_rollback "$rollback_id";;
    esac
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
