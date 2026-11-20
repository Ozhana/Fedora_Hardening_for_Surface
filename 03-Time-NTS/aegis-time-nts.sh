#!/usr/bin/bash -p
# AEGIS TIME-NTS 0.2.0-rc3 — review candidate, not hardware-certified.
# Runtime: Bash + Fedora tools. No Python, eval, sourced state, or remote code.
# Okuma sirasi: main -> preflight -> make_plan -> apply -> verify -> rollback.
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit
umask 077

VERSION=0.2.0-rc4
CONF=/etc/chrony.conf
STATE=/var/lib/fedora-hardening/time-nts
TX=$STATE/transaction
RUNROOT=/run
ANCHOR=/
OWNER_UID=0
SYSTEM_UNIT=/usr/lib/systemd/system/chronyd.service
VENDOR_TIMEOUT_DROPIN=/usr/lib/systemd/system/service.d/10-timeout-abort.conf
SYSCONFIG=/etc/sysconfig/chronyd
MACHINE=/etc/machine-id
SOCKET=/run/chrony/chronyd.sock
SERVERS=(time.cloudflare.com nts.netnod.se ptbtime1.ptb.de)
WORK= STAGING= OPEN_TX=0 LOCKED=0 SELINUX=0
ACTION=audit APPROVE= WAIT=120
BEFORE_FP= AFTER_FP= PLAN_ID= INPUT_STAMP=
CHRONYD= CHRONYC=

say() { printf '%s\n' "$*"; }
die() { printf 'STOP: %s\n' "$*" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || die "Missing command: $1 (no automatic installation)"; }
hash_stream() {
    local sum
    sum=$(sha256sum) || die 'SHA256 calculation failed'
    [[ $sum =~ ^[a-f0-9]{64}[[:space:]] ]] || die 'Malformed SHA256 output'
    printf '%s\n' "${sum%% *}"
}
# Bounded external helpers close fd 9 before exec; the parent keeps its lock.
# This is scoped descriptor closure, not a global FD_CLOEXEC setting.
# The rollback subshell intentionally inherits the lock while it is a writer.
bounded() { timeout --signal=TERM --kill-after=2s 8s "$@" 9>&-; }

# Trust boundary: protected local parents; concurrent privileged writers and
# mount replacement are not defended against. Bash has no openat2 API.
check_dir() {
    local path=$1 cursor=$ANCHOR part mode uid
    local -a parts
    [[ $path != *$'\n'* && $path != *$'\r'* ]] || die 'Control character in protected path'
    [[ $path == /* && $path != *'/../'* && $path != */.. && $path != *'/./'* ]] || die "Unsafe directory: $path"
    [[ $ANCHOR == / || $path == "$ANCHOR" || $path == "$ANCHOR/"* ]] || die "Outside trust anchor"
    [[ -d $cursor && ! -L $cursor ]] || die "Unsafe anchor"
    IFS=' ' read -r uid mode < <(stat -c '%u %a' -- "$cursor")
    [[ $uid == "$OWNER_UID" ]] && (( (8#$mode & 0022) == 0 )) || die "Writable or foreign anchor"
    IFS=/ read -r -a parts <<< "${path#"$ANCHOR"}"
    for part in "${parts[@]}"; do
        [[ -z $part ]] && continue
        [[ $part != . && $part != .. ]] || die "Dot component"
        cursor=${cursor%/}/$part
        [[ -d $cursor && ! -L $cursor ]] || die "Missing/symlink directory: $cursor"
        IFS=' ' read -r uid mode < <(stat -c '%u %a' -- "$cursor")
        [[ $uid == "$OWNER_UID" ]] && (( (8#$mode & 0022) == 0 )) || die "Unsafe directory permissions: $cursor"
    done
}
check_file() {
    local path=$1 uid mode links size
    check_dir "${path%/*}"
    [[ -f $path && ! -L $path ]] || die "Not a regular non-symlink file: $path"
    IFS=' ' read -r uid mode links size < <(stat -c '%u %a %h %s' -- "$path")
    [[ $uid == "$OWNER_UID" && $links == 1 ]] || die "Foreign owner/hardlink: $path"
    (( (8#$mode & 07022) == 0 && size <= 1048576 )) || die "Unsafe mode/size: $path"
}
make_private_dir() {
    local path=$1 mode
    if [[ ! -e $path && ! -L $path ]]; then
        check_dir "${path%/*}"
        if ! mkdir -m 700 -- "$path"; then [[ -d $path ]] || die "Cannot create $path"; fi
        persist "${path%/*}"
    fi
    check_dir "$path"
    mode=$(stat -c %a -- "$path")
    (( (8#$mode & 0077) == 0 )) || die "State directory is not private: $path"
}
# Content + owner/mode + ALL xattrs (including ACL/SELinux). Not mtime/ctime.
# getfattr -e hex avoids arbitrary multiline attribute values in the manifest.
fingerprint() {
    local path=$1 attrs
    check_file "$path"
    attrs=$(getfattr --absolute-names --dump --match=- --encoding=hex -- "$path") || die "Cannot read extended attributes: $path"
    {
        stat -c '%u:%g:%a:%h' -- "$path"
        sha256sum < "$path"
        printf '%s\n' "$attrs" | sed '/^# file: /d; /^$/d' | sort
    } | hash_stream
}
check_flags() {
    local flags rest
    IFS=' ' read -r flags rest < <(lsattr -d -- "$1")
    [[ $flags =~ ^[-e]+$ ]] || die "Non-default inode flags need manual migration"
}
copy_exact() {
    local src=$1 dst=$2 src_fp dst_fp
    local -a preserve=(--preserve=mode,ownership,timestamps,xattr)
    (( SELINUX == 0 )) || preserve=(--preserve=mode,ownership,timestamps,xattr,context)
    cp "${preserve[@]}" --reflink=auto -- "$src" "$dst"
    src_fp=$(fingerprint "$src") || die 'Cannot fingerprint copy source'
    dst_fp=$(fingerprint "$dst") || die 'Cannot fingerprint copy destination'
    [[ $src_fp == "$dst_fp" ]] || die "Copy metadata/content mismatch"
}
# GNU sync FILE uses fsync(FILE), NOT sync -f (filesystem-wide syncfs).
# File and directory persistence are distinct from rename atomicity.
persist() {
    # Empty operands would request a global sync. Reject programming mistakes.
    (( $# > 0 )) || die 'persist needs at least one path; refusing global sync'
    sync -- "$@"
}
atomic_text() {
    local path=$1 text=$2 tmp
    check_dir "${path%/*}"
    [[ ! -e $path && ! -L $path ]] || check_file "$path"
    tmp=$(mktemp "${path%/*}/.status.XXXXXXXX")
    printf '%s\n' "$text" > "$tmp"
    persist "$tmp"
    mv -T -- "$tmp" "$path"
    persist "${path%/*}"
}
set_status() { atomic_text "$TX/status" "$1"; }
read_status() {
    check_file "$TX/status"
    local value
    value=$(<"$TX/status")
    case $value in PREPARED|APPLYING|APPLIED|ROLLING_BACK|ROLLED_BACK) printf '%s\n' "$value";; *) die "Unknown journal status";; esac
}
acquire_lock() {
    make_private_dir "${STATE%/*}"
    make_private_dir "$STATE"
    if [[ ! -e $STATE/lock && ! -L $STATE/lock ]]; then
        # O_EXCL creation via noclobber; a racing cooperating invocation may win.
        if ! (set -C; : > "$STATE/lock") 2>/dev/null; then check_file "$STATE/lock"; fi
    fi
    check_file "$STATE/lock"
    [[ $(stat -c %a "$STATE/lock") == 600 ]] || die "Lock must have mode 600"
    exec 9>> "$STATE/lock"        # No truncation, in a validated root-only tree.
    if ! flock --exclusive --nonblock 9; then
        say 'BUSY: another TIME-NTS writer holds the lock.' >&2
        exit 75
    fi
    LOCKED=1
    local orphan
    for orphan in "$STATE"/.prepare.*; do
        [[ ! -e $orphan && ! -L $orphan ]] || die "Unpublished journal remains: $orphan; inspect it before retrying (configuration was not replaced by this unpublished record)"
    done
    # Never unlink lock. fd 9 is closed by process exit.
}

# Exact token matching. Existing comments/non-source settings are preserved.
# Complex configurations are refused rather than flattened or silently weakened.
render_config() {
    awk -v hosts="${SERVERS[*]}" '
    BEGIN {
        n=split(hosts,h,/[[:space:]]+/)
        for(i=1;i<=n;i++) if(length(h[i])) expected[++total]="server " h[i] " iburst nts"
        expected[++total]="authselectmode require"; expected[++total]="minsources 2"
        expected[++total]="ntsdumpdir /var/lib/chrony"; expected[++total]="nocerttimecheck 0"
        expected[++total]="port 0"
    }
    function fail(m) { print "CONFIG REVIEW REQUIRED, line " NR ": " m > "/dev/stderr"; bad=1; exit 2 }
    { clean=$0; gsub(/\t/,"",clean); if(clean ~ /[[:cntrl:]]/) fail("control character in configuration") }
    $0 == "# BEGIN FH TIME-NTS v1" { if (inside || seen++) fail("duplicate managed block"); inside=1; next }
    $0 == "# END FH TIME-NTS v1" { if (!inside || index_in_block!=total) fail("orphan/incomplete managed end"); inside=0; next }
    inside { if ($0!=expected[++index_in_block]) fail("managed block was edited; not replacing it silently"); next }
    /^[[:space:]]*([#!;]|$)/ { print; next }
    {
        line=$0; sub(/[[:space:]]*[#!;].*$/, "", line)
        sub(/^[[:space:]]+/, "", line); sub(/[[:space:]]+$/, "", line)
        n=split(line,a,/[[:space:]]+/); k=tolower(a[1])
        if (k ~ /^(include|confdir|refclock|local|manual|initstepslew|peer|broadcast|allow|cmdallow|ntsservercert|ntsserverkey|ntpsigndsocket|nosystemcert|ntstrustedcerts|mailonchange|user|pidfile|bindcmdaddress)$/)
            fail("unsupported custom/server/bootstrap directive: " k)
        if (k=="nocerttimecheck" && (n!=2 || a[2]!="0")) fail("certificate time validation must not be disabled")
        if (k=="ntsdumpdir" && (n!=2 || a[2]!="/var/lib/chrony")) fail("custom cookie directory must be reviewed")
        if (k=="minsources" && (n!=2 || a[2]!~/^[0-9]+$/ || a[2]+0>2)) fail("will not lower an existing stronger minsources policy")
        if (k=="port" && (n!=2 || a[2]!="0")) fail("explicit server port needs manual review")
        if (k=="sourcedir" && (n!=2 || a[2]!~/^\/(var\/)?run\/chrony-dhcp$/)) fail("custom sourcedir must be reviewed")
        if (k=="server" || k=="pool") {
            if (n<2) fail("missing source name")
            for(i=3;i<=n;i++) if(a[i]!="nts" && a[i]!="iburst") fail("custom source options must be reviewed")
        }
        if (k ~ /^(server|pool|sourcedir|authselectmode|minsources|ntsdumpdir|port|nocerttimecheck)$/)
            print "# fh-time-nts disabled: " $0
        else print
    }
    END {
        if (inside && !bad) { print "CONFIG REVIEW REQUIRED: unclosed managed block" > "/dev/stderr"; bad=1 }
        if (bad) exit 2
        print "# BEGIN FH TIME-NTS v1"
        n=split(hosts,h,/[[:space:]]+/)
        for(i=1;i<=n;i++) if(length(h[i])) print "server " h[i] " iburst nts"
        print "authselectmode require"
        print "minsources 2"
        print "ntsdumpdir /var/lib/chrony"
        print "nocerttimecheck 0"
        print "port 0"
        print "# END FH TIME-NTS v1"
    }' "$1"
}

unit_value() { bounded systemctl show --value --property="$1" chronyd.service; }
# Fedora ships this single global service drop-in. Its name alone is not a
# trust decision: accept only the reviewed section and setting in a protected
# regular file. No generic drop-in parser, shell evaluation or RPM writes.
# Emit no bytes for the no-drop-in case so rc1/rc2 input stamps remain valid
# when the same no-drop-in service environment is still present.
service_dropin_stamp() {
    local dropins reload before after checked_dropins checked_reload
    dropins=$(unit_value DropInPaths) || die 'Cannot inspect chronyd drop-ins'
    reload=$(unit_value NeedDaemonReload) || die 'Cannot inspect systemd reload state'
    [[ $reload == no ]] || die 'Reload-pending systemd unit; review it first'
    case $dropins in
        '') ;;
        "$VENDOR_TIMEOUT_DROPIN") ;;
        *) die 'Unreviewed chronyd service drop-ins; only the standard Fedora timeout drop-in is supported';;
    esac
    if [[ -n $dropins ]]; then
        check_file "$VENDOR_TIMEOUT_DROPIN"
        before=$(fingerprint "$VENDOR_TIMEOUT_DROPIN") || die 'Cannot fingerprint Fedora timeout drop-in'
        # Be deliberately narrower than systemd.syntax: one section and one key,
        # no duplicates, continuations, inline comments or hidden control bytes.
        # Full-line comments and horizontal whitespace do not change the policy.
        awk '
        function reject() { bad=1; exit 2 }
        {
            line=$0
            gsub(/\t/," ",line)
            if (line ~ /[[:cntrl:]]/ || line ~ /\\[ ]*$/) reject()
            sub(/^[ ]*/,"",line); sub(/[ ]*$/,"",line)
            if (line == "" || line ~ /^[#;]/) next
            if (state == 0 && line == "[Service]") { state=1; next }
            if (state == 1 && line ~ /^TimeoutStopFailureMode[ ]*=[ ]*abort$/) { state=2; next }
            reject()
        }
        END { if (bad || state != 2) exit 2 }
        ' "$VENDOR_TIMEOUT_DROPIN" || die 'Fedora timeout drop-in content differs from the reviewed policy'
        after=$(fingerprint "$VENDOR_TIMEOUT_DROPIN") || die 'Cannot recheck Fedora timeout drop-in'
        [[ $before == "$after" ]] || die 'Fedora timeout drop-in changed during inspection'
    fi
    checked_dropins=$(unit_value DropInPaths) || die 'Cannot recheck chronyd drop-ins'
    checked_reload=$(unit_value NeedDaemonReload) || die 'Cannot recheck systemd reload state'
    [[ $checked_dropins == "$dropins" && $checked_reload == no ]] || die 'Service drop-in inputs changed during inspection'
    if [[ -n $dropins ]]; then
        printf '%s\n' 'TIME-NTS reviewed Fedora timeout drop-in v1' "$dropins" "$after"
    fi
}
platform_check() {
    local os_id os_version pid1 kernel virt_rc
    (( EUID == 0 )) || die 'Root required; use sudo /usr/bin/bash -p -- ./aegis-time-nts.sh audit'
    os_id=$(awk -F= '$1=="ID" {gsub(/"/,"",$2); print $2}' /etc/os-release)
    os_version=$(awk -F= '$1=="VERSION_ID" {gsub(/"/,"",$2); print $2}' /etc/os-release)
    [[ $os_id == fedora && $os_version == 44 ]] || die 'Apply/plan/rollback target native Fedora 44 only'
    kernel=$(</proc/sys/kernel/osrelease)
    [[ ${kernel,,} != *microsoft* && ${kernel,,} != *wsl* ]] || die 'WSL is audit-only; no host-clock ownership assumption'
    read -r pid1 < /proc/1/comm
    [[ $pid1 == systemd ]] || die 'A native systemd environment is required'
    [[ ! -e /run/ostree-booted ]] || die 'Atomic/OSTree deployment requires a separate design'
    if systemd-detect-virt --quiet; then die 'Virtual machines and containers are audit-only in this release'; else
        virt_rc=$?; (( virt_rc == 1 )) || die 'Virtualisation detection failed'
    fi
}
resolve_chrony() {
    need chronyd; need chronyc
    CHRONYD=$(command -v chronyd); CHRONYC=$(command -v chronyc)
    local version
    version=$(bounded "$CHRONYD" -v)
    [[ $version == *+NTS* ]] || die 'Installed chronyd does not report NTS support'
    [[ $version =~ version[[:space:]]4\.([0-9]+) ]] && (( 10#${BASH_REMATCH[1]} >= 8 )) || die 'This candidate requires chrony 4.8+ within the 4.x series'
}
# No shell evaluation of /etc/sysconfig/chronyd, unit contents, or journal data.
service_check() {
    local require_active=${1:-yes} pid arg i other state running_exe configured_exe
    local -a argv
    [[ $(unit_value LoadState) == loaded ]] || die 'chronyd.service is not loaded'
    [[ $(unit_value FragmentPath) == "$SYSTEM_UNIT" ]] || die 'Custom unit path needs manual review'
    service_dropin_stamp >/dev/null
    [[ $(unit_value UnitFileState) == enabled ]] || die 'chronyd must already be persistently enabled; this module does not change enablement'
    if [[ $require_active == yes ]]; then
        [[ $(unit_value ActiveState) == active ]] || die 'chronyd must already be active'
        pid=$(unit_value MainPID)
        [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/cmdline ]] || die 'No inspectable chronyd PID'
        running_exe=$(readlink -f "/proc/$pid/exe") || die 'Cannot identify running executable'
        configured_exe=$(readlink -f "$CHRONYD") || die 'Cannot identify installed executable'
        [[ $running_exe == "$configured_exe" ]] || die 'Unexpected running executable'
        mapfile -d '' -t argv < "/proc/$pid/cmdline"
        for (( i=1; i<${#argv[@]}; i++ )); do
            arg=${argv[i]}
            case $arg in
                -n|-r|-R|-4|-6) ;;
                -F) (( ++i )); [[ ${argv[i]-} =~ ^[012]$ ]] || die 'Unexpected seccomp option';;
                *) die "Unreviewed chronyd command-line option: $arg (e.g. -f/-x are not supported)";;
            esac
        done
    fi
    for other in systemd-timesyncd.service ntpd.service ntp.service openntpd.service chronyd-restricted.service; do
        state=$(bounded systemctl show --value --property=ActiveState "$other")
        [[ $state != active && $state != activating ]] || die "Competing clock service: $other"
        state=$(bounded systemctl show --value --property=UnitFileState "$other")
        [[ $state != enabled && $state != enabled-runtime ]] || die "Enabled competing clock service: $other (no automatic disabling)"
    done
}
preflight() {
    local active=${1:-yes} cmd fs target
    platform_check
    for cmd in awk stat sha256sum getfattr sed sort cp sync mv mktemp flock timeout lsattr diff systemctl systemd-detect-virt readlink findmnt; do need "$cmd"; done
    for target in "$CONF" /var/lib; do
        fs=$(findmnt --noheadings --output FSTYPE --target "$target")
        case $fs in btrfs|ext4|xfs|f2fs) ;; *) die "Unreviewed filesystem for $target: $fs";; esac
    done
    [[ $(findmnt --noheadings --output FSTYPE --target "$RUNROOT") == tmpfs ]] || die '/run must be tmpfs for volatile planning'
    resolve_chrony
    check_file "$CONF"; check_flags "$CONF"
    check_file "$SYSTEM_UNIT"; check_file "$SYSCONFIG"; check_file "$MACHINE"
    if command -v getenforce >/dev/null 2>&1; then
        if [[ $(getenforce) != Disabled ]]; then SELINUX=1; fi
    fi
    validate_sysconfig
    service_check "$active"
}
# Validate the NEXT restart options as well as the currently running process.
# systemd EnvironmentFile is data, but unreviewed flags can select a different
# config or a no-clock-control mode. Do not run its contents with source/eval.
validate_sysconfig() {
    awk '
    function fail() {print "Unreviewed /etc/sysconfig/chronyd syntax/options" > "/dev/stderr"; exit 2}
    /^[[:space:]]*(#|$)/ {next}
    {
        line=$0; sub(/^[[:space:]]+/,"",line); sub(/[[:space:]]+$/,"",line)
        if (line !~ /^OPTIONS=/ || seen++) fail()
        v=substr(line,9)
        q=substr(v,1,1)
        if(q=="\"" || q==sprintf("%c",39)) {
            if(substr(v,length(v),1)!=q) fail()
            v=substr(v,2,length(v)-2)
        }
        if(v ~ /[^[:space:]a-zA-Z0-9-]/) fail()
        sub(/^[[:space:]]+/,"",v); sub(/[[:space:]]+$/,"",v)
        n=split(v,a,/[[:space:]]+/)
        for(i=1;i<=n;i++) {
            if(a[i]=="" || a[i] ~ /^-(n|r|R|4|6)$/) continue
            if(a[i]=="-F" && ++i<=n && a[i] ~ /^[012]$/) continue
            fail()
        }
    }' "$SYSCONFIG"
}
input_stamp() {
    local unit_fp sysconfig_fp machine_sha dropin_stamp
    # Validate every producer BEFORE emitting any digest. Otherwise a failed
    # producer could still feed a partial old no-drop-in stamp to hash_stream,
    # and a caller comparing $(input_stamp) could lose that failure status.
    unit_fp=$(fingerprint "$SYSTEM_UNIT") || die 'Cannot fingerprint chronyd unit'
    sysconfig_fp=$(fingerprint "$SYSCONFIG") || die 'Cannot fingerprint chronyd sysconfig'
    machine_sha=$(sha256sum < "$MACHINE") || die 'Cannot fingerprint machine identity'
    dropin_stamp=$(service_dropin_stamp) || die 'Cannot validate service drop-in inputs'
    {
        printf '%s\n' "$unit_fp" "$sysconfig_fp" "$machine_sha"
        if [[ -n $dropin_stamp ]]; then printf '%s\n' "$dropin_stamp"; fi
    } | hash_stream
}
new_workspace() {
    check_dir "$RUNROOT"
    WORK=$(mktemp -d "$RUNROOT/fh-time-nts.XXXXXXXX")
}
make_plan() {
    [[ -n $WORK ]] || new_workspace
    BEFORE_FP=$(fingerprint "$CONF")
    INPUT_STAMP=$(input_stamp)
    copy_exact "$CONF" "$WORK/before.conf"
    copy_exact "$CONF" "$WORK/after.conf"
    render_config "$WORK/before.conf" > "$WORK/rendered.conf"
    cat -- "$WORK/rendered.conf" > "$WORK/after.conf"
    bounded "$CHRONYD" -p -f "$WORK/after.conf" > "$WORK/expanded.conf"
    AFTER_FP=$(fingerprint "$WORK/after.conf")
    [[ $BEFORE_FP == "$(fingerprint "$CONF")" && $INPUT_STAMP == "$(input_stamp)" ]] || die 'Inputs changed during planning'
    PLAN_ID=$(printf '%s\n' "TIME-NTS apply $VERSION" "$BEFORE_FP" "$AFTER_FP" "$INPUT_STAMP" | hash_stream)
}
show_plan() {
    local rc
    say "TIME-NTS $VERSION | PLAN_SHA256=$PLAN_ID"
    say 'Proposed policy: three original NTS hostnames; minsources=2; no plaintext fallback; NTP server port disabled; monitoring port preserved.'
    say 'PTB hostname is retained from V38, not certified by this package. Runtime evidence is required.'
    say 'Restart honours existing makestep/rtcsync settings; rollback cannot undo elapsed time or clock adjustments.'
    if diff -u --label /etc/chrony.conf.before --label /etc/chrony.conf.proposed "$WORK/before.conf" "$WORK/after.conf"; then
        say 'NO CONFIGURATION CHANGE'
    else rc=$?; (( rc == 1 )) || die 'diff failed'; fi
}
confirm() {
    local verb=$1 digest=$2 answer
    if [[ -n $APPROVE ]]; then [[ $APPROVE == "$digest" ]] || die 'Approval SHA256 does not match the current plan'; return; fi
    printf 'Type exactly %s %s to continue: ' "$verb" "$digest" >&2
    if ! read -r answer < /dev/tty; then die 'No controlling terminal; use --approve with the reviewed plan digest'; fi
    [[ $answer == "$verb $digest" ]] || die 'Cancelled; no time configuration changed'
}
load_tx() {
    local file before after stamp
    check_dir "$STATE"; check_dir "$TX"
    [[ $(stat -c %a "$STATE") == 700 && $(stat -c %a "$TX") == 700 ]] || die 'Journal directories must be private'
    for file in before.conf after.conf before.sha after.sha input.sha schema status; do check_file "$TX/$file"; done
    [[ $(<"$TX/schema") == 1 ]] || die 'Unsupported journal schema'
    before=$(<"$TX/before.sha"); after=$(<"$TX/after.sha"); stamp=$(<"$TX/input.sha")
    [[ $before =~ ^[a-f0-9]{64}$ && $after =~ ^[a-f0-9]{64}$ && $stamp =~ ^[a-f0-9]{64}$ ]] || die 'Malformed journal digest'
    [[ $before == "$(fingerprint "$TX/before.conf")" && $after == "$(fingerprint "$TX/after.conf")" ]] || die 'Journal content/metadata is inconsistent'
    [[ $stamp == "$(input_stamp)" ]] || die 'Host/unit/drop-in inputs changed; recovery needs manual review'
    read_status >/dev/null
}
prepare_tx() {
    local stage
    if [[ -e $TX || -L $TX ]]; then
        load_tx
        [[ $(read_status) == ROLLED_BACK ]] || die 'A transaction already exists; inspect status or rollback first'
        [[ $BEFORE_FP == "$(<"$TX/before.sha")" && $AFTER_FP == "$(<"$TX/after.sha")" ]] || die 'Single-slot journal cannot replace a different baseline'
        set_status PREPARED
        return
    fi
    stage=$(mktemp -d "$STATE/.prepare.XXXXXXXX")
    STAGING=$stage
    copy_exact "$WORK/before.conf" "$stage/before.conf"
    copy_exact "$WORK/after.conf" "$stage/after.conf"
    printf '%s\n' "$BEFORE_FP" > "$stage/before.sha"
    printf '%s\n' "$AFTER_FP" > "$stage/after.sha"
    printf '%s\n' "$INPUT_STAMP" > "$stage/input.sha"
    printf '1\n' > "$stage/schema"
    printf 'PREPARED\n' > "$stage/status"
    # One sync process, still one fsync per operand. No SSD/thermal claim.
    # Explicit names avoid wildcard/empty-expansion surprises. All seven files
    # must complete before persisting the directory or publishing the journal.
    persist "$stage/before.conf" "$stage/after.conf" \
        "$stage/before.sha" "$stage/after.sha" "$stage/input.sha" \
        "$stage/schema" "$stage/status"
    persist "$stage"
    mv -T -- "$stage" "$TX"
    STAGING=
    persist "$STATE"
}
# Replace a SINGLE file. Caller journals intent BEFORE invoking this function.
install_snapshot() {
    local src=$1 expected=$2 tmp actual desired
    [[ $(fingerprint "$CONF") == "$expected" ]] || die 'Configuration was edited; refusing to overwrite'
    tmp=$(mktemp "${CONF%/*}/.fh-time-nts.XXXXXXXX")
    STAGING=$tmp
    copy_exact "$src" "$tmp"
    persist "$tmp"
    [[ $(fingerprint "$CONF") == "$expected" ]] || die 'Configuration changed immediately before rename'
    mv -T -- "$tmp" "$CONF"
    STAGING=
    persist "${CONF%/*}"
    actual=$(fingerprint "$CONF") || die 'Cannot read installed fingerprint'
    desired=$(fingerprint "$src") || die 'Cannot read intended fingerprint'
    [[ $actual == "$desired" ]] || die 'Post-rename fingerprint mismatch'
}
restart_chrony() {
    # Enqueued restart != completed restart. Fedora/systemd can represent an
    # absent queued job as either an empty Job= value or numeric 0. Require a
    # new invocation, active/running state, a live PID, and no queued job.
    local old_inv invocation start now state substate job pid
    old_inv=$(unit_value InvocationID) || return 1
    bounded systemctl --no-block restart chronyd.service || return 1
    start=$(uptime_seconds)
    while :; do
        state=$(unit_value ActiveState) || return 1
        substate=$(unit_value SubState) || return 1
        job=$(unit_value Job) || return 1
        invocation=$(unit_value InvocationID) || return 1
        pid=$(unit_value MainPID) || return 1
        if [[ $state == active && $substate == running && ( -z $job || $job == 0 ) &&
              -n $invocation && $invocation != "$old_inv" && $pid =~ ^[1-9][0-9]*$ ]]; then
            return 0
        fi
        [[ $state == failed ]] && return 1
        now=$(uptime_seconds)
        (( now-start < 60 )) || break
        sleep 1 9>&-
    done
    return 1
}
rollback_impl() {
    load_tx
    local current before after expected_inputs
    expected_inputs=$(<"$TX/input.sha")
    current=$(fingerprint "$CONF"); before=$(<"$TX/before.sha"); after=$(<"$TX/after.sha")
    [[ $current == "$before" || $current == "$after" ]] || die 'Rollback conflict: later edits are preserved'
    bounded "$CHRONYD" -p -f "$TX/before.conf" >/dev/null
    [[ $expected_inputs == "$(input_stamp)" ]] || die 'Service inputs changed before rollback'
    set_status ROLLING_BACK
    [[ $current == "$before" ]] || install_snapshot "$TX/before.conf" "$after"
    [[ $expected_inputs == "$(input_stamp)" ]] || die 'Service inputs changed before rollback restart'
    if ! restart_chrony; then say 'RECOVERY REQUIRED: original file restored, but chronyd did not become active.' >&2; return 1; fi
    [[ $expected_inputs == "$(input_stamp)" ]] || die 'Service inputs changed during rollback restart'
    set_status ROLLED_BACK
    OPEN_TX=0
    say 'ROLLED BACK: original configuration restored. Clock history, cookies and RTC conventions were not rolled back.'
}

# A bounded, local observation: no DNS lookups, socket fallback or NTS probe.
# -u root is needed for Fedora chronyc builds that otherwise drop privilege.
cyc() { bounded "$CHRONYC" -u root -h "$SOCKET" "$@"; }
uptime_seconds() { local up rest; IFS=' ' read -r up rest < /proc/uptime; printf '%s\n' "${up%%.*}"; }
verify_once() {
    local prefix=$1 first second
    cyc -n -c sources > "$prefix.sources1" || return 1
    cyc -n -c authdata > "$prefix.auth" || return 1
    cyc -N -c authdata -a > "$prefix.names" || return 1
    cyc -n ntpdata > "$prefix.ntp" || return 1
    cyc -n tracking > "$prefix.tracking" || return 1
    cyc -n -c sources > "$prefix.sources2" || return 1
    first=$(awk -F, '$1=="^" && $2=="*" {print $3}' "$prefix.sources1")
    second=$(awk -F, '$1=="^" && $2=="*" {print $3}' "$prefix.sources2")
    [[ -n $first && $first == "$second" ]] || { say 'NOT VERIFIED: selected source changed or is absent'; return 1; }
    evaluate_evidence "$prefix" "$second"
}
evaluate_evidence() {
    local prefix=$1 selected=$2
    awk -v chosen="$selected" -v hosts="${SERVERS[*]}" '
    BEGIN {n=split(hosts,h,/[[:space:]]+/); for(i=1;i<=n;i++) if(length(h[i])) allowed[h[i]]=1}
    function trim(v) { sub(/^[[:space:]]+/,"",v); sub(/[[:space:]]+$/,"",v); return v }
    function num(v) { return v ~ /^[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)([eE][+-]?[0-9]+)?$/ }
    FILENAME ~ /[.]names$/ {
        n=split($0,a,",")
        if(n!=10 || !(a[1] in allowed) || names[a[1]]++ || a[2]!="NTS") bad=1
        namecount++
        next
    }
    FILENAME ~ /[.]auth$/ {
        n=split($0,a,","); if(n!=10 || authseen[a[1]]++) {bad=1; next}
        if (a[2]=="NTS" && num(a[4]) && a[4]+0>0 && num(a[5]) && a[5]+0>0) ke[a[1]]=1
        next
    }
    FILENAME ~ /[.]ntp$/ {
        p=index($0,":"); if(!p) next
        k=trim(substr($0,1,p-1)); v=trim(substr($0,p+1))
        if(k=="Remote address") {split(v,a,/[[:space:]]+/); ip=a[1]; if(ntpseen[ip]++) bad=1}
        if(k=="Authenticated") auth[ip]=(v=="Yes")
        if(k=="Total good RX") good[ip]=(num(v) && v+0>0)
        if(k=="Remote port") port[ip]=v
        next
    }
    FILENAME ~ /[.]tracking$/ {
        p=index($0,":"); if(!p) next
        k=trim(substr($0,1,p-1)); v=trim(substr($0,p+1))
        if(k=="Leap status") leap=(v=="Normal" || v=="Insert second" || v=="Delete second")
        if(k=="Stratum") stratum=(num(v) && v+0>=1 && v+0<=15)
        if(k=="Reference ID") {split(v,a,/[[:space:]]+/); refid=a[1]; gsub(/[()]/,"",a[2]); refip=a[2]}
        if(k=="System time") {split(v,a,/[[:space:]]+/); correction=(num(a[1]) && a[1]+0<=0.1 && a[1]+0>=-0.1)}
        next
    }
    FILENAME ~ /[.]sources2$/ {
        n=split($0,a,","); if(n!=10 || a[1]!="^") {bad=1; next}
        ip=a[3]; if(sourceseen[ip]++) bad=1; fresh=(num(a[5]) && a[5]+0>=-6 && a[5]+0<=24 && a[6]~/^[0-7]+$/ && a[6]+0>0 && num(a[7]) && a[7]+0>=0 && a[7]+0<=3*(2^(a[5]+0))+2)
        usable=(a[2]=="*" || a[2]=="+" || a[2]=="-")
        ok=(fresh && ke[ip] && auth[ip] && good[ip])
        printf "SOURCE %s: state=%s NTS_key=%s authenticated_RX=%s fresh=%s UDP=%s\n",ip,a[2],(ke[ip]?"yes":"no"),(auth[ip]&&good[ip]?"yes":"no"),(fresh?"yes":"no"),port[ip]
        if(usable && ok && !counted[ip]++) count++
        if(usable && !ok) bad=1
        if(a[2]=="*") {stars++; selectedok=(ip==chosen && ok)}
    }
    END {
        ok=(!bad && namecount==3 && stars==1 && selectedok && count>=2 && leap && stratum && correction && refid!="7F7F0101" && refip==chosen)
        printf "%s: authenticated/selectable=%d, selected=%s, remaining-correction<=0.1s=%s\n", (ok?"VERIFIED SNAPSHOT":"NOT VERIFIED"),count,chosen,(correction?"yes":"no")
        exit(ok?0:1)
    }' "$prefix.names" "$prefix.auth" "$prefix.ntp" "$prefix.tracking" "$prefix.sources2"
}
verify_live() {
    local start now prefix
    start=$(uptime_seconds); prefix=$WORK/live
    while :; do
        if verify_once "$prefix"; then return 0; fi
        now=$(uptime_seconds)
        (( now-start < WAIT )) || break
        say 'Waiting for authenticated selectable sources (5-second local observation interval)...'
        sleep 5 9>&-
    done
    say 'NOT VERIFIED: no plaintext fallback, no certificate bypass, no automatic cookie deletion.'
    return 3
}
apply_plan() {
    if [[ -e $TX || -L $TX ]]; then
        load_tx
        case $(read_status) in PREPARED|APPLYING|ROLLING_BACK) die 'Pending transaction; run rollback before any new apply';; esac
    fi
    show_plan
    if [[ $BEFORE_FP == "$AFTER_FP" ]]; then
        say 'NO-OP: no backup, file replacement, restart or persistent journal write.'
        verify_live
        return
    fi
    confirm APPLY "$PLAN_ID"
    [[ $BEFORE_FP == "$(fingerprint "$CONF")" && $INPUT_STAMP == "$(input_stamp)" ]] || die 'Approved inputs changed'
    prepare_tx
    OPEN_TX=1
    set_status APPLYING
    [[ $INPUT_STAMP == "$(input_stamp)" ]] || die 'Approved service inputs changed before installation'
    install_snapshot "$TX/after.conf" "$BEFORE_FP"
    [[ $INPUT_STAMP == "$(input_stamp)" ]] || die 'Approved service inputs changed before restart'
    if ! restart_chrony; then die 'chronyd restart failed; exit handler will attempt configuration rollback'; fi
    service_check yes
    [[ $INPUT_STAMP == "$(input_stamp)" ]] || die 'Approved service inputs changed during restart'
    set_status APPLIED
    OPEN_TX=0
    say 'CONFIGURATION APPLIED. Live authentication/synchronisation is a separate result.'
    verify_live
}
rollback_action() {
    load_tx
    local current id status
    status=$(read_status); current=$(fingerprint "$CONF")
    if [[ $status == ROLLED_BACK && $current == "$(<"$TX/before.sha")" ]]; then say 'NO-OP: rollback is already complete'; return; fi
    [[ $current == "$(<"$TX/before.sha")" || $current == "$(<"$TX/after.sha")" ]] || die 'Rollback conflict: current file is neither the before nor after snapshot'
    id=$(printf '%s\n' 'TIME-NTS rollback' "$current" "$(<"$TX/before.sha")" "$(input_stamp)" "$status" | hash_stream)
    say "ROLLBACK_SHA256=$id"
    say 'Warning: this can restore plaintext NTP sources present in your original file.'
    confirm ROLLBACK "$id"
    rollback_impl
}
audit() {
    local cmd rc=0
    say "TIME-NTS $VERSION | AUDIT ONLY | No configuration or service changes"
    date --utc '+Observed local clock (not independent evidence): %Y-%m-%dT%H:%M:%SZ'
    uname -sr
    if [[ -r /etc/os-release ]]; then grep -E '^(ID|VERSION_ID|PRETTY_NAME)=' /etc/os-release; fi
    if [[ -r $CONF && ! -L $CONF ]]; then
        say '--- Active configuration directives ---'
        awk '!/^[[:space:]]*([#!;]|$)/ {printf "%d: %s\n",NR,$0}' "$CONF"
    else say 'Configuration absent/unreadable/symlink'; rc=1; fi
    if command -v systemctl >/dev/null 2>&1; then
        bounded systemctl show chronyd.service --property=LoadState,ActiveState,UnitFileState,MainPID,FragmentPath,DropInPaths || rc=1
        bounded timedatectl show --property=Timezone,LocalRTC,NTPSynchronized || rc=1
    fi
    if command -v chronyc >/dev/null 2>&1 && command -v chronyd >/dev/null 2>&1; then
        CHRONYC=$(command -v chronyc); CHRONYD=$(command -v chronyd)
        bounded "$CHRONYD" -v || rc=1
        for cmd in 'authdata -a' sources tracking ntpdata; do
            say "--- chronyc $cmd (local Unix socket) ---"
            cyc -N "$cmd" || rc=1
        done
    else say 'Chrony is not installed or not on the fixed PATH'; rc=1; fi
    say 'Network dependency: TCP 4460; negotiated NTP UDP destination (Netnod documents UDP 4123). No firewall rules changed.'
    say 'This report is not a successful NTS verdict; run plan then verify after review.'
    return "$rc"
}
cleanup() {
    local rc=$?
    trap - EXIT ERR
    trap '' INT TERM HUP
    # Run recovery in a child with its own strict-mode error handling. Testing a
    # function directly with `if` would suppress errexit inside that function.
    if (( OPEN_TX )); then
        say 'Interrupted/failed transaction: attempting conflict-aware configuration rollback.' >&2
        ( set -Eeuo pipefail; trap 'exit 2' ERR; rollback_impl ) &
        local recovery=$!
        if wait "$recovery"; then :; else
            say 'RECOVERY REQUIRED: journal preserved; do not apply again. Review and run rollback.' >&2
        fi
    fi
    if [[ -n $STAGING ]]; then
        case $STAGING in
            "$STATE"/.prepare.*) rm -rf --one-file-system -- "$STAGING";;
            "${CONF%/*}"/.fh-time-nts.*) rm -f -- "$STAGING";;
        esac
    fi
    if [[ -n $WORK && $WORK == "$RUNROOT"/fh-time-nts.* ]]; then rm -rf --one-file-system -- "$WORK"; fi
    exit "$rc"
}
usage() {
    cat <<'HELP'
Usage: sudo /usr/bin/bash -p -- ./aegis-time-nts.sh ACTION [OPTIONS]
Actions: audit (default), plan, apply, verify, rollback, status
  --approve SHA256    Explicit current-plan approval (apply/rollback only)
  --wait SECONDS      Live observation wait, 0..300 (apply/verify only; default 120)
  --help              Show this text; no root or chrony required
Bash runtime only. Configuration changes require native Fedora 44 + chrony 4.8+.
Single protected rollback slot. No package installs, clock-step commands, cookie
removal, firewall changes, RTC convention changes or unauthenticated fallback.
HELP
}
main() {
    # Bash -p must take effect BEFORE this script; a body-level unset is too late.
    [[ $- == *p* ]] || die 'Start Bash with -p: sudo /usr/bin/bash -p -- ./aegis-time-nts.sh audit'
    if [[ ${1-} != --internal-clean ]]; then
        local self=$0
        [[ $self == /* ]] || self=$PWD/$self
        [[ -f $self && ! -L $self ]] || die 'Entrypoint must be a regular non-symlink file'
        exec -c /usr/bin/bash -p -- "$self" --internal-clean "$@"
    fi
    shift
    local name wait_seen=0
    # A manually supplied internal marker does not bypass the empty-env check.
    while IFS= read -r name; do
        case $name in PWD|SHLVL|_) ;; *) die "Unexpected exported environment on clean entry: $name";; esac
    done < <(compgen -e)
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    if [[ ${1-} == --help || ${1-} == -h ]]; then usage; return; fi
    if (( $# )); then ACTION=$1; shift; fi
    case $ACTION in audit|plan|apply|verify|rollback|status) ;; *) die 'Unknown action; see --help';; esac
    while (( $# )); do
        case $1 in
            --approve) (( $#>=2 )) || die 'Missing approval digest'; [[ -z $APPROVE && $2 =~ ^[a-f0-9]{64}$ ]] || die 'Invalid/duplicate approval'; APPROVE=$2; shift 2;;
            --wait) (( $#>=2 )) || die 'Missing wait value'; [[ $2 =~ ^(0|[1-9][0-9]{0,2})$ ]] && (( 10#$2<=300 && wait_seen==0 )) || die 'Invalid/duplicate wait (0..300)'; WAIT=$((10#$2)); wait_seen=1; shift 2;;
            *) die "Unknown option: $1";;
        esac
    done
    [[ -z $APPROVE || $ACTION == apply || $ACTION == rollback ]] || die 'Approval is only valid for apply/rollback'
    (( wait_seen==0 )) || [[ $ACTION == apply || $ACTION == verify ]] || die '--wait is only valid for apply/verify'
    if [[ $ACTION == audit ]]; then need timeout; audit; return; fi
    if [[ $ACTION == rollback ]]; then
        preflight no
        acquire_lock
        [[ -e $TX ]] || die 'No rollback journal'
        rollback_action
        return
    fi
    if [[ $ACTION == status ]]; then
        preflight no
        [[ -e $TX ]] || { say 'NO JOURNAL'; return; }
        load_tx; say "TRANSACTION=$(read_status) (not a live NTS verdict)"; return
    fi
    preflight yes
    if [[ $ACTION == apply ]]; then acquire_lock; fi
    make_plan
    case $ACTION in
        plan) show_plan;;
        apply) apply_plan;;
        verify)
            [[ $BEFORE_FP == "$AFTER_FP" ]] || die 'Persistent policy differs; inspect plan (nothing changed)'
            if [[ -e $TX ]]; then load_tx; [[ $(read_status) == APPLIED ]] || die 'Journal indicates recovery or rolled-back state'; fi
            verify_live;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
