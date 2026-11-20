#!/usr/bin/bash -p
# Fedora Hardening Stage 1 -- standalone Bash edition, 0.2.0-bash1.
# Execute: sudo /usr/bin/bash -p -- ./fh-terminal.sh audit
# Never source this file. No Python, jq, download, package or service mutation.
# Supported apply target: traditional Fedora 44, x86_64/aarch64, native systemd.
# Security boundary: reviewed script and trusted root/kernel/system binaries.
# Root-private parents exclude unprivileged path races; concurrent malicious
# root, replaced mounts and a compromised initial loader are outside this model.
# Configuration changes are journaled, NOT a globally atomic host transaction.
# See --help and packages. Recovery history is never automatically deleted.

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
    builtin printf 'Bu dosyayi source etmeyin; /usr/bin/bash -p ile calistirin.\n' >&2
    return 64
fi
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
if [[ $- != *p* ]]; then
    printf 'Gerekli baslatma: /usr/bin/bash -p -- %q [secenekler]\n' "$0" >&2
    exit 78
fi
if (( BASH_VERSINFO[0] < 5 )); then
    printf 'Bash 5 veya sonrasi gereklidir.\n' >&2
    exit 69
fi
if [[ -L ${BASH_SOURCE[0]} ]]; then
    printf 'Sembolik baglanti uzerinden baslatma reddedildi.\n' >&2
    exit 66
fi

# Only builtins precede environment sanitization. -p has to be present at
# STARTUP; this cannot undo BASH_ENV/loader effects from an unsafe invocation.
while IFS= read -r inherited_name; do
    [[ $inherited_name =~ ^[a-zA-Z_][a-zA-Z_0-9]*$ ]] || continue
    builtin export -n "$inherited_name" 2>/dev/null || :
done < <(builtin compgen -e)
unset CDPATH GLOBIGNORE BASH_ENV ENV
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
export SYSTEMD_PAGER=cat SYSTEMD_COLORS=0 SYSTEMD_URLIFY=0
shopt -s nullglob dotglob
cd -P -- /

readonly VERSION=0.2.0-bash1
readonly STATE=/var/lib/fedora-hardening-stage1
readonly SYSFILE=/etc/sysctl.d/90-fedora-hardening-stage1.conf
readonly COREFILE=/etc/systemd/coredump.conf.d/90-fedora-hardening-stage1.conf
readonly MANAGED_NAME=90-fedora-hardening-stage1.conf
readonly HEADER='# Managed by Fedora Hardening Stage 1; rollback before editing.'
readonly CORE_TEXT=$'# Managed by Fedora Hardening Stage 1; rollback before editing.\n# Disables new systemd-coredump payload storage/processing, not crash logs.\n[Coredump]\nStorage=none\nProcessSizeMax=0\n'
readonly -a KEYS=(
    fs.protected_fifos fs.protected_hardlinks fs.protected_regular
    fs.protected_symlinks fs.suid_dumpable kernel.dmesg_restrict
    kernel.kptr_restrict kernel.randomize_va_space
    kernel.unprivileged_bpf_disabled kernel.yama.ptrace_scope
)
readonly -a LEGACY=(
    /etc/sysctl.d/99-hardened.conf
    /etc/systemd/system/uyku-muhuru.service
    /etc/default/grub.d/99-surface-hardening.cfg
    /etc/default/grub.d/99-hardening.cfg
    /etc/systemd/resolved.conf.d/99-quad9-dot.conf
    /etc/NetworkManager/conf.d/00-macrandomize.conf
    /etc/modprobe.d/blacklist-prots.conf
    /etc/dnf/dnf.conf.d/99-speed.conf
    /etc/security/limits.d/99-disable-core.conf
    /etc/systemd/system.conf.d/99-fast-shutdown.conf
    /etc/systemd/system/dnf5daemon-server.service.d/override.conf
    /etc/systemd/system/dnf-makecache.service.d/override.conf
)
readonly -a REQUIRED=(stat sha256sum cat head tr timeout uname systemctl
    systemd-detect-virt systemd-analyze getenforce restorecon getfattr lsattr
    flock mktemp mkdir rmdir mv rm chmod chown sync date)

ACTION=audit PROFILE=universal CORE=1 APPROVE='' RUN_ARG='' FILES_ONLY=0
ACTION_SEEN=0 KEEP_SEEN=0 LOCKED=0 TX_ACTIVE=0 TX_KIND='' RUN_DIR=''
STAGING='' CAPTURE='' WHY='' VALUE='' PLAN_HASH='' SYS_TEXT=''
SYS_HASH='' CORE_HASH='' SYS_CREATE=0 CORE_CREATE=0 OPS=0
BOOT_ID='' MACHINE_HASH='' SYS_RAW='' CORE_RAW=''
PARSE_UNSUPPORTED=0
FS_EXISTS=0 FS_HASH='' FS_MODE='' FS_UID='' FS_GID='' FS_SIZE=0
J_ID='' J_SEQUENCE=0 J_BOOT='' J_MACHINE='' J_PROFILE='' J_CORE=1
J_PLAN='' J_SYS_CREATE=0 J_CORE_CREATE=0 J_SYS_HASH='' J_CORE_HASH=''
J_STATUS='' J_REBOOT='-' HIST_COUNT=0 HIST_PREP=0 HIST_BYTES=0 HIST_MAX=0 HIST_LATEST=''
declare -a ERRORS=() FACTS=() TMPFILES=() HIST_IDS=() HIST_STATUSES=() HIST_REBOOTS=()
declare -A BEFORE=() AFTER=() J_BEFORE=() J_AFTER=() EFFECTIVE=()

say() { printf '%s\n' "$*"; }
die() { printf 'DURDURULDU: %s\n' "$*" >&2; exit 2; }
block() { ERRORS+=("$*"); }
fact() { FACTS+=("$1=$2"); }
exists() { [[ -e $1 || -L $1 ]]; }
hash_text() { local h; h=$(printf '%s' "$1" | sha256sum) || return; printf '%s' "${h%% *}"; }
hash_file() { local h; h=$(sha256sum -- "$1") || return; printf '%s' "${h%% *}"; }
trim() { VALUE=$1; VALUE=${VALUE#"${VALUE%%[![:space:]]*}"}; VALUE=${VALUE%"${VALUE##*[![:space:]]}"}; }

capture() {
    # Bound both command duration and captured output; a failed pipeline stays
    # a failure. No background worker or user-provided command is accepted.
    local rc=0
    # Command substitution would silently discard NUL bytes. Map them to a
    # forbidden sentinel first, then reject; do not inspect a changed config.
    CAPTURE=$(timeout --signal=TERM --kill-after=2s 15s "$@" 2>&1 | head -c 262145 | tr '\000' '\001') || rc=$?
    if [[ $CAPTURE == *$'\001'* ]]; then
        CAPTURE='Komut ciktisinda NUL/kontrol bayti var; metin guvenle incelenemedi.'
        return 125
    fi
    if (( ${#CAPTURE} > 262144 )); then
        CAPTURE='Komut ciktisi 256 KiB sinirini asti.'
        return 125
    fi
    return "$rc"
}

help_text() {
    cat <<'HELP'
Fedora Hardening Stage 1 -- tek dosya Bash surumu

  sudo /usr/bin/bash -p -- ./fh-terminal.sh [eylem] [secenekler]

  audit                 Salt okunur sistem incelemesi (varsayilan)
  plan                  Degisiklikleri, engelleri ve plan SHA256'sini goster
  apply                 Plani goster; onaydan sonra uygula
  verify                Canli degerleri, kalici ayarlari ve islemleri dogrula
  history               Root'a ozel geri alma kayitlarini listele
  rollback ISLEM_ID     Son geri alinmamis islemi geri al
  packages              Kurulan/silinen programlari ve bagimliliklari goster

  --profile universal|surface-pro9
  --keep-coredumps       plan/apply/verify: coredump dosyasini olusturma
  --approve SHA256      apply: gozden gecirilmis guncel planin tam SHA256'si
  --files-only          rollback: sadece dosyalar; ardindan reboot gerekir
  --help | --version

Ornek:
  sudo /usr/bin/bash -p -- ./fh-terminal.sh plan --profile surface-pro9
  sudo /usr/bin/bash -p -- ./fh-terminal.sh apply --profile surface-pro9
  sudo /usr/bin/bash -p -- ./fh-terminal.sh verify --profile surface-pro9

Uygulama onayi: APPLY surface-pro9 (veya APPLY universal).
Yeniden baslatma sonrasi rollback icin --files-only kullanilir; ardindan yeniden
baslatilir. Eski oturumun sysctl degerleri yeni oturuma kopyalanmaz.

KURULAN / INDIRILEN / SILINEN / GUNCELLENEN PROGRAM: YOK.
Python calistirilmaz, kurulmaz veya sistemden kaldirilmaz. Eksik bagimliliklar
listelenir; otomatik kurulum yapilmaz. AIDE/rkhunter referanslari degismez.

Kapsam: on sysctl + istege bagli systemd-coredump gizlilik ayari.
Iki yonetilen dosya: /etc/sysctl.d/90-fedora-hardening-stage1.conf
ve /etc/systemd/coredump.conf.d/90-fedora-hardening-stage1.conf.
Farkli mevcut dosyanin ustune yazilmaz; --keep-coredumps kaldirma komutu degildir.
Eski Python JSON islem gecmisi otomatik donusturulmez; bulunursa islem durur.
Bu dosya Fedora 44/Surface uzerinde donanim testi yapildigi iddiasini tasimaz.
HELP
}

packages() {
    local c state
    say 'Otomatik kurulan/indirilen: YOK'
    say 'Otomatik kaldirilan:       YOK'
    say 'Otomatik guncellenen:      YOK'
    say 'Python bagimliligi:        YOK (sistem Python una dokunulmaz)'
    say ''
    say 'Gerekli mevcut komutlar; eksikler otomatik kurulmaz:'
    for c in "${REQUIRED[@]}"; do
        state=EKSIK; command -v "$c" >/dev/null 2>&1 && state=VAR
        printf '  %-24s %s\n' "$c" "$state"
    done
    say 'Istege bagli audit araclari: mokutil, findmnt, lsblk, ss, firewall-cmd.'
    say 'Bunlar eksikse ilgili ek gozlem UNKNOWN olur; indirme yapilmaz.'
}

parse_args() {
    while (( $# )); do
        case $1 in
            --help|-h) help_text; exit 0 ;;
            --version) say "$VERSION"; exit 0 ;;
            --profile)
                (( $# >= 2 )) || die '--profile degeri eksik.'
                PROFILE=$2; shift 2 ;;
            --approve)
                (( $# >= 2 )) || die '--approve degeri eksik.'
                APPROVE=$2; shift 2 ;;
            --keep-coredumps) CORE=0; KEEP_SEEN=1; shift ;;
            --files-only) FILES_ONLY=1; shift ;;
            audit|plan|apply|verify|history|rollback|packages)
                (( ACTION_SEEN == 0 )) || die 'Tek eylem secin.'
                ACTION=$1; ACTION_SEEN=1; shift ;;
            --*) die "Bilinmeyen secenek: $1" ;;
            *)
                [[ $ACTION == rollback && -z $RUN_ARG ]] || die "Beklenmeyen arguman: $1"
                RUN_ARG=$1; shift ;;
        esac
    done
    [[ $PROFILE == universal || $PROFILE == surface-pro9 ]] || die 'Gecersiz profil.'
    [[ $ACTION != rollback || -n $RUN_ARG ]] || die 'rollback icin islem kimligi gerekli.'
    (( FILES_ONLY == 0 )) || [[ $ACTION == rollback ]] || die '--files-only sadece rollback icindir.'
    [[ -z $APPROVE || $ACTION == apply ]] || die '--approve sadece apply icindir.'
    [[ -z $APPROVE || $APPROVE =~ ^[0-9a-f]{64}$ ]] || die 'SHA256: 64 kucuk onaltilik karakter gerekir.'
    (( KEEP_SEEN == 0 )) || [[ $ACTION == plan || $ACTION == apply || $ACTION == verify ]] || die '--keep-coredumps: plan/apply/verify gerekir.'
}

check_dirs() {
    # Check the filesystem root and every existing component, never follow a
    # directory symlink. mode: inspect (missing allowed), required, or create.
    local path=$1 mode=${2:-required} private=${3:-0} cursor=/ part meta uid bits perm
    local -a parts=()
    [[ $path == /* && $path != *'/../'* && $path != */.. && $path != *'/./'* ]] || { WHY="Guvensiz dizin yolu: $path"; return 1; }
    IFS=/ read -r -a parts <<< "${path#/}"
    parts=('' "${parts[@]}")
    for part in "${parts[@]}"; do
        [[ -z $part ]] || cursor=${cursor%/}/$part
        if ! exists "$cursor"; then
            case $mode in
                inspect) return 0 ;;
                create)
                    perm=755; [[ $cursor != "$path" || $private == 0 ]] || perm=700
                    mkdir -m "$perm" -- "$cursor" || { WHY="Dizin olusturulamadi: $cursor"; return 1; }
                    sync -- "${cursor%/*}/" || { WHY='Dizin kaydi kalici yazilamadi.'; return 1; } ;;
                *) WHY="Dizin yok: $cursor"; return 1 ;;
            esac
        fi
        [[ -d $cursor && ! -L $cursor ]] || { WHY="Dizin veya baglanti guvensiz: $cursor"; return 1; }
        meta=$(stat -c '%u %a' -- "$cursor") || { WHY='Dizin bilgisi okunamadi.'; return 1; }
        IFS=' ' read -r uid bits <<< "$meta"
        [[ $uid == 0 && $bits =~ ^[0-7]{3,4}$ ]] || { WHY="Dizin root mulkiyetinde degil: $cursor"; return 1; }
        (( (8#$bits & 0022) == 0 )) || { WHY="Baska kullanici dizine yazabilir: $cursor"; return 1; }
        if [[ $cursor == "$path" && $private == 1 ]]; then
            (( (8#$bits & 0077) == 0 )) || { WHY="Ozel dizin 0700 olmali: $path"; return 1; }
        fi
    done
}

inspect_file() {
    local path=$1 private=${2:-0} limit=${3:-65536} meta links attrs flags line
    WHY=''; FS_EXISTS=0; FS_HASH=''; FS_MODE=''; FS_UID=''; FS_GID=''; FS_SIZE=0
    check_dirs "${path%/*}" inspect || return 1
    exists "$path" || return 0
    [[ -f $path && ! -L $path ]] || { WHY="Normal dosya degil veya symlink: $path"; return 1; }
    meta=$(stat -c '%u %g %a %h %s' -- "$path") || { WHY="stat basarisiz: $path"; return 1; }
    IFS=' ' read -r FS_UID FS_GID FS_MODE links FS_SIZE <<< "$meta"
    [[ $FS_UID == 0 && $links == 1 && $FS_MODE =~ ^[0-7]{3,4}$ && $FS_SIZE =~ ^[0-9]+$ ]] || { WHY="Guvensiz sahiplik/tur/hardlink: $path"; return 1; }
    (( (8#$FS_MODE & 07022) == 0 && FS_SIZE <= limit )) || { WHY="Guvensiz izin veya boyut: $path"; return 1; }
    if (( private )); then
        (( (8#$FS_MODE & 0077) == 0 )) || { WHY="Ozel dosya baska kullaniciya acik: $path"; return 1; }
    fi
    flags=$(lsattr -d -- "$path" 2>/dev/null) || { WHY="Dosya nitelikleri okunamadi: $path"; return 1; }
    flags=${flags%% *}
    [[ $flags != *i* && $flags != *a* ]] || { WHY="Immutable/append-only dosya: $path"; return 1; }
    attrs=$(getfattr --absolute-names -m '.*' -- "$path" 2>/dev/null) || { WHY="xattr/ACL okunamadi: $path (getfattr/attr gerekli)"; return 1; }
    while IFS= read -r line; do
        [[ -z $line || $line == \#* || $line == security.selinux ]] || { WHY="Ek ACL/xattr icin elle inceleme gerekir: $path"; return 1; }
    done <<< "$attrs"
    FS_HASH=$(hash_file "$path") || { WHY="Dosya ozeti okunamadi: $path"; return 1; }
    FS_EXISTS=1
}

matches_managed() {
    [[ $FS_EXISTS == 1 && $FS_HASH == "$1" && $FS_MODE == 644 && $FS_UID == 0 && $FS_GID == 0 ]]
}

valid_value() {
    case $1 in
        kernel.yama.ptrace_scope) [[ $2 =~ ^[0-3]$ ]] ;;
        fs.protected_hardlinks|fs.protected_symlinks|kernel.dmesg_restrict) [[ $2 =~ ^[01]$ ]] ;;
        fs.protected_fifos|fs.protected_regular|fs.suid_dumpable|kernel.kptr_restrict|kernel.randomize_va_space|kernel.unprivileged_bpf_disabled) [[ $2 =~ ^[0-2]$ ]] ;;
        *) return 1 ;;
    esac
}

read_live() {
    local key=$1 path
    valid_value "$key" 0 || { WHY='Izin listesinde olmayan sysctl.'; return 1; }
    path=/proc/sys/${key//./\/}
    if ! IFS= read -r VALUE < "$path"; then WHY="Sysctl okunamadi: $key"; return 1; fi
    valid_value "$key" "$VALUE" || { WHY="Beklenmeyen sysctl: $key=$VALUE"; return 1; }
}

desired_value() {
    local key=$1 current=$2 minimum
    case $key in
        fs.suid_dumpable) VALUE=0; return ;;
        kernel.unprivileged_bpf_disabled)
            VALUE=2; [[ $current != 1 ]] || VALUE=1; return ;;
        fs.protected_hardlinks|fs.protected_symlinks|kernel.dmesg_restrict|kernel.yama.ptrace_scope) minimum=1 ;;
        *) minimum=2 ;;
    esac
    VALUE=$minimum; (( current <= minimum )) || VALUE=$current
    return 0
}

set_live() {
    local key=$1 value=$2 current
    valid_value "$key" "$value" || die 'Izin listesi disinda sysctl yazma istegi.'
    read_live "$key" || die "$WHY"; current=$VALUE
    [[ $key != kernel.unprivileged_bpf_disabled || $value != 1 || $current == 1 ]] || die 'Geri donulemeyen BPF=1 gecisi reddedildi.'
    [[ $key != kernel.yama.ptrace_scope || $value != 3 || $current == 3 ]] || die 'Geri donulemeyen ptrace=3 gecisi reddedildi.'
    [[ $current != "$value" ]] || return 0
    printf '%s\n' "$value" > "/proc/sys/${key//./\/}"
    read_live "$key" || die "$WHY"
    [[ $VALUE == "$value" ]] || die "Canli deger dogrulanamadi: $key"
}

read_identity() {
    IFS= read -r BOOT_ID < /proc/sys/kernel/random/boot_id
    [[ $BOOT_ID =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ ]] || die 'Boot kimligi gecersiz.'
    local mid
    IFS= read -r mid < /etc/machine-id
    [[ $mid =~ ^[0-9a-f]{32}$ ]] || die 'Makine kimligi gecersiz.'
    MACHINE_HASH=$(hash_text "$mid")
}

unit_state() {
    capture systemctl show "$1" --no-pager --property=LoadState,ActiveState,UnitFileState
}

host_facts() {
    local line key val os=unknown ver=unknown variant=unknown arch kernel pid1 virt_rc selcfg=0 unit
    local vendor=UNKNOWN product=UNKNOWN c
    for c in "${REQUIRED[@]}"; do
        command -v "$c" >/dev/null 2>&1 || block "Gerekli komut eksik: $c; otomatik kurulum yok."
    done
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line == *=* ]] || continue
        key=${line%%=*}; val=${line#*=}
        if [[ $val == \"*\" || $val == \'*\' ]]; then val=${val:1:${#val}-2}; fi
        [[ $val =~ ^[a-zA-Z0-9_.-]+$ ]] || continue
        case $key in ID) os=$val ;; VERSION_ID) ver=$val ;; VARIANT_ID) variant=$val ;; esac
    done < /etc/os-release
    arch=$(uname -m); kernel=$(uname -r)
    fact os "$os"; fact version "$ver"; fact variant "$variant"; fact arch "$arch"; fact kernel "$kernel"
    [[ $os == fedora && $ver == 44 ]] || block 'Uygulama yalniz Fedora 44 icin tasarlandi; surum zorlamasi yok.'
    [[ $arch == x86_64 || $arch == aarch64 ]] || block 'Destek disi mimari.'
    if exists /run/ostree-booted || [[ $variant == silverblue || $variant == kinoite || $variant == sericea || $variant == sway-atomic || $variant == coreos ]]; then
        block 'Atomic/OSTree/bootc kurulumu kapsam disinda.'
    fi
    IFS= read -r pid1 < /proc/1/comm
    [[ $pid1 == systemd && ${kernel,,} != *microsoft* ]] || block 'Native systemd Fedora gerekli; WSL/chroot/container kapsam disinda.'
    virt_rc=0; capture systemd-detect-virt --container || virt_rc=$?
    (( virt_rc == 1 )) || block 'Container disi ortam dogrulanamadi.'
    fact container_check "$virt_rc:$CAPTURE"
    if capture getenforce; then
        [[ $CAPTURE == Enforcing ]] || block 'SELinux zaten Enforcing olmali; betik modunu degistirmez.'
    else block 'SELinux durumu okunamadi.'; fi
    fact selinux "$CAPTURE"
    if [[ -r /etc/selinux/config ]]; then
        while IFS= read -r line || [[ -n $line ]]; do
            [[ $line =~ ^[[:space:]]*SELINUX[[:space:]]*=[[:space:]]*enforcing[[:space:]]*(#.*)?$ ]] && selcfg=1
        done < /etc/selinux/config
    fi
    (( selcfg )) || block 'Kalici SELINUX=enforcing dogrulanamadi.'
    if unit_state firewalld.service; then
        [[ $'\n'$CAPTURE$'\n' == *$'\nActiveState=active\n'* && $'\n'$CAPTURE$'\n' == *$'\nUnitFileState=enabled\n'* ]] || block 'firewalld active ve enabled olmali; betik kendisi acmaz.'
    else block 'firewalld durumu okunamadi.'; fi
    fact firewalld "$CAPTURE"
    for unit in cups.service cups.socket avahi-daemon.service; do
        if unit_state "$unit"; then
            [[ $CAPTURE != *'=masked'* ]] || block "Yazici/kesif birimi maskeli: $unit"
        else block "Yazici/kesif birimi denetlenemedi: $unit"; fi
        fact "$unit" "$CAPTURE"
    done
    for c in "${LEGACY[@]}"; do exists "$c" && block "Onceki hardening dosyasi bulundu; once inceleme gerekir: $c"; done
    [[ ! -r /sys/class/dmi/id/sys_vendor ]] || IFS= read -r vendor < /sys/class/dmi/id/sys_vendor
    [[ ! -r /sys/class/dmi/id/product_name ]] || IFS= read -r product < /sys/class/dmi/id/product_name
    fact vendor "$vendor"; fact product "$product"
    if [[ $PROFILE == surface-pro9 ]]; then
        [[ $arch == x86_64 && ${vendor,,} == *microsoft* && $product =~ ^Surface\ Pro\ 9($|[^[:alnum:]_]) ]] || block 'surface-pro9 profili Intel/x86_64 Microsoft Surface Pro 9 gerektirir; SQ3 kapsam disi.'
    fi
    read_identity
    fact boot "$BOOT_ID"; fact machine_hash "$MACHINE_HASH"
}

config_text() {
    local key map=$1
    local -n values=$map
    printf '%s\n' "$HEADER"
    for key in "${KEYS[@]}"; do printf '%s = %s\n' "$key" "${values[$key]}"; done
}

parse_setting() {
    local line=$1 kind=$2 key val
    trim "$line"; line=$VALUE
    [[ -n $line && $line != \#* && $line != \;* ]] || return 0
    if [[ $kind == core && $line == *\\ ]]; then
        # INI continuation semantics differ from sysctl's physical lines.
        # Refuse this uncommon form instead of claiming a guessed result.
        PARSE_UNSUPPORTED=1
        return 0
    fi
    if [[ $line == \[*\] ]]; then SECTION=${line:1:${#line}-2}; return 0; fi
    if [[ $kind == sysctl && $line == -* && $line != *=* ]]; then
        # systemd replaces an earlier exact assignment with an exclusion too;
        # it is not merely a hint for wildcard entries elsewhere in the file.
        trim "${line#-}"; key=${VALUE//\//.}
        if valid_value "$key" 0; then unset 'EFFECTIVE[$key]'; fi
        return 0
    fi
    [[ $line == *=* ]] || return 0
    trim "${line%%=*}"; key=$VALUE
    trim "${line#*=}"; val=$VALUE
    if [[ $kind == sysctl ]]; then
        trim "${key#-}"; key=${VALUE//\//.}
        valid_value "$key" 0 || return 0
        EFFECTIVE[$key]=$val
    elif [[ $SECTION == Coredump && ( $key == Storage || $key == ProcessSizeMax ) ]]; then
        EFFECTIVE[$key]=$val
    fi
}

merged_values() {
    # cat-config supplies systemd's selected files and order. For a NEW file,
    # insert its reviewed text at its basename position, replacing a lower
    # priority file of the same basename. Recheck actual config after writing.
    local kind=$1 project=$2 raw=$3 line path base inject=0 skip=0 candidate text injected_line
    EFFECTIVE=(); SECTION=''; PARSE_UNSUPPORTED=0
    if [[ $raw == *$'\r'* ]]; then
        block 'Yapilandirmada CR/CRLF var; satir anlamini tahmin etmeden elle inceleme gerekli.'
        return 0
    fi
    text=$SYS_TEXT; [[ $kind != core ]] || text=$CORE_TEXT
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ $line == '# /'* ]]; then
            path=${line#\# }; base=${path##*/}; candidate=0
            [[ $kind != sysctl || $path != */sysctl.d/*.conf ]] || candidate=1
            [[ $kind != core || $path != */coredump.conf.d/*.conf ]] || candidate=1
            if (( candidate )); then
                skip=0
                if (( project && ! inject )) && [[ $base == "$MANAGED_NAME" || $base > "$MANAGED_NAME" ]]; then
                    SECTION=''
                    while IFS= read -r injected_line; do parse_setting "$injected_line" "$kind"; done <<< "$text"
                    inject=1
                fi
                if (( project )) && [[ $base == "$MANAGED_NAME" ]]; then skip=1; fi
                SECTION=''
            fi
        fi
        (( skip == 0 )) || continue
        parse_setting "$line" "$kind"
    done <<< "$raw"
    if (( project && ! inject )); then
        SECTION=''
        while IFS= read -r injected_line; do parse_setting "$injected_line" "$kind"; done <<< "$text"
    fi
}

check_persistence() {
    local projected=$1 key project_sys=0 project_core=0
    (( projected == 0 )) || { project_sys=$SYS_CREATE; project_core=$CORE_CREATE; }
    if capture systemd-analyze cat-config sysctl.d; then
        SYS_RAW=$CAPTURE
        merged_values sysctl "$project_sys" "$SYS_RAW"
        for key in "${KEYS[@]}"; do
            [[ ${EFFECTIVE[$key]-} == "${AFTER[$key]-}" ]] || block "Kalici sysctl cakismasi/eksigi: $key (etkin=${EFFECTIVE[$key]-YOK}, hedef=${AFTER[$key]-YOK})"
        done
    else block 'systemd birlesik sysctl yapilandirmasi okunamadi.'; SYS_RAW=$CAPTURE; fi
    CORE_RAW=''
    if (( CORE )); then
        if capture systemd-analyze cat-config systemd/coredump.conf; then
            CORE_RAW=$CAPTURE
            merged_values core "$project_core" "$CORE_RAW"
            (( PARSE_UNSUPPORTED == 0 )) || block 'Coredump yapilandirmasinda satir devam isareti var; elle inceleme gerekli.'
            [[ ${EFFECTIVE[Storage]-} == none && ${EFFECTIVE[ProcessSizeMax]-} == 0 ]] || block 'Kalici coredump ayarlari cakismali veya eksik.'
        else block 'systemd birlesik coredump yapilandirmasi okunamadi.'; CORE_RAW=$CAPTURE; fi
    fi
}

make_plan() {
    local key current path want status collector complete=1 item
    ERRORS=(); FACTS=(); BEFORE=(); AFTER=(); SYS_CREATE=0; CORE_CREATE=0; OPS=0
    SYS_RAW=''; CORE_RAW=''
    host_facts
    if (( CORE )); then
        if IFS= read -r collector < /proc/sys/kernel/core_pattern; then
            [[ $collector =~ ^\|[[:space:]]*/usr/lib/systemd/systemd-coredump([[:space:]]|$) ]] || block 'Aktif core collector systemd-coredump pipe degil; ayri inceleyin veya --keep-coredumps kullanin.'
            fact core_collector "$collector"
        else block 'Aktif coredump toplayicisi okunamadi.'; fi
    fi
    for key in "${KEYS[@]}"; do
        if read_live "$key"; then
            current=$VALUE; BEFORE[$key]=$current
            desired_value "$key" "$current"; AFTER[$key]=$VALUE
            [[ $current == "$VALUE" ]] || OPS=$((OPS + 1))
        else block "$WHY"; complete=0; fi
    done
    SYS_TEXT=''; SYS_HASH=''
    if (( complete )); then
        SYS_TEXT=$(config_text AFTER); SYS_TEXT+=$'\n'
        SYS_HASH=$(hash_text "$SYS_TEXT")
    fi
    CORE_HASH=$(hash_text "$CORE_TEXT")
    for item in sys core; do
        [[ $item != core || $CORE == 1 ]] || continue
        if [[ $item == sys ]]; then
            (( complete )) || continue
            path=$SYSFILE; want=$SYS_HASH
        else path=$COREFILE; want=$CORE_HASH; fi
        if inspect_file "$path"; then
            status=$FS_EXISTS:$FS_HASH:$FS_MODE:$FS_UID:$FS_GID
            fact "$path" "$status"
            if (( FS_EXISTS == 0 )); then
                OPS=$((OPS + 1))
                if [[ $item == sys ]]; then SYS_CREATE=1; else CORE_CREATE=1; fi
            elif ! matches_managed "$want"; then
                block "Mevcut yonetilen dosya farkli; uzerine yazilmaz: $path"
            fi
        else block "$WHY"; fi
    done
    if (( CORE == 0 )) && exists "$COREFILE"; then
        block '--keep-coredumps mevcut politikayi kaldirmaz; once eski islemi geri alin/inceleyin.'
    fi
    if (( complete )); then check_persistence 1; fi
    PLAN_HASH=$({
        printf 'FH_BASH_PLAN\t1\nversion\t%s\nprofile\t%s\ncore\t%s\n' "$VERSION" "$PROFILE" "$CORE"
        for item in "${FACTS[@]}"; do printf 'fact\t%q\n' "$item"; done
        for key in "${KEYS[@]}"; do printf 'sysctl\t%s\t%s\t%s\n' "$key" "${BEFORE[$key]-UNKNOWN}" "${AFTER[$key]-UNKNOWN}"; done
        printf 'sysfile\t%s\t%s\ncorefile\t%s\t%s\n' "$SYS_CREATE" "$SYS_HASH" "$CORE_CREATE" "$CORE_HASH"
        printf 'effective_sysctl\t%q\neffective_core\t%q\n' "$SYS_RAW" "$CORE_RAW"
        for item in "${ERRORS[@]}"; do printf 'block\t%q\n' "$item"; done
    } | sha256sum)
    PLAN_HASH=${PLAN_HASH%% *}
}

show_plan() {
    local key item
    printf '\nFedora Hardening Stage 1 %s | profil: %s\n' "$VERSION" "$PROFILE"
    printf '%-39s %7s %7s\n' 'Ayar' 'Mevcut' 'Hedef'
    for key in "${KEYS[@]}"; do printf '%-39s %7s %7s\n' "$key" "${BEFORE[$key]-UNKNOWN}" "${AFTER[$key]-UNKNOWN}"; done
    (( SYS_CREATE == 0 )) || printf 'OLUSTUR: %s\n' "$SYSFILE"
    (( CORE_CREATE == 0 )) || printf 'OLUSTUR: %s\n' "$COREFILE"
    if (( CORE )); then say 'Yeni systemd coredump bellek verisi: saklama/isleme kapali.'; else say 'Coredump politikasi: bu islemde degistirilmiyor.'; fi
    printf 'Planlanan islem sayisi: %s\n' "$OPS"
    for item in "${ERRORS[@]}"; do printf 'ENGEL: %s\n' "$item"; done
    printf 'Plan SHA256: %s\n' "$PLAN_HASH"
    say 'Program kurma/indirme/silme/guncelleme: YOK.'
    say 'Dogrulama bu modulun ayarlariyla sinirlidir; reboot sonrasi verify calistirin.'
}

write_private() {
    local path=$1 content=$2 tmp
    # Every failure is explicit: this is also called from EXIT with errexit
    # disabled. A failed/truncated temporary must NEVER replace valid history.
    check_dirs "${path%/*}" required 1 || { printf '%s\n' "$WHY" >&2; return 1; }
    tmp=$(mktemp "${path%/*}/.fh-write.XXXXXXXXXXXX") || return 1
    TMPFILES+=("$tmp")
    printf '%s' "$content" > "$tmp" || return 1
    chmod 600 -- "$tmp" || return 1
    chown 0:0 -- "$tmp" || return 1
    sync -- "$tmp" || return 1
    mv -T -- "$tmp" "$path" || return 1
    sync -- "${path%/*}" || return 1
}

save_status() {
    local status=$1 reboot=${2:--}
    write_private "$RUN_DIR/status" "$status"$'\t'"$reboot"$'\n'
}

cleanup() {
    local rc=$? path
    trap - EXIT INT TERM HUP
    set +e
    if (( rc != 0 && TX_ACTIVE )); then
        if [[ $TX_KIND == apply ]]; then
            save_status FAILED - || printf 'Durum guncellenemedi; onceki kalici kayit kurtarma icin korundu.\n' >&2
        fi
        printf 'YARIM ISLEM: %s\nGecmisi inceleyin; rollback ile kurtarin. Otomatik geri alma yapilmadi.\n' "${RUN_DIR##*/}" >&2
    fi
    for path in "${TMPFILES[@]}"; do
        [[ ! -f $path || -L $path ]] || rm -f -- "$path"
    done
    # An unpublished prepared directory has never authorized a host write.
    # Remove only the fixed filenames made by this process; never recurse.
    if [[ -n $STAGING && -d $STAGING && ! -L $STAGING ]]; then
        for path in manifest.tsv status sysctl.conf coredump.conf; do
            [[ ! -f $STAGING/$path || -L $STAGING/$path ]] || rm -f -- "$STAGING/$path"
        done
        rmdir -- "$STAGING" 2>/dev/null || :
    fi
    if (( LOCKED )); then exec 9>&-; fi
    if (( rc != 0 )); then printf 'Cikis kodu: %s\n' "$rc" >&2; fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

lock_state() {
    local c
    (( EUID == 0 )) || die 'Bu eylem icin sudo/root gerekir.'
    for c in flock mktemp mkdir rmdir mv rm chmod chown sync getfattr lsattr; do
        command -v "$c" >/dev/null 2>&1 || die "Kurtarma/kilit araci eksik: $c; otomatik kurulum yok."
    done
    check_dirs "$STATE" create 1 || die "$WHY"
    if ! exists "$STATE/lock"; then (set -o noclobber; : > "$STATE/lock") || die 'Kilit dosyasi olusturulamadi.'; fi
    inspect_file "$STATE/lock" 1 || die "$WHY"
    [[ $FS_EXISTS == 1 && $FS_MODE == 600 && $FS_GID == 0 ]] || die 'Kilit dosyasi root:root 0600 olmali.'
    exec 9<> "$STATE/lock"
    flock -n 9 || die 'Baska bir Stage 1 islemi calisiyor.'
    LOCKED=1
    # Never unlink the lock: all versions coordinate on this SAME inode.
}

valid_id() { [[ $1 =~ ^B-[0-9]{8}T[0-9]{15}Z-[0-9a-f]{12}$ ]]; }
valid_uuid() { [[ $1 =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ ]]; }

load_record() {
    local dir=$1 line key i n=0 expected actual name
    local -a lines=() row=()
    check_dirs "$dir" required 1 || die "$WHY"
    if exists "$dir/manifest.json"; then
        die "Python JSON gecmisi bulundu: ${dir##*/}. Otomatik gecmis donusumu yok; once eski surumun islemini inceleyin/geri alin."
    fi
    valid_id "${dir##*/}" || die "Bilinmeyen islem dizini: ${dir##*/}"
    inspect_file "$dir/manifest.tsv" 1 16384 || die "$WHY"
    [[ $FS_EXISTS == 1 && $FS_MODE == 600 && $FS_GID == 0 ]] || die 'Islem manifesti yok veya guvensiz.'
    mapfile -t lines < "$dir/manifest.tsv"
    (( ${#lines[@]} == 21 )) || die 'Manifest satir sayisi gecersiz.'
    [[ ${lines[0]} == $'FH_BASH\t1' && ${lines[1]} == $'version\t'"$VERSION" ]] || die 'Desteklenmeyen manifest surumu.'
    for i in 2 3 4 5 6 7 8; do
        IFS=$'\t' read -r -a row <<< "${lines[$i]}"
        (( ${#row[@]} == 2 )) || die 'Manifest alan sayisi gecersiz.'
        case $i in
            2) [[ ${row[0]} == id && ${row[1]} == "${dir##*/}" ]] || die 'Manifest kimligi uyusmuyor.'; J_ID=${row[1]} ;;
            3) [[ ${row[0]} == sequence && ${row[1]} =~ ^[1-9][0-9]{0,8}$ ]] || die 'Gecersiz sira numarasi.'; J_SEQUENCE=${row[1]} ;;
            4) [[ ${row[0]} == boot ]] && valid_uuid "${row[1]}" || die 'Gecersiz boot kimligi.'; J_BOOT=${row[1]} ;;
            5) [[ ${row[0]} == machine && ${row[1]} =~ ^[0-9a-f]{64}$ ]] || die 'Gecersiz makine ozeti.'; J_MACHINE=${row[1]} ;;
            6) [[ ${row[0]} == profile && ( ${row[1]} == universal || ${row[1]} == surface-pro9 ) ]] || die 'Gecersiz kayit profili.'; J_PROFILE=${row[1]} ;;
            7) [[ ${row[0]} == core && ${row[1]} =~ ^[01]$ ]] || die 'Gecersiz coredump bayragi.'; J_CORE=${row[1]} ;;
            8) [[ ${row[0]} == plan && ${row[1]} =~ ^[0-9a-f]{64}$ ]] || die 'Gecersiz plan ozeti.'; J_PLAN=${row[1]} ;;
        esac
    done
    for i in 9 10; do
        IFS=$'\t' read -r -a row <<< "${lines[$i]}"
        (( ${#row[@]} == 3 )) || die 'Gecersiz dosya kaydi.'
        [[ ${row[1]} =~ ^[01]$ && ${row[2]} =~ ^[0-9a-f]{64}$ ]] || die 'Gecersiz dosya bayragi/ozeti.'
        if (( i == 9 )); then
            [[ ${row[0]} == sysfile ]] || die 'sysfile kaydi eksik.'
            J_SYS_CREATE=${row[1]}; J_SYS_HASH=${row[2]}
        else
            [[ ${row[0]} == corefile ]] || die 'corefile kaydi eksik.'
            J_CORE_CREATE=${row[1]}; J_CORE_HASH=${row[2]}
        fi
    done
    (( J_CORE == 1 || J_CORE_CREATE == 0 )) || die 'Coredump kaydi tutarsiz.'
    J_BEFORE=(); J_AFTER=()
    for i in "${!KEYS[@]}"; do
        key=${KEYS[$i]}; n=$((i + 11))
        IFS=$'\t' read -r -a row <<< "${lines[$n]}"
        (( ${#row[@]} == 4 )) || die 'Gecersiz sysctl kaydi.'
        [[ ${row[0]} == sysctl && ${row[1]} == "$key" ]] || die 'Sysctl izin listesi/sirasi uyusmuyor.'
        valid_value "$key" "${row[2]}" && valid_value "$key" "${row[3]}" || die 'Kayitta gecersiz sysctl degeri.'
        desired_value "$key" "${row[2]}"
        [[ $VALUE == "${row[3]}" ]] || die 'Kayittaki politika izin verilen donusum degil.'
        J_BEFORE[$key]=${row[2]}; J_AFTER[$key]=${row[3]}
    done
    expected=$(config_text J_AFTER); expected+=$'\n'
    [[ $(hash_text "$expected") == "$J_SYS_HASH" && $(hash_text "$CORE_TEXT") == "$J_CORE_HASH" ]] || die 'Kaydin politika ozeti uyusmuyor.'
    for name in sysctl coredump; do
        n=$J_SYS_CREATE; actual=$J_SYS_HASH
        [[ $name != coredump ]] || { n=$J_CORE_CREATE; actual=$J_CORE_HASH; }
        if (( n )); then
            inspect_file "$dir/$name.conf" 1 16384 || die "$WHY"
            [[ $FS_EXISTS == 1 && $FS_HASH == "$actual" && $FS_MODE == 600 && $FS_GID == 0 ]] || die 'Beklenen dosya kopyasi eksik/farkli.'
        elif exists "$dir/$name.conf"; then die 'Beklenmeyen dosya kopyasi.'; fi
    done
    inspect_file "$dir/status" 1 256 || die "$WHY"
    [[ $FS_EXISTS == 1 && $FS_MODE == 600 && $FS_GID == 0 ]] || die 'Durum kaydi eksik/guvensiz.'
    mapfile -t lines < "$dir/status"
    (( ${#lines[@]} == 1 )) || die 'Gecersiz durum satiri.'
    IFS=$'\t' read -r -a row <<< "${lines[0]}"
    (( ${#row[@]} == 2 )) || die 'Gecersiz durum alanlari.'
    J_STATUS=${row[0]}; J_REBOOT=${row[1]}
    case $J_STATUS in
        APPLYING|COMMITTED|FAILED|ROLLING_BACK|ROLLED_BACK) [[ $J_REBOOT == - ]] || die 'Beklenmeyen reboot kaydi.' ;;
        ROLLING_BACK_FILES_ONLY|ROLLED_BACK_FILES_ONLY) valid_uuid "$J_REBOOT" || die 'Reboot kaydi gecersiz.' ;;
        *) die 'Bilinmeyen islem durumu.' ;;
    esac
    for name in "$dir"/*; do
        case ${name##*/} in
            manifest.tsv|status|sysctl.conf|coredump.conf) ;;
            .fh-write.*)
                # SIGKILL/power loss can leave an unpublished status temporary.
                # It is inert, never executed/adopted, but counts toward quota.
                [[ ${name##*/} =~ ^\.fh-write\.[a-zA-Z0-9]{12}$ ]] || die 'Gecersiz gecici kayit adi.'
                inspect_file "$name" 1 16384 || die "$WHY"
                [[ $FS_EXISTS == 1 && $FS_MODE == 600 && $FS_GID == 0 ]] || die 'Guvensiz gecici kayit.' ;;
            *) die "Beklenmeyen kayit dosyasi: $name" ;;
        esac
    done
}

load_history() {
    local dir file seq n latest_seq=0
    local -A seen=()
    HIST_IDS=(); HIST_STATUSES=(); HIST_REBOOTS=(); HIST_COUNT=0; HIST_PREP=0; HIST_BYTES=0; HIST_MAX=0; HIST_LATEST=''
    exists "$STATE" || return 0
    check_dirs "$STATE" required 1 || die "$WHY"
    # A crash before atomic directory publication cannot have changed host
    # configuration. Keep these preparations inert, visible and quota-bounded.
    for dir in "$STATE"/.prepare-*; do
        valid_id "${dir##*/.prepare-}" || die 'Bilinmeyen hazirlik dizini.'
        check_dirs "$dir" required 1 || die "$WHY"
        HIST_PREP=$((HIST_PREP + 1))
        (( HIST_PREP <= 64 )) || die 'Yarim hazirlik kotasi dolu; elle arsiv/inceleme gerekli.'
        for file in "$dir"/*; do
            case ${file##*/} in
                manifest.tsv|status|sysctl.conf|coredump.conf) ;;
                .fh-write.*) [[ ${file##*/} =~ ^\.fh-write\.[a-zA-Z0-9]{12}$ ]] || die 'Gecersiz hazirlik dosyasi.' ;;
                *) die "Bilinmeyen hazirlik dosyasi: $file" ;;
            esac
            inspect_file "$file" 1 16384 || die "$WHY"
            [[ $FS_EXISTS == 1 && $FS_MODE == 600 && $FS_GID == 0 ]] || die 'Guvensiz hazirlik dosyasi.'
            HIST_BYTES=$((HIST_BYTES + FS_SIZE))
            (( HIST_BYTES <= 8388608 )) || die '8 MiB toplam gecmis/hazirlik kotasi dolu.'
        done
    done
    (( HIST_PREP == 0 )) || printf 'BILGI: %s yayimlanmamis hazirlik kaydi korundu; hicbiri uygulanmis kayit olarak kullanilmaz.\n' "$HIST_PREP"
    exists "$STATE/runs" || return 0
    check_dirs "$STATE/runs" required 1 || die "$WHY"
    for dir in "$STATE/runs"/*; do
        HIST_COUNT=$((HIST_COUNT + 1))
        (( HIST_COUNT <= 64 )) || die '64 islem siniri asildi; kayitlar otomatik silinmez.'
        load_record "$dir"
        seq=$J_SEQUENCE
        [[ -z ${seen[$seq]-} ]] || die 'Tekrarlanan islem sira numarasi.'
        seen[$seq]=1
        (( seq <= HIST_MAX )) || HIST_MAX=$seq
        HIST_IDS+=("$J_ID"); HIST_STATUSES+=("$J_STATUS"); HIST_REBOOTS+=("$J_REBOOT")
        if [[ $J_STATUS != ROLLED_BACK && $J_STATUS != ROLLED_BACK_FILES_ONLY ]] && (( seq > latest_seq )); then
            latest_seq=$seq; HIST_LATEST=$J_ID
        fi
        for file in "$dir"/*; do
            n=$(stat -c %s -- "$file")
            HIST_BYTES=$((HIST_BYTES + n))
        done
        (( HIST_BYTES <= 8388608 )) || die '8 MiB gecmis siniri asildi; otomatik temizlik yok.'
    done
}

check_recovery() {
    local i
    for i in "${!HIST_IDS[@]}"; do
        case ${HIST_STATUSES[$i]} in
            COMMITTED|ROLLED_BACK) ;;
            ROLLED_BACK_FILES_ONLY)
                [[ ${HIST_REBOOTS[$i]} != "$BOOT_ID" ]] || die 'Dosya geri alimi sonrasi yeniden baslatma gerekli.' ;;
            *) die "Yarim islem var; once rollback: ${HIST_IDS[$i]} (${HIST_STATUSES[$i]})" ;;
        esac
    done
}

confirm_plan() {
    local answer phrase="APPLY $PROFILE"
    if [[ -n $APPROVE ]]; then
        [[ $APPROVE == "$PLAN_HASH" ]] || die 'Onay SHA256 guncel plandan farkli; yeni plani inceleyin.'
        return
    fi
    [[ -r /dev/tty && -w /dev/tty ]] || die 'Etkilesimli terminal yok; incelenmis plan icin --approve kullanin.'
    printf '\nYukaridaki plani uygulamak icin aynen "%s" yazin: ' "$phrase" > /dev/tty
    IFS= read -r answer < /dev/tty || die 'Onay okunamadi.'
    [[ $answer == "$phrase" ]] || die 'Iptal edildi; sistem ayarlari degismedi.'
}

create_record() {
    local run_id stamp random manifest key
    (( HIST_COUNT + HIST_PREP < 64 && HIST_BYTES + 16384 <= 8388608 )) || die 'Gecmis/hazirlik kotasi dolu; otomatik silme yapilmaz.'
    stamp=$(date -u +%Y%m%dT%H%M%S%NZ)
    IFS= read -r random < /proc/sys/kernel/random/uuid; random=${random//-/}; random=${random:0:12}
    run_id=B-$stamp-$random
    valid_id "$run_id" || die 'Gecerli islem kimligi uretilemedi.'
    check_dirs "$STATE/runs" create 1 || die "$WHY"
    STAGING=$STATE/.prepare-$run_id
    mkdir -m 700 -- "$STAGING"
    manifest=$({
        printf 'FH_BASH\t1\nversion\t%s\nid\t%s\nsequence\t%s\n' "$VERSION" "$run_id" "$((HIST_MAX + 1))"
        printf 'boot\t%s\nmachine\t%s\nprofile\t%s\ncore\t%s\nplan\t%s\n' "$BOOT_ID" "$MACHINE_HASH" "$PROFILE" "$CORE" "$PLAN_HASH"
        printf 'sysfile\t%s\t%s\ncorefile\t%s\t%s\n' "$SYS_CREATE" "$SYS_HASH" "$CORE_CREATE" "$CORE_HASH"
        for key in "${KEYS[@]}"; do printf 'sysctl\t%s\t%s\t%s\n' "$key" "${BEFORE[$key]}" "${AFTER[$key]}"; done
    }); manifest+=$'\n'
    write_private "$STAGING/manifest.tsv" "$manifest"
    write_private "$STAGING/status" $'APPLYING\t-\n'
    (( SYS_CREATE == 0 )) || write_private "$STAGING/sysctl.conf" "$SYS_TEXT"
    (( CORE_CREATE == 0 )) || write_private "$STAGING/coredump.conf" "$CORE_TEXT"
    sync -- "$STAGING"
    RUN_DIR=$STATE/runs/$run_id
    [[ ! -e $RUN_DIR && ! -L $RUN_DIR ]] || die 'Islem kimligi zaten mevcut.'
    mv -T -n -- "$STAGING" "$RUN_DIR"
    [[ ! -d $STAGING ]] || die 'Hazir kayit yayimlanamadi.'
    STAGING=''
    sync -- "$STATE/runs" "$STATE"
    TX_ACTIVE=1; TX_KIND=apply
    printf '\nISLEM: %s\n' "$run_id"
}

create_managed() {
    local path=$1 content=$2 expected=$3 tmp
    [[ $path == "$SYSFILE" || $path == "$COREFILE" ]] || die 'Yonetilen dosya izin listesi ihlali.'
    check_dirs "${path%/*}" create || die "$WHY"
    inspect_file "$path" || die "$WHY"
    (( FS_EXISTS == 0 )) || die "Eszamanli degisiklik: dosya artik mevcut: $path"
    tmp=$(mktemp "${path%/*}/.fh-stage1.XXXXXXXXXXXX")
    TMPFILES+=("$tmp")
    printf '%s' "$content" > "$tmp"
    chown 0:0 -- "$tmp"; chmod 644 -- "$tmp"
    capture restorecon -F -- "$tmp" || die "SELinux etiketi atanamadi: $tmp"
    sync -- "$tmp"
    mv -T -n -- "$tmp" "$path"
    [[ ! -e $tmp ]] || die "Dosya yayinlama cakismasi: $path"
    sync -- "${path%/*}"
    capture restorecon -F -- "$path" || die "SELinux etiketi dogrulanamadi: $path"
    inspect_file "$path" || die "$WHY"
    matches_managed "$expected" || die "Yazilan dosya dogrulanamadi: $path"
    printf 'UYGULANDI: %s\n' "$path"
}

apply_plan() {
    local key approved
    (( EUID == 0 )) || die 'apply icin sudo/root gerekli.'
    make_plan
    if (( ${#ERRORS[@]} )); then show_plan; die 'On kontrol engelledi; ayar/state yazilmadi.'; fi
    lock_state
    load_history; check_recovery
    make_plan; show_plan
    (( ${#ERRORS[@]} == 0 )) || die 'Kilit altindaki son kontrol basarisiz.'
    if (( OPS == 0 )); then say 'NO-OP: Canli ve kalici ayarlar zaten uygun; yeni islem kaydi yok.'; return; fi
    confirm_plan; approved=$PLAN_HASH
    # A user can spend minutes reviewing the prompt; recompute before creating
    # a journal or changing configuration, then require the SAME plan.
    make_plan
    [[ $PLAN_HASH == "$approved" && ${#ERRORS[@]} == 0 ]] || die 'Onaydan sonra durum degisti; plani yeniden inceleyin.'
    create_record
    (( SYS_CREATE == 0 )) || create_managed "$SYSFILE" "$SYS_TEXT" "$SYS_HASH"
    (( CORE_CREATE == 0 )) || create_managed "$COREFILE" "$CORE_TEXT" "$CORE_HASH"
    for key in "${KEYS[@]}"; do
        [[ ${BEFORE[$key]} != "${AFTER[$key]}" ]] || continue
        read_live "$key" || die "$WHY"
        [[ $VALUE == "${BEFORE[$key]}" ]] || die "Eszamanli sysctl degisikligi: $key"
        set_live "$key" "${AFTER[$key]}"
        printf 'UYGULANDI: %s = %s\n' "$key" "${AFTER[$key]}"
    done
    ERRORS=(); check_persistence 0
    for key in "${KEYS[@]}"; do
        read_live "$key" || die "$WHY"
        [[ $VALUE == "${AFTER[$key]}" ]] || block "Son canli dogrulama basarisiz: $key"
    done
    if (( ${#ERRORS[@]} )); then printf 'ENGEL: %s\n' "${ERRORS[@]}" >&2; die 'Son dogrulama basarisiz; islem geri alinabilir.'; fi
    save_status COMMITTED -
    TX_ACTIVE=0
    say 'COMMITTED: Modulun canli/kalici kontrolleri gecti. Reboot sonrasi verify calistirin.'
}

rollback_file_check() {
    inspect_file "$1" || die "$WHY"
    (( FS_EXISTS == 0 )) || matches_managed "$2" || die "ROLLBACK CAKISMASI: Sonradan degismis dosya korunuyor: $1"
}

rollback_run() {
    local i key current id=$RUN_ARG
    valid_id "$id" || die 'Gecersiz islem kimligi; dosya yolu kabul edilmez.'
    lock_state; read_identity; load_history
    RUN_DIR=$STATE/runs/$id
    [[ -d $RUN_DIR ]] || die 'Islem bulunamadi.'
    load_record "$RUN_DIR"
    [[ $J_MACHINE == "$MACHINE_HASH" ]] || die 'Kayit baska makineye ait.'
    if [[ $J_STATUS == ROLLED_BACK || $J_STATUS == ROLLED_BACK_FILES_ONLY ]]; then say 'NO-OP: Bu islem zaten geri alinmis.'; return; fi
    [[ $HIST_LATEST == "$id" ]] || die "Once en yeni aktif islemi geri alin: $HIST_LATEST"
    for i in "${!HIST_IDS[@]}"; do
        if [[ ${HIST_STATUSES[$i]} == ROLLED_BACK_FILES_ONLY && ${HIST_REBOOTS[$i]} == "$BOOT_ID" ]]; then die 'Once dosya geri alimi sonrasi yeniden baslatin.'; fi
    done
    if (( FILES_ONLY == 0 )); then
        [[ $J_BOOT == "$BOOT_ID" ]] || die 'Boot degismis. --files-only ile geri alin, sonra yeniden baslatin.'
        [[ $J_STATUS != ROLLING_BACK_FILES_ONLY ]] || die 'Baslamis dosya geri alimini --files-only ile tamamlayin.'
    fi
    # Preflight every conflict BEFORE the first rollback write.
    (( J_SYS_CREATE == 0 )) || rollback_file_check "$SYSFILE" "$J_SYS_HASH"
    (( J_CORE_CREATE == 0 )) || rollback_file_check "$COREFILE" "$J_CORE_HASH"
    if (( FILES_ONLY == 0 )); then
        for key in "${KEYS[@]}"; do
            [[ ${J_BEFORE[$key]} != "${J_AFTER[$key]}" ]] || continue
            read_live "$key" || die "$WHY"
            [[ $VALUE == "${J_BEFORE[$key]}" || $VALUE == "${J_AFTER[$key]}" ]] || die "ROLLBACK CAKISMASI: $key=$VALUE"
        done
    fi
    TX_KIND=rollback
    if (( FILES_ONLY )); then save_status ROLLING_BACK_FILES_ONLY "$BOOT_ID"; else save_status ROLLING_BACK -; fi
    TX_ACTIVE=1
    if (( FILES_ONLY == 0 )); then
        for ((i=${#KEYS[@]}-1; i>=0; i--)); do
            key=${KEYS[$i]}
            [[ ${J_BEFORE[$key]} != "${J_AFTER[$key]}" ]] || continue
            read_live "$key" || die "$WHY"; current=$VALUE
            [[ $current == "${J_BEFORE[$key]}" || $current == "${J_AFTER[$key]}" ]] || die "Eszamanli rollback cakismasi: $key"
            set_live "$key" "${J_BEFORE[$key]}"
            printf 'GERI ALINDI: %s\n' "$key"
        done
    fi
    if (( J_CORE_CREATE )); then
        rollback_file_check "$COREFILE" "$J_CORE_HASH"
        if (( FS_EXISTS )); then rm -- "$COREFILE"; sync -- "${COREFILE%/*}"; fi
        ! exists "$COREFILE" || die 'Coredump dosyasi geri alinamadi.'
    fi
    if (( J_SYS_CREATE )); then
        rollback_file_check "$SYSFILE" "$J_SYS_HASH"
        if (( FS_EXISTS )); then rm -- "$SYSFILE"; sync -- "${SYSFILE%/*}"; fi
        ! exists "$SYSFILE" || die 'Sysctl dosyasi geri alinamadi.'
    fi
    if (( FILES_ONLY )); then
        save_status ROLLED_BACK_FILES_ONLY "$BOOT_ID"
        say 'ROLLED_BACK_FILES_ONLY: Kalici dosyalar geri alindi; simdi yeniden baslatin.'
    else save_status ROLLED_BACK -; say 'ROLLED_BACK: Bu islemin degisiklikleri geri alindi.'; fi
    TX_ACTIVE=0
    say 'Bos ayar dizinleri ve root a ozel kurtarma kayitlari korundu.'
}

audit_extra() {
    local label path unit
    say ''; say 'EK SALT OKUNUR GOZLEMLER (eksik arac = UNKNOWN):'
    for label in secure_boot root_mount block_devices listening_sockets active_zones zone_rules; do
        case $label in
            secure_boot) capture mokutil --sb-state || : ;;
            root_mount) capture findmnt --target / --output SOURCE,FSTYPE,OPTIONS || : ;;
            block_devices) capture lsblk --output NAME,TYPE,FSTYPE,MOUNTPOINTS || : ;;
            listening_sockets) capture ss -lntu || : ;;
            active_zones) capture firewall-cmd --get-active-zones || : ;;
            zone_rules) capture firewall-cmd --list-all-zones || : ;;
        esac
        printf '\n[%s]\n%s\n' "$label" "$CAPTURE"
    done
    for path in /sys/kernel/security/lockdown /sys/power/mem_sleep /proc/acpi/wakeup /proc/cmdline; do
        printf '\n[%s]\n' "$path"
        if [[ -r $path ]]; then head -c 12000 -- "$path"; printf '\n'; else say UNKNOWN; fi
    done
    for unit in auditd.service sshd.service usbguard.service fapolicyd.service fwupd-refresh.timer docker.service; do
        unit_state "$unit" || :
        printf '\n[%s]\n%s\n' "$unit" "$CAPTURE"
    done
    say 'Firewall aktifligi her kuralin guvenli oldugunu kanitlamaz.'
    say 'Disk sifreleme, TPM unsealing, pil, termal veya performans testi yapilmaz.'
}

main() {
    local c i item
    parse_args "$@"
    if [[ $ACTION == packages ]]; then packages; return; fi
    for c in stat sha256sum cat head tr timeout uname; do
        command -v "$c" >/dev/null 2>&1 || die "Temel arac eksik: $c; otomatik kurulum yok."
    done
    case $ACTION in
        audit)
            make_plan
            say 'AUDIT: Salt okunur inceleme; asagidaki hedefler henuz uygulanmadi.'
            for item in "${FACTS[@]}"; do printf 'BILGI: %q\n' "$item"; done
            show_plan; audit_extra
            if (( EUID == 0 )) && exists "$STATE"; then
                load_history
                for i in "${!HIST_IDS[@]}"; do printf '%s %s\n' "${HIST_IDS[$i]}" "${HIST_STATUSES[$i]}"; done
            fi
            say 'AUDIT tamamlandi; cikis 0 engel olmadigi anlamina gelmez.' ;;
        plan|verify)
            make_plan; show_plan
            (( ${#ERRORS[@]} == 0 )) || return 2
            if [[ $ACTION == verify ]]; then
                if exists "$STATE"; then
                    (( EUID == 0 )) || die 'Ozel islem gecmisini dogrulamak icin sudo ile verify gerekir.'
                    load_history; check_recovery
                fi
                (( OPS == 0 )) || { say 'NOT VERIFIED: Planlanan degisiklikler henuz var.'; return 3; }
                say 'VERIFIED: Yalniz bu modulun ayarlari dogrulandi.'
            fi ;;
        apply) apply_plan ;;
        history)
            (( EUID == 0 )) || die 'Ozel gecmisi okumak icin sudo gerekli.'
            load_history
            if (( HIST_COUNT == 0 )); then say 'Kayitli Bash islemi yok.'; fi
            for i in "${!HIST_IDS[@]}"; do printf '%s %s\n' "${HIST_IDS[$i]}" "${HIST_STATUSES[$i]}"; done ;;
        rollback) rollback_run ;;
    esac
}

main "$@"
