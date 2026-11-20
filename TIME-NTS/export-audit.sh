#!/usr/bin/bash -p
# Run as your desktop user. Root never opens a Desktop log pathname.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
[[ $- == *p* ]] || { printf 'Use /usr/bin/bash -p -- ./export-audit.sh\n' >&2; exit 2; }
(( EUID != 0 )) || { printf 'Run without sudo; only the audit child requests sudo.\n' >&2; exit 2; }
BASE=${BASH_SOURCE[0]%/*}
[[ $BASE != "${BASH_SOURCE[0]}" ]] || BASE=.
cd -P -- "$BASE"
BASE=$PWD
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset BASH_ENV ENV LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT
# File creation here is unprivileged, not an elevated log writer.
if command -v xdg-user-dir >/dev/null 2>&1; then DESKTOP=$(xdg-user-dir DESKTOP); else DESKTOP=$HOME/Desktop; fi
[[ $DESKTOP == /* && -d $DESKTOP && ! -L $DESKTOP ]] || { printf 'Desktop directory is missing or is a symlink; no guessed directory created.\n' >&2; exit 2; }
LOGDIR=$DESKTOP/LOG_FILES
[[ ! -L $LOGDIR ]] || { printf 'LOG_FILES is a symlink; refusing.\n' >&2; exit 2; }
if [[ ! -e $LOGDIR ]]; then mkdir -m 700 -- "$LOGDIR"; fi
[[ -d $LOGDIR && -O $LOGDIR ]] || { printf 'LOG_FILES must be your directory.\n' >&2; exit 2; }
REPORT=$(mktemp "$LOGDIR/time-nts-audit.XXXXXXXX.txt")
printf 'Report: %s\n' "$REPORT"
# The user-owned tee process opens REPORT; sudo receives no output pathname.
if sudo /usr/bin/bash -p -- "$BASE/aegis-time-nts.sh" audit 2>&1 | tee -- "$REPORT"; then
    exit 0
else
    rc=$?
    printf 'Audit returned %s; available diagnostics were saved.\n' "$rc" >&2
    exit "$rc"
fi
