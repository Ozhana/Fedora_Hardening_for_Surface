#!/usr/bin/bash -p
set -Eeuo pipefail
IFS=$'\n\t'
BASE=${BASH_SOURCE[0]%/*}
cd -P -- "$BASE/.."
bash -n aegis-time-nts.sh
bash -n export-audit.sh
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck --shell=bash aegis-time-nts.sh export-audit.sh tests/run.sh
else
    printf 'NOT RUN: ShellCheck is not installed.\n' >&2
fi
exec python3 -B -m unittest discover -s tests -p 'test_*.py' -v
