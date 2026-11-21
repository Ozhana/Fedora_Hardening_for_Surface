#!/usr/bin/bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$ROOT"
if (( EUID == 0 )); then
    echo 'STOP: offline tests must run as a normal user' >&2
    exit 2
fi
sha256sum --check SHA256SUMS
/usr/bin/python3 -B -I ./tests/test_static.py
/usr/bin/python3 -B -I ./tests/test_review4_regressions.py
/usr/bin/python3 -B -I ./tests/test_review5_regressions.py
/usr/bin/python3 -B -I ./tests/test_documentation_contract.py
bash -n ./install-preflight.sh
bash -n ./scripts/test-offline.sh
printf '
OFFLINE_TESTS_PASS: SHA256 + static + 9 review4 + 7 review5 + 5 doc contract + bash syntax
'
