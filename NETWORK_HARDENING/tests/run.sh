#!/usr/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd -- "$HERE/.." && pwd -P)
/usr/bin/bash -n "$ROOT/aegis-network.sh"
python3 "$HERE/test_static.py"
/usr/bin/bash "$HERE/test_functions.sh"
if (( EUID == 0 )); then
    /usr/bin/bash "$HERE/test_apply_sim.sh"
else
    echo 'SKIP root apply/verify/rollback simulation (run tests with sudo for this case)'
fi
echo ALL_TESTS_PASS
