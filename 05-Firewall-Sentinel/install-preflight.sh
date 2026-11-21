#!/usr/bin/bash
set -Eeuo pipefail

if (( EUID == 0 )); then
  printf 'ERROR: run as your regular user, not root.\n' >&2
  exit 2
fi

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DEST_DIR='/usr/local/libexec/aegis/firewall-sentinel'
DEST="$DEST_DIR/aegis-firewall-sentinel.py"
cd -- "$HERE"

printf '\n[1/8] SOURCE INTEGRITY\n'
sha256sum --check SHA256SUMS
printf '\n[2/8] OFFLINE REGRESSIONS\n'
/usr/bin/python3 -m py_compile aegis-firewall-sentinel.py tests/test_static.py tests/test_review4_regressions.py tests/test_review5_regressions.py
/usr/bin/python3 -I tests/test_static.py
/usr/bin/python3 -I tests/test_review4_regressions.py
/usr/bin/python3 -I tests/test_review5_regressions.py

printf '\n[3/8] SUDO AUTHORIZATION\n'
sudo -v
printf '\n[4/8] NATIVE NFT PARSER CHECK — NO FIREWALL MUTATION\n'
# `--check` parses/validates the whole synthetic transaction but does not load it.
# Run before replacing the installed runtime. Do not execute `nft -f` here.
sudo /usr/sbin/nft --check --file - <<'AEGIS_NFT_SYNTAX'
add table inet aegis_review5_syntax_probe
add set inet aegis_review5_syntax_probe trusted_ifaces { type ifname; }
flush set inet aegis_review5_syntax_probe trusted_ifaces
add element inet aegis_review5_syntax_probe trusted_ifaces { "wlp0s20f3" }
AEGIS_NFT_SYNTAX

printf '\n[5/8] ATOMIC ROOT-OWNED RUNTIME REPLACEMENT\n'
sudo install -d -o root -g root -m 0755 "$DEST_DIR"
# A unique root-owned stage file is used so no partially-written installed script is visible.
# mktemp is root-run; its output is a path in the protected root-owned directory.
staged="$(sudo mktemp "$DEST_DIR/.aegis-stage.XXXXXXXX")"
cleanup() { if [[ -n "${staged:-}" ]]; then sudo rm -f -- "$staged"; fi; }
trap cleanup EXIT
sudo install -o root -g root -m 0755 -- ./aegis-firewall-sentinel.py "$staged"
sudo restorecon -F -- "$staged"
sudo mv -fT -- "$staged" "$DEST"
staged=''
sudo restorecon -F -- "$DEST"

printf '\n[6/8] INSTALLED SHA256\n'
/usr/bin/python3 -I "$DEST" verify-install --source ./aegis-firewall-sentinel.py

printf '\n[7/8] PLATFORM AND CONFIG VALIDATION\n'
sudo /usr/bin/python3 -I "$DEST" validate

printf '\n[8/8] PLAN - NO FIREWALL MUTATION\n'
sudo /usr/bin/python3 -I "$DEST" plan

printf '\nPREFLIGHT_OK: runtime updated; Sentinel firewall policy NOT applied.\n'
printf 'NEXT: read README_TR.md and log in via physical virtual console for strict apply.\n'
