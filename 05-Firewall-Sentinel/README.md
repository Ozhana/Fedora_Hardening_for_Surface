# 05 — AEGIS Firewall Sentinel

**Version:** `0.9.0-alpha2-review5` (strict)  
**Platform:** Fedora 44 Workstation; native systemd + firewalld + nftables  
**Required earlier layer:** [04 — AEGIS Network Hardening](../04-Network-Hardening), `0.7.0-rc4`  
**Operating guides:** [English](docs/INSTALL_EN.md) · [Türkçe](README_TR.md) · [Operations](docs/OPERATIONS.md) · [Safety & recovery](docs/SECURITY_AND_RECOVERY.md)  
**Licence:** [Repository MIT licence](../LICENSE)

> **Status: field-verified alpha, not production-certified.** On a Fedora 44 Surface Pro 9, 21 November 2026, the strict physical-TTY `apply` completed with `COMMITTED`, independent `verify` returned `VERIFIED`, and a graphical-session `monitor-now` returned `INFO`. NetworkManager, firewalld, CUPS, Avahi, and DNS resolution remained functional. **Reboot persistence, printing to an actual printer, strict DoT, VPN kill-switch, quarantine, and emergency active-response operations remain untested.**

## Purpose / scope

Sentinel is a **host egress policy layer** atop AEGIS Network Hardening. The base layer continues to own firewalld zones, reviewed NetworkManager bindings, and network sysctls. Sentinel owns its own `inet aegis_sentinel` nftables table, its own configuration, unit files, dynamic trust-dispatcher hooks, and limited RAM-only response tables. It does **not** rewrite the base hardening configuration and does **not** flush the global nftables ruleset.

Default reviewed policy:

| Control | Default |
|---|---|
| Outbound LLMNR 5355, NAT-PMP/PCP 5351 | Denied |
| mDNS / SSDP / WS-Discovery | Denied outside reviewed connection's trusted interface set |
| LAN SMB, RPC, NetBIOS egress | Denied unless explicitly allowed |
| Direct UDP/TCP DNS 53 | **PASSTHROUGH** (not blocked) |
| Strict DoT, VPN kill-switch, quarantine | **OFF** |
| Live drop/reject inspection | Rate-limited NFLOG group 10; not a disk packet logger |
| Drift monitoring | systemd path + timer |

**DNS disclosure:** A successful DNS lookup does **not** imply DNS encryption. The verified Fedora host resolved through its LAN router with DNSOverTLS disabled. Do not enable strict DoT until you have configured and validated a supported encrypted resolver.

**Printers:** CUPS and Avahi remained running; no printers had yet been configured on the freshly installed test machine. A physical printer test remains outstanding.

## Installation, safest path

Run in a **local normal-user desktop terminal**; do not execute the full workflow as root:

```bash
# Install the prerequisite 04-Network-Hardening first; it must pass its own verification.
git clone https://github.com/Ozhana/Fedora_Hardening_for_Surface.git
cd Fedora_Hardening_for_Surface/05-Firewall-Sentinel
sha256sum --check SHA256SUMS
bash ./install-preflight.sh
```

`install-preflight.sh` verifies checksums, static/regression tests, a **non-mutating** nftables parser probe, the root-owned Python runtime, and platform/configuration. It updates the installed runtime but **does not apply the firewall policy**. Do not proceed unless you see `PREFLIGHT_OK`.

**Then log in on a new physical Linux virtual console**, e.g. `Ctrl+Alt+F3`, using the ordinary user (not `su` or `sudo -i`). Confirm `tty` prints `/dev/tty3` (or similar) and:

```bash
loginctl show-session self -p Class -p Type -p Active -p Remote -p Seat
# Expect: Class=user, Type=tty, Active=yes, Remote=no, Seat=seat0
sudo /usr/bin/python3 -I /usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py apply
```

Review the **current plan**, then type the exact `APPLY <PLAN_SHA256>` requested on that same physical TTY. Do **not** reuse the hash from someone else's machine. A graphical `/dev/pts/*` terminal is intentionally rejected for changing operations. Do **not** add `--strict-dot-resolver` unless its prerequisites are genuinely met.

Only after `COMMITTED:` appears, still on that TTY:

```bash
sudo /usr/bin/python3 -I /usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py verify
```

Expect `VERIFIED: ...` and exit code 0. Return to the desktop and inspect [Operations](docs/OPERATIONS.md). Do not reboot immediately: check internet/DNS/printer dependencies, and plan a supervised boot-persistence test.

## Safe everyday commands

```bash
AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py
sudo /usr/bin/python3 -I "$AEGIS" status
sudo /usr/bin/python3 -I "$AEGIS" verify
sudo /usr/bin/python3 -I "$AEGIS" monitor-now
sudo /usr/bin/python3 -I "$AEGIS" history
sudo /usr/bin/python3 -I "$AEGIS" plan
```

`monitor-now` can report `INFO WILDCARD_LISTENERS` for `avahi-daemon` 5353 and `systemd-resolved` 5355; a listener socket by itself is **not evidence that a remote attacker can reach that port**. See the [Security and recovery guide](docs/SECURITY_AND_RECOVERY.md).

## Testing and provenance

- Offline: static tests + 9 review4 regressions + 7 review5 nftables regressions passed.
- Fedora 44: preflight `nft --check`, `validate`, `plan`, strict physical-TTY `apply`, `verify`, and post-apply `monitor-now` passed (2026-11-21).
- Review5 fixes literal `\n` in `sync_trusted_interfaces()` that previously broke `nft --check`; review4 had rolled back safely.
- **No reboot-persistence PASS yet.** Do not label this a stable release or claim complete hardening.

Run offline tests without touching the firewall:

```bash
bash ./scripts/test-offline.sh
```

See [field acceptance evidence](docs/FIELD_ACCEPTANCE.md) and [change history](docs/CHANGELOG.md). No machine-specific UUIDs, router addresses, process logs, or personal paths are committed to this repository.
