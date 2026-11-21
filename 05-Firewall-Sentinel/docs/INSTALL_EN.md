# Fedora 44 installation and acceptance (EN)

## Requirements

Fedora 44 mutable Workstation; physical access to a Linux VT/TTY; regular user with `sudo`; working `firewalld`, `nftables`, NetworkManager and systemd; **installed and verified** AEGIS Network Hardening `0.7.0-rc4` from the sibling `04-Network-Hardening`. Do not install solely over SSH or remote desktop. Prefer a maintenance window and a physical keyboard.

## 1. Verify source and offline tests

```bash
git clone https://github.com/Ozhana/Fedora_Hardening_for_Surface.git
cd Fedora_Hardening_for_Surface/05-Firewall-Sentinel
sha256sum --check SHA256SUMS
bash ./scripts/test-offline.sh
```

## 2. Preflight (ordinary GUI-terminal user)

```bash
bash ./install-preflight.sh
```

Checks: file hashes; static tests; 9+7 behavior regressions; native **non-mutating** `nft --check` parser test; atomic root-owned runtime installation; SHA-256 comparison; platform validation; plan preview. **Preflight changes the installed Python executable but does NOT install or activate the firewall policy.** Require `PREFLIGHT_OK` before continuing.

If a prior attempt left a failed systemd unit, inspect its transaction rollback, policy files, nftables table inventory and NetworkManager before deciding whether `systemctl reset-failed` is appropriate; it is not an automatic universal remedy.

## 3. Apply (new local physical console login)

Use `Ctrl+Alt+F3` and **log in as the regular user**. A desktop pseudoterminal (`/dev/pts/*`) is deliberately not accepted for firewall-changing actions. From the **physical** console:

```bash
tty
loginctl show-session self -p Class -p Type -p Active -p Remote -p Seat
# Require Class=user, Type=tty, Active=yes, Remote=no, Seat=seat0
sudo /usr/bin/python3 -I /usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py apply
```

Inspect the actual current plan, then supply its exact requested `APPLY <PLAN_SHA256>` approval. Do not hard-code or copy an old or another user's hash. Default direct DNS port 53 is `PASSTHROUGH`; do not use `--strict-dot-resolver` without passing its cryptographic resolver preconditions.

## 4. Verify (same physical console)

Proceed only if `COMMITTED:` was displayed:

```bash
sudo /usr/bin/python3 -I /usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py verify
```

Require `VERIFIED:` and exit 0. Then return to desktop and run the post-apply checks documented in [OPERATIONS.md](OPERATIONS.md). Keep printing/CUPS/Avahi availability in mind. Do not reboot until confirming normal networking and having a physical recovery path.

## 5. Upgrade, recovery and reboot

For upgrades verify the *new* source and installed runtime hash, run preflight, review `plan`, re-apply only from an active physical VT and re-verify. The installer does not unconditionally uninstall or clear policies. For drift, failure, manual rollback or recovery commands, see [SECURITY_AND_RECOVERY.md](SECURITY_AND_RECOVERY.md).

**Reboot persistence has not yet passed a field acceptance test.** It must be tested separately on physical Fedora hardware, with post-boot `verify`, `monitor-now`, NetworkManager, DNS, and printer checks.
