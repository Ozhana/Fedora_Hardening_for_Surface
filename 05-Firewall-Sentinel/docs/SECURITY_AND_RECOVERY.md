# Security model, limitations and recovery

## Trust boundaries

1. **Host boundary:** root-owned runtime path `/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py`, explicit `/usr/bin/python3 -I`, root-only systemd files/config and state manifest.
2. **Privilege boundary:** changing operations require `sudo`, the current local active `Class=user`, `Type=tty` systemd-logind session and an audit relationship to the invoking process. A graphical terminal inherited from a `Class=manager` audit session was correctly refused on the tested Fedora machine; an active physical TTY worked. Do not bypass the check to make a GUI call succeed.
3. **Firewall boundary:** base AEGIS Network Hardening owns firewalld zones/profile/sysctls. Sentinel owns separate nftables tables only. Avoid competing global nftables writers or `flush ruleset`.
4. **Rollback boundary:** apply stores transaction snapshots, schedules a temporary guard and runs post-apply verification and manifest sealing before committing. Failed apply attempts *attempt* automatic restore. Inspect proof of rollback; never assume a failed start is harmless.
5. **Trust boundary for network identity:** trusted LAN is dynamically selected from the reviewed NetworkManager connection UUID. Do not hard-code a user's UUID in public examples or tests.

**Emergency trust boundary:** `quarantine-on --force-emergency` and `panic-off` use a distinct weaker interactive-TTY/loginuid break-glass check rather than the full active-logind-session audit gate. Neither has been field-accepted. This distinction is intentional and must not be hidden by documentation.

## What is NOT proven

- One real-hardware Fedora 44 reboot **passed** as of 2026-11-21 (VERIFIED, monitor INFO, five active units, both nftables tables, DNS working, zero failed units). Broader boot-order failure injection and multiple-hardware persistence remain **untested**.
- No verified actual printing after applying Sentinel. CUPS and Avahi service health is not a printer functional test.
- `strict-dot-resolver` rejected preflight on the field host; current DNS is resolved through LAN infrastructure with systemd-resolved DoT disabled and DNSSEC unsupported. Direct DNS port 53 remains `PASSTHROUGH`.
- VPN kill-switch, persistent quarantine, emergency panic, blocklist and cgroup isolation remain experimental; none should be inferred safe from a base `apply`/`verify` PASS.
- `INFO` listeners on UDP 5353 (Avahi) and TCP/UDP 5355 (systemd-resolved) are not by themselves evidence of remotely accessible vulnerabilities; nftables inbound policy must be examined before making exposure claims.
- No formal third-party independent security audit or production support guarantee exists.

## Recovery on FAILED/STOP (read-only first)

```bash
sudo journalctl -b -u aegis-firewall-sentinel.service -n 100 --no-pager -o short-iso
sudo find /var/lib/aegis/firewall-sentinel/transactions -maxdepth 2 -type f   \( -name status -o -name rollback.reason \) -print -exec cat {} \;
sudo test -f /etc/aegis/firewall-sentinel/policy.json && echo POLICY_PRESENT || echo POLICY_ABSENT
sudo nft list tables
systemctl show NetworkManager.service -p ActiveState -p SubState -p Result
```

If failure produced `ROLLED_BACK`, compare actual policy file, nft table inventory and NetworkManager state against the pre-apply baseline. The older review4 failure did leave a remembered `failed` unit result even after policy rollback. Only after verifying the rollback is complete is `sudo systemctl reset-failed aegis-firewall-sentinel.service` an appropriate way to clear that historical failed flag; it is **not** a repair for an active fault.

## Intentional rollback of a committed change

**Network-changing operation.** Review `history` and the exact target transaction first. Work from an active physical local TTY, not SSH or a desktop pseudoterminal. The code's `rollback [TX_ID]` command prompts for `ROLLBACK <TX_ID> <SHA256_OF_TX_PLAN_JSON>` and checks the requested transaction before applying conflict-aware restoration. Never guess the target ID and do not run it solely to clean an informational monitor result.

A generic `sudo systemctl restart NetworkManager` is **not** a rollback and can interrupt connectivity. A system-wide nftables flush is forbidden. Use the original base layer's documented recovery path when the base owner, not Sentinel, is responsible.

## Open items before stable release

- Repeat guarded hardware reboot after any future release/upgrade; post-boot `verify`, `monitor-now`, DNS, service order and physical printer checks remain required per target host.
- Confirm printing with an actually configured printer; retain CUPS/Avahi unless separately reviewed.
- Adversarially test NetworkManager restarts, disconnections/reconnections, foreign hook drift, and counter/watcher behavior.
- Separately validate each opt-in mode (DoT, VPN, quarantine, blocklist, cgroup) before considering it production-ready.
