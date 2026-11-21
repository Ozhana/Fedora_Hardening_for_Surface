# Operations — commands and expected behavior

**Complete command/flag catalog with exact or conditional expected outputs:** [English–Turkish two-column README](../README.md) · [Arabic manual](../README_AR.md).

**This is an alpha security tool.** Routine read-only monitoring may run from a GUI terminal. Destructive or connectivity-changing actions are **not** routine checks. Review `--help`, make a current plan and use a physical TTY where required.

## Everyday verification / Günlük denetim

```bash
AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py
sudo /usr/bin/python3 -I "$AEGIS" status
sudo /usr/bin/python3 -I "$AEGIS" verify
sudo /usr/bin/python3 -I "$AEGIS" monitor-now
sudo /usr/bin/python3 -I "$AEGIS" history
sudo /usr/bin/python3 -I "$AEGIS" plan
```

`verify` confirms managed files, manifest, base hardening layer and live rule semantics. `monitor-now` reports drift and visibility information. `INFO WILDCARD_LISTENERS` is informational; an open local socket does not establish external reachability. Unknown `CRITICAL`, unexpected `WARNING` or failed verification demands investigation, not blindly resetting the baseline.

## systemd and connectivity / servis ve bağlantı

```bash
systemctl show aegis-firewall-sentinel.service -p LoadState -p ActiveState -p SubState -p Result
systemctl show aegis-firewall-sentinel-monitor.timer aegis-firewall-sentinel-monitor.path -p ActiveState -p SubState -p Result
systemctl is-active NetworkManager firewalld cups avahi-daemon
sudo nft list tables
resolvectl status
resolvectl query example.org
lpstat -r
lpstat -p -d
```

`active (exited)` for the policy loader and `active (waiting)` for the monitor units can be healthy. After a fresh Fedora installation, `No destinations added` means no CUPS printers are configured, not proof that Sentinel broke printing. Physical printing must be tested separately.

## Useful CLI groups / komut aileleri

| Area | Commands | Notes |
|---|---|---|
| View & inspect | `version`, `packages`, `status`, `history`, `audit`, `validate`, `plan`, `verify`, `monitor-now` | Some inspection commands still require root; see `--help`. |
| Live inspection | `watch` | NFLOG group 10; rate-limited; observe locally with care. |
| Temporary IP response | `block-ip IP --ttl 24h`, `unblock-ip IP`, `list-blocked` | RAM-only; not exercised in field acceptance. Misuse can block critical endpoints. |
| Advanced LAN isolation | `isolate-cgroup-lan`, `unisolate-cgroup-lan`, `rebind-cgroup-lan` | RAM-only and version-/cgroup-sensitive; not field-tested. |
| Strong isolation | `quarantine-on`, `quarantine-off`, `panic-off`, `apply --vpn-only`, `apply --strict-dot-resolver` | **Not acceptance-tested.** High risk of self-disconnection. |
| Recovery | `rollback [TX_ID]` | Needs current local TTY authentication and exact `ROLLBACK ...` confirmation. |
| Internal / systemd only | `network-gate`, `runtime-load`, `trust-sync`, `emergency-rollback` | **Do not invoke manually** as ordinary diagnostics. |

Examples deliberately omit actual mutating commands for high-risk modes: consult code and current generated `plan` and test in an isolated environment before enabling them.

## Read-only issue capture / salt-okunur arıza kanıtı

```bash
sudo journalctl -b -u aegis-firewall-sentinel.service -n 100 --no-pager -o short-iso
sudo find /var/lib/aegis/firewall-sentinel/transactions -maxdepth 2 -type f   \( -name status -o -name rollback.reason \) -print -exec cat {} \;
sudo nft list tables
systemctl --failed --no-pager
systemctl show NetworkManager.service -p ActiveState -p SubState -p Result
```

Review logs before posting them publicly; network UUIDs, interface identifiers and private addresses can be present. One physical Fedora 44 reboot persistence test passed on 2026-11-21; read-only checks do not substitute for repeated platform testing or a real physical printer test.
