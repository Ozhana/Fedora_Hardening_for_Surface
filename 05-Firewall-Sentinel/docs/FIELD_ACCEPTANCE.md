# Fedora 44 field acceptance — sanitized, 2026-11-21

**Evidence:** User-supplied Fedora terminal outputs and physical-console screenshots during the local test session; this is a summary, not a substitute for raw evidence or an independent audit. Sensitive UUIDs, local paths, private IPs and personal identifiers are intentionally omitted.

| Test | Recorded outcome |
|---|---|
| Source SHA256 / root-owned `verify-install` | PASS |
| Static tests | PASS |
| Review4 regressions | 9 / 9 PASS |
| Review5 regressions | 7 / 7 PASS |
| Fedora `nft --check --file -` parser preflight | PASS |
| `validate` and `plan` | PASS |
| Local physical TTY / audit gate | PASS (GUI manager session denied by design) |
| Review5 `apply` / transaction commit | `COMMITTED` |
| Explicit independent `verify` | `VERIFIED` |
| `monitor-now` | `INFO`, no reported `CRITICAL` |
| Sentinel systemd policy service | `loaded`, `active (exited)`, `Result=success` |
| Monitor timer / path | both `active (waiting)`, `Result=success` |
| NetworkManager / firewalld | both `active` |
| Resolver functionality | `resolvectl query` SUCCESS |
| DNS encryption | NOT ENABLED on field host; DoT `no` |
| CUPS / Avahi | `active (running)` |
| Printer destinations | none configured after clean Fedora installation |
| Actual physical printing | NOT TESTED |
| Reboot persistence | **NOT TESTED** |
| Optional strict DoT/VPN/quarantine/active response | NOT TESTED |

## Root-cause history

- Review3 & review4 desktop GUI terminal: changing operations were denied because the calling process belonged to a systemd user-manager audit session. This is a strict provenance design choice. Physical local TTY login was used successfully.
- Review4 physical TTY apply: `nft --check` failed because trusted-interface command builder emitted the literal backslash + n bytes rather than real newline bytes. Automatic transaction recovered with `ROLLED_BACK` and NetworkManager remained active. systemd continued to remember the historical failed unit result.
- Review5: single-line source fix created actual LF separators; native parser and 7 additional tests passed; after confirming rollback and clearing the historical failed systemd state, the physical TTY `apply` and independent `verify` succeeded.

## Evidence boundary

`COMMITTED` + `VERIFIED` confirms the policy files, runtime table, sealed manifest and base network layer in the observed boot. It does **not** prove every packet flow, printer workflow, DNS privacy or boot persistence under all conditions. Do not market this alpha as production-certified.
