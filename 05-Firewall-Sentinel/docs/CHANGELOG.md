# Revision history

## 0.9.0-alpha2-review5 — Fedora field-verified alpha (2026-11-21)

- Corrected nftables payload construction in `sync_trusted_interfaces()`: actual LF between `flush set` and `add element` commands, rather than literal `\n`.
- Added seven focused mocked regressions for empty/multiple/trusted interface sets, precheck-before-load and fail-closed parser behavior.
- Retained nine review4 session/zone regressions and original strict TTY audit gate.
- Passed live Fedora 44 preflight, physical-TTY `apply` → `COMMITTED`, explicit `verify` → `VERIFIED`, and normal-session monitoring → `INFO`.
- Post-apply service check passed; reboot and optional-feature acceptance remain pending.

## 0.9.0-alpha2-review4

- Kept fail-closed session protection and improved error explaining why `Class=manager` audit context is not evidence of local-seat provenance.
- Corrected firewalld live zone target inspection and introduced nine mocked regressions.
- Physical-TTY apply exposed literal-LF bug. Failure was rolled back.

## 0.9.0-alpha2-review3

- Prior strict-security baseline; verified source/static and installed runtime; GUI-terminal session mutating operations denied. Replaced by later review revisions.

**Upgrade note:** The review5 Python **application runtime** differs from review4 only in version text and trusted-interface payload newline handling. Documentation, smoke tests, fixture sanitization and repository layout are separate packaging work. The source byte hash is preserved in this GitHub package.
