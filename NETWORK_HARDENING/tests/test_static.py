#!/usr/bin/python3
from __future__ import annotations

import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "aegis-network.sh"
TEXT = SCRIPT.read_text(encoding="utf-8")


class StaticTests(unittest.TestCase):
    def test_bash_syntax(self) -> None:
        p = subprocess.run(["/usr/bin/bash", "-n", str(SCRIPT)], text=True, capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_version(self) -> None:
        p = subprocess.run(["/usr/bin/bash", "-p", "--", str(SCRIPT), "version"], text=True, capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "0.7.0-rc4")

    def test_required_actions_present(self) -> None:
        for action in ("audit", "plan", "apply", "verify", "status", "history", "rollback", "export", "verify-install"):
            self.assertIn(action, TEXT)

    def test_old_unsafe_mechanisms_absent(self) -> None:
        forbidden = (
            "firewall-cmd --lockdown-on",
            "firewall-cmd --set-log-denied=all",
            '<icmp-block name="echo-request"',
            '<zone target="DROP"',
            '<command name="/usr/bin/python3*"',
            '<command name="/usr/sbin/iptables*"',
            '<command name="/usr/sbin/nft*"',
            "DefaultDependencies=no",
            "Wants=firewalld.service docker.service",
            "Lockdown=no",
        )
        for token in forbidden:
            self.assertNotIn(token, TEXT, token)

    def test_transaction_safety_primitives_present(self) -> None:
        for token in (
            "set -Eeuo pipefail",
            "IFS=$'\\n\\t'",
            "flock -n 9",
            "systemd-run --quiet --collect",
            "ROLLBACK_SECONDS=180",
            "snapshot_transaction",
            "emergency_restore",
            "check_rollback_conflicts",
            "sync -f",
        ):
            self.assertIn(token, TEXT)

    def test_layer_ownership_boundaries(self) -> None:
        # These strings are allowed in audit output and explanatory text, but not in the generated sysctl function body.
        start = TEXT.index("write_sysctl_policy()")
        end = TEXT.index("write_nm_policy()", start)
        body = TEXT[start:end]
        for forbidden in (
            "net.ipv4.ip_forward",
            "net.ipv6.conf.all.forwarding",
            "net.ipv4.tcp_congestion_control",
            "net.core.default_qdisc",
            "net.ipv4.tcp_mtu_probing",
            "net.ipv6.conf.all.accept_ra",
            "src_valid_mark",
        ):
            self.assertNotIn(forbidden, body)

    def test_no_deprecated_nmcli_read_only_property(self) -> None:
        self.assertNotIn("nmcli -g connection.read-only", TEXT)
        self.assertNotIn("-g connection.read-only", TEXT)
        self.assertIn("nm_profile_property_read", TEXT)

    def test_target_query_semantics_and_commit_order(self) -> None:
        self.assertNotIn('firewall-cmd --zone="$z" --get-target', TEXT)
        self.assertIn('firewall-cmd --permanent --zone="$zone" --get-target', TEXT)
        self.assertIn('zone_runtime_target', TEXT)
        apply_start = TEXT.index('apply_hardening()')
        apply_body = TEXT[apply_start:TEXT.index('plan_hardening()', apply_start)]
        self.assertLess(apply_body.index('verify_hardening'), apply_body.index('save_managed_identity'))
        self.assertIn('managed-profile-uuid', TEXT)
        self.assertIn('managed-profile-device', TEXT)
        self.assertIn('managed-latest-transaction', TEXT)
        self.assertIn('managed_identity_is_committed', TEXT)


    def test_systemd_sysctl_interface_persistence_model(self) -> None:
        start = TEXT.index("write_sysctl_policy()")
        end = TEXT.index("write_nm_policy()", start)
        body = TEXT[start:end]
        for token in (
            "net.ipv4.conf.*.accept_redirects = 0",
            "net.ipv4.conf.*.secure_redirects = 0",
            "net.ipv4.conf.*.send_redirects = 0",
            "net.ipv4.conf.*.accept_source_route = 0",
            "net.ipv6.conf.*.accept_redirects = 0",
            "net.ipv6.conf.*.accept_source_route = -1",
        ):
            self.assertIn(token, body)
        self.assertNotIn('sysctl --load="$SYSCTL_FILE"', TEXT)
        self.assertIn("[[ $key == *'*'* || $key == *'?'* || $key == *'['* ]] && continue", TEXT)

    def test_no_embedded_cr_or_nul(self) -> None:
        raw = SCRIPT.read_bytes()
        self.assertNotIn(b"\r", raw)
        self.assertNotIn(b"\x00", raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
