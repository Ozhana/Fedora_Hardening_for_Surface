#!/usr/bin/python3 -I
"""Offline fail-closed regressions for review4. Never writes live system state."""
from __future__ import annotations
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import os
import stat
import sys
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "aegis-firewall-sentinel.py"
spec = importlib.util.spec_from_file_location("aegis_review4_test", SCRIPT)
assert spec and spec.loader
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)

class FakePath:
    def __init__(self, value: str): self.value = value
    def read_text(self, **_): return self.value

class SessionGate(unittest.TestCase):
    def check_gate(self, *, audits, wayland_remote="no", wayland_active="yes", wayland_class="user", wayland_type="wayland"):
        rows = "2 1000 alice seat0 2000 user tty2 no -\n3 1000 alice - 3000 manager - no -\n"
        session2 = (
            f"User=1000\nAudit=2\nRemote={wayland_remote}\nActive={wayland_active}\n"
            f"Class={wayland_class}\nType={wayland_type}\n"
        )
        session3 = "User=1000\nAudit=3\nRemote=no\nActive=yes\nClass=manager\nType=unspecified\n"
        def fake_run(cmd, **_):
            if cmd[1] == "list-sessions": return m.CommandResult(0, rows)
            if cmd[1] == "show-session": return m.CommandResult(0, session2 if cmd[2] == "2" else session3)
            raise AssertionError(f"unexpected command {cmd}")
        with (patch.object(m, "LOGINUID_PATH", FakePath("1000")),
              patch.object(m, "SESSIONID_PATH", FakePath("3")),
              patch.dict(os.environ, {"SUDO_UID":"1000", "SUDO_TTY":"/dev/pts/0"}),
              patch.object(m.os, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_uid=1000)),
              patch.object(m, "_sudo_invoker_audit_sessions", return_value=audits),
              patch.object(m, "run", side_effect=fake_run)):
            m.require_local_recovery_session()

    def test_true_local_audit_must_pass(self):
        self.check_gate(audits=["2"])

    def test_true_local_tty_must_pass(self):
        self.check_gate(audits=["2"], wayland_type="tty")

    def test_manager_ancestor_not_mistaken_for_physical_login(self):
        with self.assertRaises(m.Stop) as err:
            self.check_gate(audits=["3"])
        self.assertIn("virtual console", str(err.exception))

    def test_remote_tty_denied(self):
        with self.assertRaises(m.Stop):
            self.check_gate(audits=["2"], wayland_remote="yes", wayland_type="tty")

    def test_inactive_session_denied(self):
        with self.assertRaises(m.Stop):
            self.check_gate(audits=["2"], wayland_active="no")

    def test_manager_class_denied_even_exact_audit(self):
        with self.assertRaises(m.Stop):
            self.check_gate(audits=["2"], wayland_class="manager")

class RuntimeZoneTarget(unittest.TestCase):
    def inspect(self, target="default", query_code=0):
        calls=[]
        def fake_run(cmd, **_):
            calls.append(cmd)
            assert cmd[0] == "/usr/bin/firewall-cmd" and cmd[1] == "--zone=aegis-public", cmd
            assert "--get-target" not in cmd and "--permanent" not in cmd, cmd
            option = cmd[-1]
            if option == "--list-all":
                return m.CommandResult(query_code, f"aegis-public\n  target: {target}\n  interfaces: \n  services: dhcpv6-client\n")
            if option == "--list-services": return m.CommandResult(0, "dhcpv6-client\n")
            if option.startswith("--query-"): return m.CommandResult(1, "no\n")
            return m.CommandResult(0, "\n")
        with patch.object(m, "run", side_effect=fake_run):
            findings = m._zone_readonly_findings("aegis-public", {"dhcpv6-client"})
        self.assertIn("--list-all", [cmd[-1] for cmd in calls])
        return findings

    def test_valid_live_target_no_false_alarm(self):
        self.assertEqual(self.inspect(), [])

    def test_changed_live_target_detected(self):
        self.assertIn("aegis-public runtime target drift", self.inspect(target="ACCEPT"))

    def test_live_zone_query_failure_not_accepted(self):
        self.assertIn("aegis-public runtime target drift", self.inspect(query_code=2))

if __name__ == "__main__":
    unittest.main(verbosity=2)
