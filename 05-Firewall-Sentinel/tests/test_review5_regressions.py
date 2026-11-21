#!/usr/bin/python3 -I
"""Offline regression coverage of trusted_ifaces nft syntax and fail-closed semantics.
No privileges, nft invocation, files outside Python bytecode cache, or live state changes.
"""
from __future__ import annotations
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "aegis-firewall-sentinel.py"
spec = importlib.util.spec_from_file_location("aegis_review5_test", SCRIPT)
assert spec and spec.loader
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


class TrustedInterfacesNftPayload(unittest.TestCase):
    def capture(self, desired=None, force_clear=False, table_exists=True):
        payloads=[]
        def record(data, *, load):
            payloads.append((data, load))
        with (
            patch.object(m, "nft_table_json", return_value={"nftables": []} if table_exists else None),
            patch.object(m, "read_policy", return_value={"name": "fixture"}) as rp,
            patch.object(m, "_active_trusted_interfaces", return_value=set(desired or [])) as active,
            patch.object(m, "_nft_stdin_transaction", side_effect=record),
        ):
            m.sync_trusted_interfaces(force_clear=force_clear)
        return payloads, rp.call_count, active.call_count

    def test_nonempty_trusted_interfaces_use_real_lf(self):
        payloads, rp, active = self.capture(["wlan0"])
        self.assertEqual(payloads, [(b'flush set inet aegis_sentinel trusted_ifaces\n'
                                     b'add element inet aegis_sentinel trusted_ifaces { "wlan0" }\n', True)])
        self.assertNotIn(b'\\n', payloads[0][0])
        self.assertEqual((rp, active), (1, 1))

    def test_two_interfaces_sorted_in_single_atomic_transaction(self):
        payloads, _, _ = self.capture(["wlan0", "enp1s0"])
        self.assertEqual(len(payloads),1)
        self.assertEqual(payloads[0][0],
            b'flush set inet aegis_sentinel trusted_ifaces\n'
            b'add element inet aegis_sentinel trusted_ifaces { "enp1s0", "wlan0" }\n')

    def test_empty_trust_is_only_flush(self):
        payloads, _, _ = self.capture([])
        self.assertEqual(payloads, [(b'flush set inet aegis_sentinel trusted_ifaces\n', True)])

    def test_force_clear_never_reads_connection_policy(self):
        payloads, rp, active = self.capture(["wlan0"], force_clear=True)
        self.assertEqual(payloads, [(b'flush set inet aegis_sentinel trusted_ifaces\n', True)])
        self.assertEqual((rp, active), (0, 0))

    def test_missing_table_does_not_attempt_mutation(self):
        payloads, rp, active = self.capture(["wlan0"], table_exists=False)
        self.assertEqual(payloads, [])
        self.assertEqual((rp, active), (0, 0))


class NftTransactionSafety(unittest.TestCase):
    def test_precheck_before_load_with_identical_payload(self):
        seen=[]
        data=b'flush set inet aegis_sentinel trusted_ifaces\n'
        def fake_run(cmd, **kwargs):
            seen.append((cmd, kwargs.get("stdin")))
            return m.CommandResult(0, "")
        with patch.object(m,"run",side_effect=fake_run):
            m._nft_stdin_transaction(data, load=True)
        self.assertEqual(len(seen),2)
        self.assertEqual(seen[0][0],["/usr/sbin/nft","--check","--file","-"])
        self.assertEqual(seen[1][0],["/usr/sbin/nft","--file","-"])
        self.assertEqual([x[1] for x in seen],[data,data])

    def test_failed_precheck_does_not_load(self):
        seen=[]
        def fake_run(cmd, **kwargs):
            seen.append(cmd)
            raise m.Stop("nft parse failure")
        with patch.object(m,"run",side_effect=fake_run):
            with self.assertRaisesRegex(m.Stop, "parse failure"):
                m._nft_stdin_transaction(b'flush set inet aegis_sentinel trusted_ifaces\n',load=True)
        self.assertEqual(seen,[["/usr/sbin/nft","--check","--file","-"]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
