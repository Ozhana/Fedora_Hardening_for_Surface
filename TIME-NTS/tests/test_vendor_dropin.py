"""Focused rc3 tests for the Fedora vendor timeout drop-in trust boundary.

These tests execute the real service_check, input_stamp, planning, approval and
journal functions. Only external systemctl responses, chronyd parsing/restart
and live network observations are adapted. Every writable path is a private
temporary fixture. No host service, clock, configuration or RPM database is
changed. Python is a test dependency only.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import unittest

import test_time_nts as fixtures


VENDOR_CONTENT = """# This file is part of the systemd package.
# See https://fedoraproject.org/wiki/Changes/Shorter_Shutdown_Timer.
# A comment does not authorize additional service settings.

[Service]
TimeoutStopFailureMode=abort
"""


class VendorDropinTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.BashTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root = self.fixture.root
        self.vendor = self.root / 'etc/10-timeout-abort.conf'
        self.vendor.write_text(VENDOR_CONTENT)
        self.vendor.chmod(0o600)
        self.paths = self.root / 'etc/dropin-paths'
        self.paths.write_text(str(self.vendor) + '\n')
        self.reload = self.root / 'etc/reload-pending'
        self.reload.write_text('no\n')
        # Keep the real service_check and unit_value. Unlike the shared baseline
        # fixture, this suite must exercise the guard that rejected Fedora.
        stub = 'service_check() { :; }\n'
        self.assertEqual(self.fixture.preamble.count(stub), 1)
        self.fixture.preamble = self.fixture.preamble.replace(stub, '') + r'''
VENDOR_TIMEOUT_DROPIN=$ANCHOR/etc/10-timeout-abort.conf
fixture_systemctl() {
    [[ $# == 4 && $1 == show && $2 == --value && $3 == --property=* ]] || return 88
    local property=${3#--property=} unit=$4
    if [[ $unit == chronyd.service ]]; then
        case $property in
            DropInPaths) cat -- "$ANCHOR/etc/dropin-paths";;
            NeedDaemonReload) cat -- "$ANCHOR/etc/reload-pending";;
            LoadState) printf 'loaded\n';;
            FragmentPath) printf '%s\n' "$SYSTEM_UNIT";;
            UnitFileState) printf 'enabled\n';;
            ActiveState) printf 'active\n';;
            *) return 89;;
        esac
    else
        case $property in
            ActiveState) printf 'inactive\n';;
            UnitFileState) printf 'disabled\n';;
            *) return 90;;
        esac
    fi
}
systemctl() { fixture_systemctl "$@"; }
'''
        self.sh = self.fixture.sh

    def set_paths(self, value):
        self.paths.write_text(value + '\n')

    def assert_no_apply(self):
        self.assertEqual(self.fixture.conf.read_text(), fixtures.ORIGINAL)
        self.assertFalse((self.root / 'state/time-nts/transaction').exists())
        self.assertFalse((self.root / 'restarts').exists())

    def test_01_original_vendor_file_passes_real_service_check(self):
        self.sh('service_check no')

    def test_02_no_dropins_passes_real_service_check(self):
        self.set_paths('')
        self.sh('service_check no')

    def test_03_no_dropins_preserves_exact_legacy_input_stamp(self):
        self.set_paths('')
        self.sh(r'''
legacy=$({ fingerprint "$SYSTEM_UNIT"; fingerprint "$SYSCONFIG"; sha256sum < "$MACHINE"; } | hash_stream)
current=$(input_stamp)
[[ $legacy == "$current" ]]
''')

    def test_04_vendor_presence_is_bound_to_input_stamp(self):
        with_vendor = self.sh('input_stamp').stdout
        self.set_paths('')
        without_vendor = self.sh('input_stamp').stdout
        self.assertNotEqual(with_vendor, without_vendor)

    def test_05_comments_blank_lines_and_horizontal_spacing_are_accepted(self):
        self.vendor.write_text(
            '\t# Fedora package comment\n; another comment\n\n'
            ' \t[Service]\t \n\tTimeoutStopFailureMode \t=\t abort \t\n')
        self.sh('service_check no')

    def test_06_other_path_even_with_identical_content_is_rejected(self):
        other = self.root / 'etc/custom.conf'
        other.write_text(VENDOR_CONTENT)
        other.chmod(0o600)
        self.set_paths(str(other))
        self.sh('service_check no', 2)

    def test_07_additional_or_duplicate_dropin_is_rejected(self):
        for suffix in (' /etc/systemd/system/chronyd.service.d/custom.conf',
                       ' /run/systemd/system/chronyd.service.d/custom.conf',
                       ' ' + str(self.vendor)):
            with self.subTest(suffix=suffix):
                self.set_paths(str(self.vendor) + suffix)
                self.sh('service_check no', 2)

    def test_08_multiline_path_list_is_rejected(self):
        self.set_paths(str(self.vendor) + '\n/etc/systemd/system/custom.conf')
        self.sh('service_check no', 2)

    def test_09_changed_or_extra_active_directives_are_rejected(self):
        cases = (
            '[Service]\nTimeoutStopFailureMode=kill\n',
            '[Service]\nTimeoutStopFailureMode=abort\nExecStart=/usr/bin/false\n',
            '[Service]\nTimeoutStopFailureMode=abort\nEnvironment=OPTIONS=-x\n',
            '[Service]\nTimeoutStopFailureMode=abort\n[Unit]\nDescription=other\n',
            '[Unit]\nTimeoutStopFailureMode=abort\n',
            '[Service]\nTimeoutStopFailureMode=abort\nTimeoutStopFailureMode=abort\n',
            '[Service]\nTimeoutStopFailureMode=abort\n[Service]\n',
            '[Service]\nTimeoutStopFailureMode="abort"\n',
            '[Service]\nTimeoutStopFailureMode=abort # inline comment\n',
            '[Service]\n',
            '# no operative policy\n',
        )
        for content in cases:
            with self.subTest(content=content):
                self.vendor.write_text(content)
                self.sh('service_check no', 2)

    def test_10_line_continuation_is_rejected(self):
        cases = (
            '[Service]\nTimeoutStopFailureMode=ab\\\nort\n',
            '[Service]\nTimeoutStopFailureMode=abort\\\n\n',
            '# comment with continuation\\\n[Service]\nTimeoutStopFailureMode=abort\n',
        )
        for content in cases:
            with self.subTest(content=content):
                self.vendor.write_text(content)
                self.sh('service_check no', 2)

    def test_11_symlink_file_is_rejected(self):
        original = self.root / 'etc/original-vendor.conf'
        self.vendor.rename(original)
        self.vendor.symlink_to(original)
        self.sh('service_check no', 2)
        self.assertEqual(original.read_text(), VENDOR_CONTENT)

    def test_12_hardlinked_file_is_rejected(self):
        os.link(self.vendor, self.root / 'etc/vendor-alias.conf')
        self.sh('service_check no', 2)

    def test_13_group_or_world_writable_file_is_rejected(self):
        for mode in (0o620, 0o602):
            with self.subTest(mode=oct(mode)):
                self.vendor.chmod(mode)
                self.sh('service_check no', 2)

    def test_14_writable_parent_is_rejected(self):
        self.vendor.parent.chmod(0o770)
        self.sh('service_check no', 2)

    def test_15_missing_file_is_rejected(self):
        self.vendor.unlink()
        self.sh('service_check no', 2)

    def test_16_fifo_is_rejected_without_hanging(self):
        self.vendor.unlink()
        os.mkfifo(self.vendor, 0o600)
        self.sh('service_check no', 2, timeout=3)

    @unittest.skipUnless(os.geteuid() == 0, 'Changing fixture file owner requires root')
    def test_17_foreign_file_owner_is_rejected(self):
        try:
            os.chown(self.vendor, 65534, -1)
        except OSError as exc:
            if exc.errno in (errno.EPERM, errno.EACCES, errno.EINVAL):
                self.skipTest('Fixture owner change unavailable in this user namespace')
            raise
        self.sh('service_check no', 2)

    def test_18_reload_pending_is_rejected_with_and_without_dropin(self):
        self.reload.write_text('yes\n')
        self.sh('service_check no', 2)
        self.set_paths('')
        self.sh('service_check no', 2)

    def test_19_property_read_failure_is_not_treated_as_empty(self):
        for property_name in ('DropInPaths', 'NeedDaemonReload'):
            with self.subTest(property_name=property_name):
                self.sh(r'''
systemctl() {
    [[ $3 != --property=''' + property_name + r''' ]] || return 7
    fixture_systemctl "$@"
}
service_dropin_stamp
''', 2)

    def test_20_allowed_comment_change_changes_input_stamp(self):
        before = self.sh('input_stamp').stdout
        self.vendor.write_text(VENDOR_CONTENT + '# updated package comment\n')
        after = self.sh('input_stamp').stdout
        self.assertNotEqual(before, after)

    def test_21_metadata_change_changes_input_stamp(self):
        before = self.sh('input_stamp').stdout
        self.vendor.chmod(0o640)
        after = self.sh('input_stamp').stdout
        self.assertNotEqual(before, after)

    def test_22_extended_attribute_change_changes_input_stamp(self):
        before = self.sh('input_stamp').stdout
        os.setxattr(self.vendor, 'user.rc3-review', b'changed')
        after = self.sh('input_stamp').stdout
        self.assertNotEqual(before, after)

    def test_23_changed_content_after_approval_prevents_apply(self):
        self.sh(r'''
trap cleanup EXIT
acquire_lock
make_plan
APPROVE=$PLAN_ID
printf '# modified after plan\n' >> "$VENDOR_TIMEOUT_DROPIN"
apply_plan
''', 2)
        self.assert_no_apply()

    def test_24_removed_dropin_after_approval_prevents_apply(self):
        self.sh(r'''
trap cleanup EXIT
acquire_lock
make_plan
APPROVE=$PLAN_ID
: > "$ANCHOR/etc/dropin-paths"
apply_plan
''', 2)
        self.assert_no_apply()

    def test_25_added_dropin_after_approval_prevents_apply(self):
        self.set_paths('')
        self.sh(r'''
trap cleanup EXIT
acquire_lock
make_plan
APPROVE=$PLAN_ID
printf '%s\n' "$VENDOR_TIMEOUT_DROPIN" > "$ANCHOR/etc/dropin-paths"
apply_plan
''', 2)
        self.assert_no_apply()

    def test_26_changed_vendor_file_blocks_rollback_before_writes(self):
        self.fixture.setup_tx()
        before = self.fixture.conf.read_bytes()
        status = self.root / 'state/time-nts/transaction/status'
        self.vendor.write_text(VENDOR_CONTENT + '# newer vendor file\n')
        self.sh('rollback_impl', 2)
        self.assertEqual(self.fixture.conf.read_bytes(), before)
        self.assertEqual(status.read_text(), 'APPLIED\n')
        self.assertFalse((self.root / 'restarts').exists())

    def test_27_old_no_dropin_journal_remains_readable(self):
        self.set_paths('')
        self.fixture.setup_tx()
        self.sh(r'''
{ fingerprint "$SYSTEM_UNIT"; fingerprint "$SYSCONFIG"; sha256sum < "$MACHINE"; } | hash_stream > "$TX/input.sha"
load_tx
''')

    def test_28_new_dropin_does_not_silently_rewrite_legacy_journal(self):
        self.set_paths('')
        self.fixture.setup_tx()
        old_stamp = (self.root / 'state/time-nts/transaction/input.sha').read_bytes()
        before = self.fixture.conf.read_bytes()
        self.set_paths(str(self.vendor))
        self.sh('rollback_impl', 2)
        self.assertEqual((self.root / 'state/time-nts/transaction/input.sha').read_bytes(), old_stamp)
        self.assertEqual(self.fixture.conf.read_bytes(), before)

    def test_29_no_dropin_plan_then_reload_pending_prevents_apply(self):
        self.set_paths('')
        self.sh(r'''
trap cleanup EXIT
acquire_lock
make_plan
APPROVE=$PLAN_ID
printf 'yes\n' > "$ANCHOR/etc/reload-pending"
apply_plan
''', 2)
        self.assert_no_apply()

    def test_30_correct_stdout_with_failed_property_query_prevents_apply(self):
        self.set_paths('')
        for property_name in ('DropInPaths', 'NeedDaemonReload'):
            with self.subTest(property_name=property_name):
                self.sh(r'''
trap cleanup EXIT
acquire_lock
make_plan
APPROVE=$PLAN_ID
systemctl() {
    fixture_systemctl "$@"
    [[ $3 != --property=''' + property_name + r''' ]] || return 7
}
apply_plan
''', 2)
                self.assert_no_apply()

    def test_31_query_failure_is_rejected_in_conditional_stamp_context(self):
        self.set_paths('')
        self.sh(r'''
systemctl() {
    fixture_systemctl "$@"
    [[ $3 != --property=DropInPaths ]] || return 7
}
if input_stamp; then
    printf 'UNSAFE\n'
fi
''', 2)

    def test_32_dropin_or_reload_change_during_inspection_is_rejected(self):
        for property_name in ('DropInPaths', 'NeedDaemonReload'):
            with self.subTest(property_name=property_name):
                (self.root / 'query-count').write_text('0\n')
                self.sh(r'''
systemctl() {
    if [[ $3 == --property=''' + property_name + r''' ]]; then
        count=$(<"$ANCHOR/query-count")
        count=$((count + 1))
        printf '%s\n' "$count" > "$ANCHOR/query-count"
        if (( count > 1 )); then
            printf 'CHANGED\n'
            return
        fi
    fi
    fixture_systemctl "$@"
}
service_dropin_stamp
''', 2)

    def test_33_symlink_parent_is_rejected(self):
        original = self.root / 'etc-original'
        self.vendor.parent.rename(original)
        (self.root / 'etc').symlink_to(original, target_is_directory=True)
        self.sh('service_dropin_stamp', 2)

    def test_34_control_bytes_are_rejected_even_in_comments(self):
        for suffix in ('# invalid\x00comment\n', '# invalid\rcomment\n'):
            with self.subTest(suffix=repr(suffix)):
                self.vendor.write_text(VENDOR_CONTENT + suffix)
                self.sh('service_dropin_stamp', 2)

    def test_35_foreign_owner_metadata_is_rejected(self):
        # Exercise the owner decision even where an unprivileged user namespace
        # cannot create a real foreign-owner fixture. Test 17 is the real chown
        # case; only this one metadata field is adapted in this portable case.
        self.sh(r'''
stat() {
    if [[ $# == 4 && $1 == -c && $2 == '%u %a %h %s' && $3 == -- && $4 == "$VENDOR_TIMEOUT_DROPIN" ]]; then
        command stat -c "$((OWNER_UID + 1)) %a %h %s" -- "$4"
    else
        command stat "$@"
    fi
}
service_dropin_stamp
''', 2)

    def test_36_dropin_change_during_journal_publication_blocks_install(self):
        self.sh(r'''
trap cleanup EXIT
acquire_lock
make_plan
APPROVE=$PLAN_ID
persist() {
    (( $# > 0 )) || die 'empty fixture persist'
    command sync -- "$@"
    if [[ $# == 1 && $1 == "$STATE" && -d $TX ]]; then
        printf '# changed while publishing journal\n' >> "$VENDOR_TIMEOUT_DROPIN"
    fi
}
install_snapshot() {
    printf 'UNEXPECTED_INSTALL\n' > "$ANCHOR/install-called"
    die 'snapshot installation must not be reached'
}
apply_plan
''', 2)
        self.assertEqual(self.fixture.conf.read_text(), fixtures.ORIGINAL)
        self.assertFalse((self.root / 'install-called').exists())
        self.assertFalse((self.root / 'restarts').exists())
        self.assertEqual((self.root / 'state/time-nts/transaction/status').read_text(), 'APPLYING\n')

    def test_37_dropin_change_after_install_blocks_restart_and_preserves_journal(self):
        self.sh(r'''
trap cleanup EXIT
acquire_lock
make_plan
APPROVE=$PLAN_ID
persist() {
    (( $# > 0 )) || die 'empty fixture persist'
    command sync -- "$@"
    if [[ $# == 1 && $1 == "${CONF%/*}" ]]; then
        printf '# changed after configuration rename\n' >> "$VENDOR_TIMEOUT_DROPIN"
    fi
}
apply_plan
''', 2)
        transaction = self.root / 'state/time-nts/transaction'
        self.assertEqual(self.fixture.conf.read_bytes(), (transaction / 'after.conf').read_bytes())
        self.assertNotEqual(self.fixture.conf.read_text(), fixtures.ORIGINAL)
        self.assertFalse((self.root / 'restarts').exists())
        self.assertEqual((transaction / 'status').read_text(), 'APPLYING\n')
        self.assertEqual((transaction / 'before.conf').read_text(), fixtures.ORIGINAL)


if __name__ == '__main__':
    unittest.main()
