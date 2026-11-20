#!/usr/bin/env python3
"""Offline Bash regression tests. Python is a TEST dependency, not runtime.
No installed chronyd, host service, host clock or host configuration is changed.
The getfattr adapter uses real os.listxattr/getxattr for fixtures; it is not a
Fedora integration test. Chronyd/systemd calls are deliberately mocked.
"""
from __future__ import annotations
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'aegis-time-nts.sh'
HOSTS = ['time.cloudflare.com', 'nts.netnod.se', 'ptbtime1.ptb.de']
IPS = ['192.0.2.1', '192.0.2.2', '192.0.2.3']  # Documentation networks, not probes.
ORIGINAL = '''# local comment about server and ntsdumpdir must survive
pool 2.fedora.pool.ntp.org iburst
sourcedir /run/chrony-dhcp
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
ntsdumpdir /var/lib/chrony
logdir /var/log/chrony
'''

class BashTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fh-nts-test.')
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        for name in ('etc', 'run', 'state', 'bin'):
            (self.root/name).mkdir(mode=0o700)
        self.conf = self.root/'etc/chrony.conf'
        self.conf.write_text(ORIGINAL)
        self.conf.chmod(0o600)
        for name in ('unit', 'sysconfig', 'machine'):
            f=self.root/'etc'/name; f.write_text('OPTIONS="-F 2"\n' if name=='sysconfig' else name+' fixture\n'); f.chmod(0o600)
        adapter=self.root/'bin/getfattr'
        adapter.write_text('''#!/usr/bin/python3
import os,sys
p=sys.argv[-1]
try:
 print("# file: "+p)
 for n in sorted(os.listxattr(p)):
  print(n+"=0x"+os.getxattr(p,n).hex())
except OSError as e:
 print(e,file=sys.stderr);sys.exit(1)
''')
        adapter.chmod(0o700)
        self.preamble=f'''
source {shlex.quote(str(SCRIPT))}
ANCHOR={shlex.quote(str(self.root))}
OWNER_UID={os.getuid()}
CONF=$ANCHOR/etc/chrony.conf
STATE=$ANCHOR/state/time-nts
TX=$STATE/transaction
RUNROOT=$ANCHOR/run
SYSTEM_UNIT=$ANCHOR/etc/unit
SYSCONFIG=$ANCHOR/etc/sysconfig
MACHINE=$ANCHOR/etc/machine
export PATH=$ANCHOR/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
CHRONYD=fixture_chronyd
fixture_chronyd() {{ [[ $1 == -p && $2 == -f ]]; cat -- "$3"; }}
bounded() {{ "$@" 9>&-; }}
# Legacy tests model a service with no drop-ins. The separate rc3 suite runs
# the real service guard and supplies complete systemctl property fixtures.
systemctl() {{
    [[ $# == 4 && $1 == show && $2 == --value && $4 == chronyd.service ]] || return 88
    case $3 in
        --property=DropInPaths) ;;
        --property=NeedDaemonReload) printf 'no\\n';;
        *) return 89;;
    esac
}}
service_check() {{ :; }}
restart_chrony() {{ printf 'restart\\n' >> "$ANCHOR/restarts"; }}
verify_live() {{ return 0; }}
'''
        self.make_evidence()

    def tearDown(self):
        self.temp.cleanup()

    def sh(self, body, expected=0, timeout=20):
        p=subprocess.run(['/usr/bin/bash','-p','-c',self.preamble+body],text=True,capture_output=True,timeout=timeout)
        if expected is not None:
            self.assertEqual(p.returncode,expected, p.stdout+'\n'+p.stderr)
        return p

    def public(self, *args, privileged=True, env=None):
        return subprocess.run(['/usr/bin/bash',*(['-p'] if privileged else []),'--',str(SCRIPT),*args],capture_output=True,text=True,env=env,timeout=10)

    def make_evidence(self):
        prefix=self.root/'run/obs'; self.prefix=prefix
        def write(ext,text): Path(str(prefix)+ext).write_text(text)
        sources=''.join(f'^,{state},{ip},1,6,377,2,0.00001,0.00002,0.001\n' for state,ip in zip(['*','+','-'],IPS))
        write('.sources1',sources);write('.sources2',sources)
        write('.auth',''.join(f'{ip},NTS,1,15,256,100,0,0,8,100\n' for ip in IPS))
        write('.names',''.join(f'{h},NTS,1,15,256,100,0,0,8,100\n' for h in HOSTS))
        write('.ntp',''.join(f'Remote address  : {ip} (C0000201)\nRemote port : {123 if i!=1 else 4123}\nAuthenticated : Yes\nTotal good RX : 8\n' for i,ip in enumerate(IPS)))
        write('.tracking','Reference ID : C0000201 (192.0.2.1)\nStratum : 2\nSystem time : 0.000001 seconds slow of NTP time\nLeap status : Normal\n')

    def alter(self, ext, old, new):
        p=Path(str(self.prefix)+ext);p.write_text(p.read_text().replace(old,new))

    def evidence(self, expected=0):
        return self.sh('evaluate_evidence "$ANCHOR/run/obs" 192.0.2.1',expected)

    def setup_tx(self):
        return self.sh('acquire_lock; make_plan; prepare_tx; set_status APPLYING; install_snapshot "$TX/after.conf" "$BEFORE_FP"; set_status APPLIED')

    def test_01_public_help(self):
        p=self.public('--help'); self.assertEqual(p.returncode,0,p.stderr)

    def test_02_plain_bash_is_rejected(self):
        p=self.public('--help',privileged=False);self.assertEqual(p.returncode,2)

    def test_03_bash_env_not_executed(self):
        envfile=self.root/'env.sh'; marker=self.root/'poisoned'
        envfile.write_text(f'touch {shlex.quote(str(marker))}\n')
        env=dict(os.environ,BASH_ENV=str(envfile),PYTHONHOME='/bogus')
        p=self.public('--help',env=env);self.assertEqual(p.returncode,0,p.stderr);self.assertFalse(marker.exists())

    def test_04_internal_marker_cannot_bypass_clean_environment(self):
        p=self.public('--internal-clean','--help',env=dict(os.environ,UNTRUSTED_TEST='1'));self.assertEqual(p.returncode,2)

    def test_05_invalid_wait(self):
        for value in ('-1','301','01','1;touch /x','nan','1.5'):
            with self.subTest(value=value):self.assertEqual(self.public('verify','--wait',value).returncode,2)

    def test_06_invalid_approval(self):
        self.assertEqual(self.public('apply','--approve','$(id)').returncode,2)

    def test_07_hash_has_exactly_64_hex_characters(self):
        p=self.sh('printf abc | hash_stream');self.assertEqual(p.stdout.strip(),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_08_renderer_preserves_non_source_settings(self):
        out=self.sh('render_config "$CONF"').stdout
        for line in ('makestep 1.0 3','rtcsync','driftfile /var/lib/chrony/drift','# local comment about server and ntsdumpdir must survive'):
            self.assertIn(line,out)
        self.assertEqual(out.count('server time.cloudflare.com iburst nts'),1)
        self.assertIn('# fh-time-nts disabled: sourcedir /run/chrony-dhcp',out)

    def test_09_renderer_is_idempotent(self):
        self.sh('render_config "$CONF" > "$ANCHOR/etc/a"; render_config "$ANCHOR/etc/a" > "$ANCHOR/etc/b"; cmp "$ANCHOR/etc/a" "$ANCHOR/etc/b"')

    def test_10_renderer_rejects_unsafe_or_complex_directives(self):
        for line in ('include /etc/custom.conf','confdir /etc/chrony.d','nocerttimecheck 1','refclock PHC /dev/ptp0','local stratum 10','manual','initstepslew 1 pool.example','allow all','ntsservercert /x','mailonchange root 1','ntstrustedcerts /tmp/ca','nosystemcert','server example.test iburst trust','minsources 3','ntsdumpdir /custom','sourcedir /custom'):
            with self.subTest(line=line):
                self.conf.write_text(ORIGINAL+line+'\n');self.sh('render_config "$CONF"',2)

    def test_11_managed_block_tampering_rejected(self):
        out=self.sh('render_config "$CONF"').stdout
        self.conf.write_text(out.replace('minsources 2','minsources 1'))
        self.sh('render_config "$CONF"',2)

    def test_12_unclosed_or_duplicate_block_rejected(self):
        out=self.sh('render_config "$CONF"').stdout
        for text in (out.replace('# END FH TIME-NTS v1',''),out+out):
            self.conf.write_text(text);self.sh('render_config "$CONF"',2)

    def test_13_symlink_target_rejected_without_writing(self):
        sentinel=self.root/'etc/sentinel';sentinel.write_text('KEEP')
        self.conf.unlink();self.conf.symlink_to(sentinel)
        self.sh('check_file "$CONF"',2);self.assertEqual(sentinel.read_text(),'KEEP')

    def test_14_symlink_parent_rejected(self):
        (self.root/'alias').symlink_to(self.root/'etc',target_is_directory=True)
        self.sh('check_file "$ANCHOR/alias/chrony.conf"',2)

    def test_15_hardlink_rejected(self):
        os.link(self.conf,self.root/'etc/other');self.sh('check_file "$CONF"',2)

    def test_16_fifo_rejected_without_hanging(self):
        self.conf.unlink();os.mkfifo(self.conf,0o600);self.sh('check_file "$CONF"',2,timeout=3)

    def test_17_group_writable_file_and_parent_rejected(self):
        self.conf.chmod(0o660);self.sh('check_file "$CONF"',2)
        self.conf.chmod(0o600);self.conf.parent.chmod(0o770);self.sh('check_file "$CONF"',2)

    def test_18_real_copy_preserves_xattrs(self):
        os.setxattr(self.conf,'user.fh-test',b'abc\nxyz\x00')
        self.sh('copy_exact "$CONF" "$ANCHOR/etc/copied"')
        self.assertEqual(os.getxattr(self.root/'etc/copied','user.fh-test'),b'abc\nxyz\x00')

    def test_19_fingerprint_detects_content_and_metadata_changes(self):
        orig=self.sh('fingerprint "$CONF"').stdout
        self.conf.chmod(0o640)
        self.assertNotEqual(orig,self.sh('fingerprint "$CONF"').stdout)
        self.conf.chmod(0o600);os.setxattr(self.conf,'user.other',b'1')
        self.assertNotEqual(orig,self.sh('fingerprint "$CONF"').stdout)

    def test_20_bad_getfattr_stops_copy(self):
        self.sh('getfattr() { return 1; }; copy_exact "$CONF" "$ANCHOR/etc/copied"; echo UNSAFE',2)

    def test_21_private_lock_not_truncated(self):
        self.sh('acquire_lock; printf SENTINEL > "$STATE/lock"')
        lock=self.root/'state/time-nts/lock';ino=lock.stat().st_ino
        self.sh('acquire_lock');self.assertEqual(lock.read_text(),'SENTINEL');self.assertEqual(lock.stat().st_ino,ino)

    def test_22_second_writer_is_rejected(self):
        child=subprocess.Popen(['/usr/bin/bash','-p','-c',self.preamble+'acquire_lock; echo READY; sleep 30'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        try:
            self.assertEqual(child.stdout.readline().strip(),'READY')
            self.sh('acquire_lock',75)
        finally:
            os.killpg(child.pid,signal.SIGKILL);child.communicate()
        self.sh('acquire_lock')

    def test_23_lock_symlink_is_rejected(self):
        self.sh('make_private_dir "$STATE"')
        (self.root/'state/time-nts/lock').symlink_to(self.conf)
        self.sh('acquire_lock',2);self.assertEqual(self.conf.read_text(),ORIGINAL)

    def test_24_plan_does_not_change_source_or_create_journal(self):
        self.sh('make_plan; show_plan');self.assertEqual(self.conf.read_text(),ORIGINAL)
        self.assertFalse((self.root/'state/time-nts').exists())

    def test_25_candidate_syntax_failure_leaves_source_unchanged(self):
        self.sh('fixture_chronyd() { return 1; }; make_plan',1)
        self.assertEqual(self.conf.read_text(),ORIGINAL)

    def test_26_journal_is_complete_before_replace(self):
        self.sh('acquire_lock; make_plan; prepare_tx; load_tx; [[ $(read_status) == PREPARED ]]')
        self.assertEqual(self.conf.read_text(),ORIGINAL)
        self.assertTrue((self.root/'state/time-nts/transaction/before.conf').exists())

    def test_27_install_and_rollback_preserve_original(self):
        self.setup_tx();self.assertIn('authselectmode require',self.conf.read_text())
        self.sh('rollback_impl');self.assertEqual(self.conf.read_text(),ORIGINAL)
        self.assertEqual((self.root/'state/time-nts/transaction/status').read_text(),'ROLLED_BACK\n')

    def test_28_rollback_preserves_later_manual_edits(self):
        self.setup_tx();self.conf.write_text(self.conf.read_text()+'# later edit\n')
        self.sh('rollback_impl',2);self.assertIn('# later edit',self.conf.read_text())

    def test_29_journal_not_sourced(self):
        self.setup_tx();status=self.root/'state/time-nts/transaction/status'
        status.write_text('$(touch '+str(self.root/'owned')+')\n')
        self.sh('load_tx',2);self.assertFalse((self.root/'owned').exists())

    def test_30_corrupt_backup_rejected(self):
        self.setup_tx();f=self.root/'state/time-nts/transaction/before.conf';f.write_text('bad')
        self.sh('rollback_impl',2)

    def test_31_host_unit_change_blocks_recovery(self):
        self.setup_tx();(self.root/'etc/unit').write_text('changed')
        self.sh('load_tx',2)

    def test_32_noop_apply_performs_no_persistent_write_or_restart(self):
        self.setup_tx()
        p=self.sh('''make_plan
persist() { echo UNEXPECTED_PERSIST >&2; exit 99; }
restart_chrony() { exit 98; }
apply_plan
''')
        self.assertIn('NO-OP',p.stdout)

    def test_33_noop_rollback_performs_no_write(self):
        self.setup_tx();self.sh('rollback_impl')
        self.sh('persist() { exit 99; }; restart_chrony() { exit 98; }; rollback_action')

    def test_34_pending_transaction_blocks_new_apply(self):
        self.setup_tx();self.sh('set_status APPLYING')
        self.sh('make_plan; apply_plan',2)

    def test_35_reapply_after_rollback_reuses_same_slot(self):
        self.setup_tx();self.sh('rollback_impl')
        before=self.root/'state/time-nts/transaction/before.conf';ino=before.stat().st_ino
        self.sh('make_plan; APPROVE=$PLAN_ID; apply_plan')
        self.assertEqual(before.stat().st_ino,ino)

    def test_36_wrong_approval_does_not_replace(self):
        self.sh('make_plan; APPROVE='+('0'*64)+'; apply_plan',2)
        self.assertEqual(self.conf.read_text(),ORIGINAL)

    def test_37_healthy_evidence_passes(self):
        self.assertIn('VERIFIED SNAPSHOT',self.evidence().stdout)

    def test_38_mode_nts_without_keys_or_packets_fails(self):
        self.alter('.auth',',15,256,',',0,0,');self.evidence(1)
        self.make_evidence();self.alter('.ntp','Authenticated : Yes','Authenticated : No');self.evidence(1)

    def test_39_tracking_normal_alone_is_not_sufficient(self):
        Path(str(self.prefix)+'.auth').write_text('');self.evidence(1)

    def test_40_one_source_fails_two_source_policy(self):
        self.alter('.sources2','^,+,','^,?,');self.alter('.sources2','^,-,','^,?,');self.evidence(1)

    def test_41_third_unavailable_source_allows_two_healthy(self):
        self.alter('.sources2','^,-,','^,?,')
        self.alter('.auth',IPS[2]+',NTS,1,15,256',IPS[2]+',NTS,0,0,0')
        self.evidence(0)

    def test_42_stale_measurement_fails(self):
        self.alter('.sources2',',377,2,',',377,999999,');self.evidence(1)

    def test_43_plaintext_selected_source_fails(self):
        self.alter('.auth',IPS[0]+',NTS,',IPS[0]+',-,');self.evidence(1)

    def test_44_duplicate_auth_or_source_fails(self):
        for ext in ('.auth','.sources2','.names'):
            with self.subTest(ext=ext):
                self.make_evidence();f=Path(str(self.prefix)+ext);f.write_text(f.read_text()+f.read_text().splitlines()[0]+'\n');self.evidence(1)

    def test_45_wrong_runtime_hostname_fails(self):
        self.alter('.names','time.cloudflare.com','evil.example');self.evidence(1)

    def test_46_large_correction_or_nan_fails(self):
        for v in ('2.0','nan','-0.2','Inf'):
            with self.subTest(v=v):
                self.make_evidence();self.alter('.tracking','0.000001',v);self.evidence(1)

    def test_47_local_reference_and_mismatched_reference_fail(self):
        for ref in ('7F7F0101','C0000202 (192.0.2.2)'):
            with self.subTest(ref=ref):
                self.make_evidence();self.alter('.tracking','C0000201 (192.0.2.1)',ref);self.evidence(1)

    def test_48_cached_cookie_does_not_require_new_key_exchange(self):
        self.alter('.auth',',NTS,1,',',NTS,0,');self.evidence(0)

    def test_49_legitimate_leap_announcement_accepted(self):
        self.alter('.tracking','Normal','Insert second');self.evidence(0)

    def test_50_malformed_schema_fails_closed(self):
        self.alter('.auth',',100\n',',100,EXTRA\n');self.evidence(1)

    def test_51_sigterm_after_rename_triggers_rollback(self):
        p=self.sh('''trap cleanup EXIT
trap 'exit 143' TERM
acquire_lock; make_plan; prepare_tx; OPEN_TX=1; set_status APPLYING
install_snapshot "$TX/after.conf" "$BEFORE_FP"
kill -TERM $$
echo UNSAFE
''',143)
        self.assertNotIn('UNSAFE',p.stdout);self.assertEqual(self.conf.read_text(),ORIGINAL)

    def test_52_sigkill_after_rename_can_be_recovered_next_run(self):
        p=self.sh('''acquire_lock; make_plan; prepare_tx; set_status APPLYING
install_snapshot "$TX/after.conf" "$BEFORE_FP"
kill -KILL $$
''',-signal.SIGKILL)
        self.assertIn('authselectmode require',self.conf.read_text())
        self.sh('acquire_lock; rollback_impl');self.assertEqual(self.conf.read_text(),ORIGINAL)

    def test_53_restart_failure_restores_configuration(self):
        p=self.sh('''trap cleanup EXIT
acquire_lock; make_plan; APPROVE=$PLAN_ID
restart_chrony() { if [[ ! -f $ANCHOR/failed-once ]]; then touch "$ANCHOR/failed-once"; return 1; fi; return 0; }
apply_plan
''',2)
        self.assertEqual(self.conf.read_text(),ORIGINAL)
        self.assertIn('ROLLED BACK',p.stdout)

    def test_54_network_verification_failure_keeps_valid_nts_policy(self):
        self.sh('''trap cleanup EXIT
acquire_lock; make_plan; APPROVE=$PLAN_ID
verify_live() { return 3; }
apply_plan
''',3)
        self.assertIn('authselectmode require',self.conf.read_text())
        self.assertEqual((self.root/'state/time-nts/transaction/status').read_text(),'APPLIED\n')

    def test_55_orphan_preparation_blocks_retry(self):
        self.sh('make_private_dir "$STATE"; mkdir -m 700 "$STATE/.prepare.orphan"')
        self.sh('acquire_lock',2)

    def test_56_no_clock_or_cookie_mutating_commands_in_runtime(self):
        s=SCRIPT.read_text()
        for bad in ('rm -rf /var/lib/chrony','chronyc makestep','timedatectl set-','hwclock --','curl ','wget ','eval '):
            self.assertNotIn(bad,s)

    def test_57_next_restart_options_are_checked_as_data(self):
        for v in ('OPTIONS="-F 2"', "OPTIONS='-F 2 -R'", 'OPTIONS=""', '# comment'):
            (self.root/'etc/sysconfig').write_text(v+'\n');self.sh('validate_sysconfig')
        for v in ('OPTIONS="-f /tmp/evil.conf"', 'OPTIONS="-x"', 'OPTIONS="$(touch /x)"', 'OPTIONS="-F 2"\nOPTIONS=""', 'OTHER=1'):
            (self.root/'etc/sysconfig').write_text(v+'\n');self.sh('validate_sysconfig',2)

    def test_58_monitoring_port_is_preserved(self):
        self.conf.write_text(ORIGINAL+'cmdport 323\n')
        p=self.sh('render_config "$CONF"');self.assertIn('\ncmdport 323\n',p.stdout)
        self.assertNotIn('cmdport 0',p.stdout)

    def test_59_write_error_does_not_install_candidate(self):
        self.sh('acquire_lock; make_plan; prepare_tx; persist() { return 1; }; set_status APPLYING; install_snapshot "$TX/after.conf" "$BEFORE_FP"',1)
        self.assertEqual(self.conf.read_text(),ORIGINAL)

    def test_60_queued_restart_is_not_reported_as_complete(self):
        # Keep the real restart_chrony, but replace only systemd/time adapters.
        code="""
source SCRIPT_PATH
ANCHOR=ROOT_PATH
calls=$ANCHOR/calls
printf '0\n' > "$calls"
unit_value() {
 case $1 in
  InvocationID) n=$(cat "$calls"); if (( n < 2 )); then printf old; else printf new; fi;;
  ActiveState) printf active;;
  SubState) printf running;;
  MainPID) printf 1234;;
  Job) n=$(cat "$calls"); n=$((n+1)); printf '%s\n' "$n" > "$calls"; if (( n < 2 )); then printf 42; else printf 0; fi;;
 esac
}
bounded() { :; }
sleep() { :; }
restart_chrony
[[ $(cat "$calls") == 2 ]]
""".replace('SCRIPT_PATH',shlex.quote(str(SCRIPT))).replace('ROOT_PATH',shlex.quote(str(self.root)))
        self.sh(code)

    def test_60b_fedora_empty_job_means_no_pending_job(self):
        # Fedora 44 / systemd 259 reports no queued unit job as an empty Job=.
        code="""
source SCRIPT_PATH
calls=0
unit_value() {
 case $1 in
  InvocationID) if (( calls == 0 )); then printf old; else printf new; fi;;
  ActiveState) printf active;;
  SubState) printf running;;
  MainPID) printf 4321;;
  Job) printf '';;
 esac
}
bounded() { calls=1; return 0; }
sleep() { :; }
restart_chrony
""".replace('SCRIPT_PATH',shlex.quote(str(SCRIPT)))
        self.sh(code)

    def test_61_sha256_failure_is_not_accepted(self):
        self.sh('sha256sum() { return 1; }; printf abc | hash_stream',2)

    def test_62_noop_1000_passes_no_io_in_transaction_function(self):
        # Isolate the no-op transaction branch, not the entire live CLI/preflight.
        self.sh("""
BEFORE_FP=abc AFTER_FP=abc
show_plan() { :; }
say() { :; }
persist() { exit 99; }
prepare_tx() { exit 98; }
restart_chrony() { exit 97; }
for (( n=0;n<1000;n++ )); do apply_plan; done
""")

    def test_63_sigint_and_sighup_exit_codes(self):
        for sig,rc in (('INT',130),('HUP',129)):
            with self.subTest(signal=sig):
                p=self.sh(f"trap cleanup EXIT; trap 'exit {rc}' {sig}; kill -{sig} $$; echo UNSAFE",rc)
                self.assertNotIn('UNSAFE',p.stdout)

    def test_64_rollback_failure_is_not_hidden(self):
        self.setup_tx()
        self.sh('restart_chrony() { return 1; }; rollback_impl',1)
        self.assertEqual(self.conf.read_text(),ORIGINAL)
        self.assertEqual((self.root/'state/time-nts/transaction/status').read_text(),'ROLLING_BACK\n')

    def test_65_ipv6_reference_supported(self):
        for ext in ('.sources2','.auth','.ntp','.tracking'):
            self.alter(ext,'192.0.2.1','2001:db8::1')
        self.sh('evaluate_evidence "$ANCHOR/run/obs" 2001:db8::1')

    def test_66_control_character_in_config_rejected(self):
        for control in ('\x00','\r','\x1b'):
            with self.subTest(control=repr(control)):
                self.conf.write_text(ORIGINAL+'# bad'+control+'comment\n')
                self.sh('render_config "$CONF"',2)

    def test_67_nondefault_inode_flags_refused(self):
        self.sh('lsattr() { printf "%s %s\\n" "----i-----------------" "$CONF"; }; check_flags "$CONF"',2)
        self.sh('lsattr() { printf "%s %s\\n" "----c-----------------" "$CONF"; }; check_flags "$CONF"',2)
        self.sh('lsattr() { printf "%s %s\\n" "--------------e-------" "$CONF"; }; check_flags "$CONF"')

    def test_68_approval_becomes_invalid_when_input_changes(self):
        self.sh('make_plan; old=$PLAN_ID; printf "# edit\\n" >> "$CONF"; make_plan; [[ $old != "$PLAN_ID" ]]')

if __name__=='__main__':
    unittest.main(verbosity=2)
