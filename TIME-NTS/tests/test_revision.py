"""Focused rc2 review tests. Only temporary files/processes; no host services.

The optional C helper logs real GNU sync fsync calls from userspace and forwards
those calls to Linux. It is not kernel/NVMe tracing. GCC is a test-only dependency
for two methods, not a production dependency.
"""
from __future__ import annotations
import fcntl
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
import test_time_nts as fixtures

SCRIPT = Path(__file__).resolve().parents[1] / 'aegis-time-nts.sh'

class ReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='fh-nts-probe.')
        cls.addClassCleanup(cls.build.cleanup)
        cls.probe = None
        compiler = shutil.which('gcc')
        if compiler:
            cls.probe = Path(cls.build.name) / 'sync-probe.so'
            subprocess.run([compiler, '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                            '-O2', str(Path(__file__).with_name('sync_probe.c')),
                            '-o', str(cls.probe)], check=True, capture_output=True, timeout=20)

    def setUp(self):
        self.fixture = fixtures.BashTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root = self.fixture.root
        self.sh = self.fixture.sh
        self.public = self.fixture.public

    def direct(self, body, expected=0, timeout=10):
        p = subprocess.run(['/usr/bin/bash', '-p', '-c',
            'source '+shlex.quote(str(SCRIPT))+'\n'+body],
            capture_output=True, text=True, timeout=timeout)
        self.assertEqual(p.returncode, expected, p.stdout+'\n'+p.stderr)
        return p

    def test_01_empty_persist_is_rejected_before_sync(self):
        p = self.sh('sync() { echo UNEXPECTED_SYNC; return 0; }; persist', 2)
        self.assertNotIn('UNEXPECTED_SYNC', p.stdout)
        self.assertIn('refusing global sync', p.stderr)

    def test_02_persist_preserves_operand_boundaries(self):
        p = self.sh('''sync() { printf '%s\\0' "$@"; }
persist "$ANCHOR/with space" "$ANCHOR/--looks-like-option"
''')
        self.assertEqual(p.stdout.split('\0')[:-1],
                         ['--', str(self.root/'with space'), str(self.root/'--looks-like-option')])

    def test_03_seven_files_then_directory_then_parent(self):
        p = self.sh('''acquire_lock; make_plan
sync() {
    printf 'SYNC:'
    printf '<%s>' "$@"
    printf '\\n'
    command /usr/bin/sync "$@"
}
prepare_tx
load_tx
''')
        calls = [line for line in p.stdout.splitlines() if line.startswith('SYNC:')]
        self.assertEqual(len(calls), 3, calls)
        # Seven distinct file operands in one process, then two directory calls.
        operands = calls[0][len('SYNC:'):].strip('<>').split('><')
        self.assertEqual(operands[0], '--')
        self.assertEqual([Path(x).name for x in operands[1:]],
            ['before.conf', 'after.conf', 'before.sha', 'after.sha', 'input.sha', 'schema', 'status'])
        stage = str(Path(operands[1]).parent)
        self.assertEqual(calls[1], 'SYNC:<--><'+stage+'>')
        self.assertEqual(calls[2], 'SYNC:<--><'+str(self.root/'state/time-nts')+'>')
        self.assertEqual(self.fixture.conf.read_text(), fixtures.ORIGINAL)

    def test_04_failed_file_batch_prevents_publication(self):
        self.sh('''trap cleanup EXIT
acquire_lock; make_plan
sync() { return 7; }
prepare_tx
printf UNSAFE
''', 7)
        self.assertFalse((self.root/'state/time-nts/transaction').exists())
        self.assertEqual(self.fixture.conf.read_text(), fixtures.ORIGINAL)
        self.assertEqual(list((self.root/'state/time-nts').glob('.prepare.*')), [])

    def test_05_sync_exit_status_is_preserved(self):
        p = self.sh('sync() { return 7; }; persist "$CONF"; echo UNSAFE', 7)
        self.assertNotIn('UNSAFE', p.stdout)

    def test_06_real_bounded_child_has_no_lock_descriptor(self):
        lock = self.root/'probe.lock'
        py = '''import os,sys
st=os.stat(sys.argv[1]); leaks=[]
for name in os.listdir('/proc/self/fd'):
 try: info=os.fstat(int(name))
 except OSError: continue
 if (info.st_dev,info.st_ino)==(st.st_dev,st.st_ino): leaks.append(name)
assert not leaks, leaks
print('HELPER_HAS_NO_LOCK_FD')
'''
        # A numeric /proc/<Bash PID>/fd path can refer to a different PID view
        # in an executor namespace. Inherit the descriptor into an ordinary
        # test child and compare its real fstat identity with the lock file.
        parent_fd = '''import os,sys
target=os.stat(sys.argv[1]); descriptor=os.fstat(9)
assert (target.st_dev,target.st_ino)==(descriptor.st_dev,descriptor.st_ino)
print('PARENT_FD9_MATCHES_LOCK')
'''
        p = self.direct(f'''exec 9>> {shlex.quote(str(lock))}
flock -n 9
bounded /usr/bin/python3 -I -S -B -c {shlex.quote(py)} {shlex.quote(str(lock))}
/usr/bin/python3 -I -S -B -c {shlex.quote(parent_fd)} {shlex.quote(str(lock))}
if flock -n {shlex.quote(str(lock))} /usr/bin/true 9>&-; then exit 91; fi
printf 'PARENT_STILL_LOCKED\\n'
''')
        self.assertIn('HELPER_HAS_NO_LOCK_FD', p.stdout)
        self.assertIn('PARENT_FD9_MATCHES_LOCK', p.stdout)
        self.assertIn('PARENT_STILL_LOCKED', p.stdout)

    def test_07_scoped_descriptor_close_is_not_cloexec(self):
        # The parent's fd remains inheritable; bounded's command-local redirection
        # closes the child's copy. No false global FD_CLOEXEC claim is made.
        lock = self.root/'probe.lock'
        py = 'import os; assert os.get_inheritable(9); print("PARENT_FD_INHERITABLE")'
        p = self.direct(f'''exec 9>> {shlex.quote(str(lock))}
/usr/bin/python3 -I -S -B -c {shlex.quote(py)}
''')
        self.assertIn('PARENT_FD_INHERITABLE', p.stdout)

    def test_08_recovery_keeps_lock_if_waiting_parent_is_killed(self):
        fifo = self.root/'release-recovery'
        os.mkfifo(fifo, 0o600)
        body = self.fixture.preamble + '''
trap cleanup EXIT
acquire_lock
OPEN_TX=1
rollback_impl() {
    printf '%s\\n' "$BASHPID" > "$ANCHOR/recovery.pid"
    printf 'RECOVERY_READY\\n'
    read -r release < "$ANCHOR/release-recovery"
    [[ $release == RELEASE ]]
}
exit 23
'''
        p = subprocess.Popen(['/usr/bin/bash','-p','-c',body],stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,text=True,start_new_session=True)
        try:
            deadline = time.monotonic()+5
            while not (self.root/'recovery.pid').exists():
                self.assertIsNone(p.poll(), 'Parent exited before recovery began')
                self.assertLess(time.monotonic(),deadline, 'Recovery never started')
                time.sleep(0.01)
            self.sh('acquire_lock', 75)
            os.kill(p.pid, signal.SIGKILL)  # Kill ONLY the waiting parent.
            deadline = time.monotonic()+5
            while p.poll() is None:
                self.assertLess(time.monotonic(),deadline)
                time.sleep(0.01)
            self.sh('acquire_lock', 75)  # Actual cleanup's subshell still holds it.
            with fifo.open('w') as f:
                f.write('RELEASE\n')
            p.communicate(timeout=5)
            deadline = time.monotonic()+5
            lock = self.root/'state/time-nts/lock'
            with lock.open('a') as f:
                while True:
                    try:
                        fcntl.flock(f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        self.assertLess(time.monotonic(),deadline)
                        time.sleep(0.01)
            self.sh('acquire_lock')
        finally:
            try: os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            p.communicate(timeout=5)

    def test_09_cleanup_uses_ignore_dispositions(self):
        # Capture trap settings from the actual cleanup's rollback subshell.
        p = self.sh('''trap cleanup EXIT
OPEN_TX=1
rollback_impl() { trap -p INT TERM HUP; }
exit 23
''', 23)
        for sig in ('SIGINT','SIGTERM','SIGHUP'):
            self.assertIn("trap -- '' "+sig, p.stdout)

    def test_10_real_sync_batches_processes_not_fsync_operations(self):
        if self.probe is None:
            self.skipTest('GCC missing: optional userspace instrumentation not built')
        paths = []
        for i in range(7):
            path = self.root/f'small file {i}'
            path.write_text(f'record {i}\n')
            paths.append(str(path))
        env = dict(os.environ, LD_PRELOAD=str(self.probe))
        one_by_one = []
        for path in paths:
            p = subprocess.run(['/usr/bin/sync','--',path], env=env,
                               capture_output=True,text=True,check=True,timeout=5)
            one_by_one.extend(p.stderr.splitlines())
        # Dirty the files again; this is NOT a timing comparison.
        for path in paths:
            Path(path).write_text('changed record\n')
        p = subprocess.run(['/usr/bin/sync','--',*paths], env=env,
                           capture_output=True,text=True,check=True,timeout=5)
        together = p.stderr.splitlines()
        def counts(lines):
            return (sum(x.startswith('FH_TEST_LOAD ') for x in lines),
                    sum(x.startswith('FH_TEST_FSYNC ') for x in lines))
        self.assertEqual(counts(one_by_one), (7,7),one_by_one)
        self.assertEqual(counts(together), (1,7),together)
        for line in one_by_one+together:
            if line.startswith('FH_TEST_FSYNC '): self.assertEqual(line.split()[-1],'0')
        print('PROBE: separate sync loads=7, fsync calls=7; batched loads=1, fsync calls=7')

    def test_11_clean_reexec_stops_preload_inheritance_not_initial_loading(self):
        if self.probe is None:
            self.skipTest('GCC missing: optional userspace instrumentation not built')
        marker = self.root/'BASH_ENV_EXECUTED'
        envfile = self.root/'startup.sh'
        envfile.write_text('printf bad > '+shlex.quote(str(marker))+'\n')
        env = dict(os.environ, LD_PRELOAD=str(self.probe), BASH_ENV=str(envfile),
                   LD_LIBRARY_PATH='/nonexistent/fh-test', REVIEW_EXTRA='not-allowed')
        p = self.public('--help',env=env)
        self.assertEqual(p.returncode,0,p.stderr)
        loads = [x for x in p.stderr.splitlines() if x.startswith('FH_TEST_LOAD ')]
        # The deliberately supplied library DID load in the first Bash, before
        # any script body. It did NOT load in the clean Bash or its help cat.
        self.assertEqual(len(loads),1,loads)
        self.assertTrue(loads[0].endswith('/bash'), loads)
        self.assertFalse(marker.exists())
        self.assertIn('Usage:',p.stdout)
        print('PROBE: initial Bash preload loads=1; clean re-exec/helper preload loads=0')

    def test_12_internal_marker_rejects_loader_environment(self):
        p = self.public('--internal-clean','--help',
                        env={'LD_LIBRARY_PATH':'/nonexistent/fh-test'})
        self.assertEqual(p.returncode,2,p.stderr)
        self.assertIn('LD_LIBRARY_PATH',p.stderr)
        self.assertNotIn('Usage:',p.stdout)

if __name__ == '__main__':
    unittest.main(verbosity=2)
