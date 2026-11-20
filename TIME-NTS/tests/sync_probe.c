/* TEST ONLY: Linux/glibc loader + fsync observation.
 * Logs to stderr; fsync is forwarded to the real Linux syscall.
 * Does not alter time, system configuration, or any file contents.
 * This is userspace instrumentation, NOT NVMe tracing or a power-loss test.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

__attribute__((constructor)) static void loaded(void) {
    char exe[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n < 0) return;
    exe[n] = '\0';
    dprintf(STDERR_FILENO, "FH_TEST_LOAD %ld %s\n", (long)getpid(), exe);
}

int fsync(int fd) {
    int result = (int)syscall(SYS_fsync, fd);
    int saved_errno = errno;
    dprintf(STDERR_FILENO, "FH_TEST_FSYNC %ld %d %d\n", (long)getpid(), fd, result);
    errno = saved_errno;
    return result;
}
