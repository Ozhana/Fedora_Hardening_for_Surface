#!/usr/bin/python3 -I
"""AEGIS Firewall Sentinel: advanced egress containment, quarantine, kill-switch,
active response, live NFLOG forensics, and drift monitoring.

Target: native mutable Fedora 44 with AEGIS Network Hardening 0.7.0-rc4.
The program owns only its separate nftables tables (``inet aegis_sentinel`` plus
RAM-only ``inet aegis_panic``, ``inet aegis_blocklist``, and ``inet aegis_cgroup_lan``)
and its own systemd units/drop-in/config. It never rewrites the Network Hardening
zones, NetworkManager profile, firewalld.conf, or network sysctl files.
"""
from __future__ import annotations

import sys as _bootstrap_sys

if __name__ == "__main__" and not _bootstrap_sys.flags.isolated:
    print("STOP: invoke this program with /usr/bin/python3 -I or its isolated shebang", file=_bootstrap_sys.stderr)
    raise SystemExit(2)

import argparse
from collections.abc import Iterable
import dataclasses
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
import pathlib
import pwd
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, NoReturn

VERSION = "0.9.0-alpha2-review5"
SUPPORTED_FEDORA = "44"
NETWORK_VERSION = "0.7.0-rc4"
NETWORK_SHA256 = "6cf202fa3e19263cd4bba28f6148fd77d0d07481efbae7ce503d493331015a2e"
INSTALL_DIR = pathlib.Path("/usr/local/libexec/aegis/firewall-sentinel")
INSTALL_PATH = INSTALL_DIR / "aegis-firewall-sentinel.py"
NETWORK_SCRIPT = pathlib.Path("/usr/local/libexec/aegis/network-hardening/aegis-network.sh")
CONFIG_DIR = pathlib.Path("/etc/aegis/firewall-sentinel")
POLICY_FILE = CONFIG_DIR / "policy.json"
NFT_DIR = pathlib.Path("/etc/nftables")
NFT_FILE = NFT_DIR / "aegis-firewall-sentinel.nft"
STATE = pathlib.Path("/var/lib/aegis/firewall-sentinel")
TRANSACTIONS = STATE / "transactions"
MANAGED = STATE / "managed"
MONITOR_STATE = STATE / "monitor"
COMMITTED_MANIFEST = MANAGED / "committed-manifest.json"
# Must match RuntimeDirectory=aegis/firewall-sentinel in systemd units (ProtectSystem=strict).
RUNTIME = pathlib.Path("/run/aegis/firewall-sentinel")
LOCK = RUNTIME / "session.lock"
RUNTIME_REPORT = RUNTIME / "current-monitor.json"
LATEST_EVENT = MONITOR_STATE / "latest-change.json"
LATEST_HASH = MONITOR_STATE / "latest-state.sha256"
TABLE_FAMILY = "inet"
TABLE_NAME = "aegis_sentinel"
PANIC_TABLE_NAME = "aegis_panic"
BLOCKLIST_TABLE_NAME = "aegis_blocklist"
CGROUP_TABLE_NAME = "aegis_cgroup_lan"
NFLOG_GROUP = 10
NFLOG_SNAPLEN = 128
NFLOG_RATE = 5
NFLOG_BURST = 20
DOT_SERVER_NAME_DEFAULT = "dns.quad9.net"
UNIT_DIR = pathlib.Path("/etc/systemd/system")
NM_DROPIN_DIR = UNIT_DIR / "NetworkManager.service.d"
NM_DROPIN = NM_DROPIN_DIR / "90-aegis-firewall-sentinel.conf"
NM_DISPATCH_DIR = pathlib.Path("/etc/NetworkManager/dispatcher.d")
NM_DISPATCH_PRE_UP_DIR = NM_DISPATCH_DIR / "pre-up.d"
NM_DISPATCH_PRE_DOWN_DIR = NM_DISPATCH_DIR / "pre-down.d"
NM_TRUST_DISPATCH = NM_DISPATCH_DIR / "90-aegis-firewall-sentinel-trust"
NM_TRUST_PRE_UP = NM_DISPATCH_PRE_UP_DIR / "90-aegis-firewall-sentinel-trust"
NM_TRUST_PRE_DOWN = NM_DISPATCH_PRE_DOWN_DIR / "90-aegis-firewall-sentinel-trust"
ENFORCE_UNIT = UNIT_DIR / "aegis-firewall-sentinel.service"
MONITOR_UNIT = UNIT_DIR / "aegis-firewall-sentinel-monitor.service"
TIMER_UNIT = UNIT_DIR / "aegis-firewall-sentinel-monitor.timer"
PATH_UNIT = UNIT_DIR / "aegis-firewall-sentinel-monitor.path"
UNIT_NAMES = (
    "aegis-firewall-sentinel.service",
    "aegis-firewall-sentinel-monitor.service",
    "aegis-firewall-sentinel-monitor.timer",
    "aegis-firewall-sentinel-monitor.path",
)
PERSISTENT_UNIT_NAMES = (
    "aegis-firewall-sentinel.service",
    "aegis-firewall-sentinel-monitor.timer",
    "aegis-firewall-sentinel-monitor.path",
)
MONITOR_PERSISTENT_UNITS = (
    "aegis-firewall-sentinel-monitor.timer",
    "aegis-firewall-sentinel-monitor.path",
)
MANAGED_PATHS = (
    POLICY_FILE,
    NFT_FILE,
    ENFORCE_UNIT,
    MONITOR_UNIT,
    TIMER_UNIT,
    PATH_UNIT,
    NM_DROPIN,
    NM_TRUST_DISPATCH,
    NM_TRUST_PRE_UP,
    NM_TRUST_PRE_DOWN,
)
STATE_PATHS = (
    MANAGED / "nft-table.sha256",
    MANAGED / "latest-transaction",
    COMMITTED_MANIFEST,
)
# Read-only base files owned by AEGIS Network Hardening and watched by PATH_UNIT.
BASE_WATCHED_PATHS = (
    pathlib.Path("/etc/firewalld/firewalld.conf"),
    pathlib.Path("/etc/firewalld/zones/aegis-public.xml"),
    pathlib.Path("/etc/firewalld/zones/aegis-lan.xml"),
    pathlib.Path("/etc/NetworkManager/conf.d/90-aegis-network-hardening.conf"),
    pathlib.Path("/etc/sysctl.d/91-aegis-network-hardening.conf"),
    pathlib.Path("/var/lib/aegis/network-hardening/managed/profile.uuid"),
    pathlib.Path("/var/lib/aegis/network-hardening/managed/profile.device"),
)
LOGINUID_PATH = pathlib.Path("/proc/self/loginuid")
SESSIONID_PATH = pathlib.Path("/proc/self/sessionid")
BOOT_ID_PATH = pathlib.Path("/proc/sys/kernel/random/boot_id")
CGROUP_ROOT = pathlib.Path("/sys/fs/cgroup")
CGROUP_STATE = RUNTIME / "cgroup-lan.json"
CHILD_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
    "LANG": "C",
    "TZ": "UTC",
    "HOME": "/root",
    "SYSTEMD_PAGER": "cat",
    "SYSTEMD_COLORS": "0",
    "SYSTEMD_URLIFY": "0",
}
MAX_OUTPUT = 1024 * 1024
MAX_FILE = 1024 * 1024
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
TX_RE = re.compile(r"^T-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
FOREIGN_TABLE_RE = re.compile(r"^(inet|ip|ip6|arp|bridge|netdev):[A-Za-z0-9_.-]{1,64}$")
TTL_RE = re.compile(r"^([1-9][0-9]{0,5})([smhd])$")
CGROUP_REL_RE = re.compile(r"^[A-Za-z0-9_.@:/-]{1,256}$")
DEFAULT_DOT_SERVERS = ("9.9.9.9", "149.112.112.112", "2620:fe::9", "2620:fe::fe")
EXPECTED_SMB_DESTINATIONS = {
    "ipv4": ["10.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"],
    "ipv6": ["fc00::/7", "fe80::/10"],
}
REVIEWED_PACKAGES = {
    "firewalld": ((2, 4, 4), (2, 5, 0)),
    "nftables": ((1, 1, 6), (1, 2, 0)),
    "NetworkManager": ((1, 56, 1), (1, 57, 0)),
    "systemd": ((259, 10), (260, 0)),
}


class Stop(RuntimeError):
    """Fail-closed operational refusal."""


class SignalExit(BaseException):
    def __init__(self, signum: int):
        super().__init__(f"signal {signum}")
        self.signum = signum
        self.code = 128 + signum


def install_signal_handlers() -> None:
    def handler(signum: int, _frame: Any) -> None:
        raise SignalExit(signum)

    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, handler)


@dataclasses.dataclass(frozen=True)
class CommandResult:
    code: int
    output: str


def say(text: str = "") -> None:
    print(text)


def stop(message: str) -> NoReturn:
    raise Stop(message)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def pretty_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    with path.open("rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def _terminate_process_group(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 2.0
    while proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        pass


def run(
    args: list[str],
    *,
    timeout: float = 30.0,
    cap: int = MAX_OUTPUT,
    check: bool = False,
    stdin: bytes | None = None,
) -> CommandResult:
    """Run one fixed absolute executable with bounded time/output, non-blocking I/O, and zero zombies."""
    if not args or not args[0].startswith("/"):
        stop("External commands must use absolute paths")
    if timeout <= 0 or cap <= 0:
        stop("Invalid command resource bound")
    if stdin is not None and len(stdin) > MAX_FILE:
        stop("Command input exceeded the configured bound")
    try:
        proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=CHILD_ENV,
            cwd="/",
            start_new_session=True,
            close_fds=True,
        )
    except FileNotFoundError:
        stop(f"Executable is missing: {args[0]}")

    assert proc.stdout is not None
    os.set_blocking(proc.stdout.fileno(), False)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, data="stdout")

    stdin_view = memoryview(stdin) if stdin is not None else None
    stdin_offset = 0
    if stdin_view is not None:
        assert proc.stdin is not None
        os.set_blocking(proc.stdin.fileno(), False)
        if len(stdin_view) == 0:
            proc.stdin.close()
            stdin_view = None
        else:
            selector.register(proc.stdin, selectors.EVENT_WRITE, data="stdin")

    output = bytearray()
    deadline = time.monotonic() + timeout
    stdout_open = True
    try:
        while stdout_open or stdin_view is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process_group(proc)
                stop(f"Command timeout: {args[0]}")
            events = selector.select(min(0.25, remaining))
            if not events:
                if proc.poll() is not None and not stdout_open:
                    break
                continue
            for key, _mask in events:
                if key.data == "stdin" and stdin_view is not None and proc.stdin is not None:
                    try:
                        written = os.write(proc.stdin.fileno(), stdin_view[stdin_offset : stdin_offset + 65536])
                        stdin_offset += written
                        if stdin_offset >= len(stdin_view):
                            selector.unregister(proc.stdin)
                            proc.stdin.close()
                            stdin_view = None
                    except (BrokenPipeError, OSError):
                        selector.unregister(proc.stdin)
                        proc.stdin.close()
                        stdin_view = None
                elif key.data == "stdout":
                    try:
                        chunk = os.read(proc.stdout.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(proc.stdout)
                        stdout_open = False
                        continue
                    output.extend(chunk)
                    if len(output) > cap:
                        _terminate_process_group(proc)
                        stop(f"Command output exceeded {cap} bytes: {args[0]}")
        code = proc.wait(timeout=max(0.1, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        _terminate_process_group(proc)
        stop(f"Command timeout while waiting: {args[0]}")
    except BaseException:
        _terminate_process_group(proc)
        raise
    finally:
        selector.close()
        if proc.stdin is not None and not proc.stdin.closed:
            proc.stdin.close()
        if not proc.stdout.closed:
            proc.stdout.close()

    data = bytes(output)
    if b"\x00" in data:
        stop(f"Command returned NUL bytes: {args[0]}")
    text = data.decode("utf-8", "replace")
    if check and code != 0:
        stop(f"Command failed ({code}): {' '.join(args)}\n{text.rstrip()}")
    return CommandResult(code, text)


def command_path(name: str) -> str:
    path = shutil.which(name, path=CHILD_ENV["PATH"])
    if not path or not path.startswith("/"):
        stop(f"Missing dependency: {name}")
    return path


def ensure_root() -> None:
    if os.getuid() != 0 or os.geteuid() != 0:
        stop("Root is required for this action")


def read_os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    for line in pathlib.Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        data[key] = value.strip().strip('"').strip("'")
    return data


def version_tuple(value: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", value.split("-", 1)[0])
    return tuple(int(x) for x in nums[:4])


def package_version(name: str) -> str:
    result = run(["/usr/bin/rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\n", name])
    if result.code != 0:
        stop(f"Required Fedora package is not installed: {name}")
    return result.output.strip()


def platform_inventory() -> dict[str, str]:
    osr = read_os_release()
    return {
        "os_id": osr.get("ID", "UNKNOWN"),
        "os_version": osr.get("VERSION_ID", "UNKNOWN"),
        "firewalld": package_version("firewalld"),
        "nftables": package_version("nftables"),
        "NetworkManager": package_version("NetworkManager"),
        "systemd": package_version("systemd"),
        "kernel": os.uname().release,
    }


def unreviewed_package_versions(versions: dict[str, str]) -> list[str]:
    warnings: list[str] = []
    for name, (_minimum, upper_exclusive) in REVIEWED_PACKAGES.items():
        current = version_tuple(versions[name])
        if current >= upper_exclusive:
            warnings.append(f"{name}={versions[name]} (>= {'.'.join(map(str, upper_exclusive))})")
    return warnings


def require_boot_runtime_platform() -> None:
    """Zero-fork boot check for runtime-load/network-gate; avoids touching RPM SQLite DB."""
    osr = read_os_release()
    if osr.get("ID") != "fedora" or osr.get("VERSION_ID") != SUPPORTED_FEDORA:
        stop(f"This release targets native Fedora {SUPPORTED_FEDORA}")
    kernel = os.uname().release
    if version_tuple(kernel) < (6, 3):
        stop(f"The reviewed nft destroy transaction requires Linux 6.3+; found {kernel}")


def require_platform(*, mutation: bool = False, strict_upper_bound: bool = True) -> dict[str, str]:
    versions = platform_inventory()
    if versions["os_id"] != "fedora" or versions["os_version"] != SUPPORTED_FEDORA:
        stop(f"This release targets native Fedora {SUPPORTED_FEDORA}")
    if mutation and (pathlib.Path("/run/ostree-booted").exists() or pathlib.Path("/run/bootc").exists()):
        stop("Atomic/bootc systems are not supported for mutation")
    virt = run(["/usr/bin/systemd-detect-virt", "--container"])
    if mutation and virt.code == 0:
        stop("Container execution is not supported for mutation")
    if mutation:
        enforcing = run(["/usr/sbin/getenforce"], check=True).output.strip()
        if enforcing != "Enforcing":
            stop("SELinux must already be Enforcing")
    kernel = versions["kernel"]
    if version_tuple(kernel) < (6, 3):
        stop(f"The reviewed nft destroy transaction requires Linux 6.3+; found {kernel}")
    for name, (minimum, upper_exclusive) in REVIEWED_PACKAGES.items():
        current = version_tuple(versions[name])
        if current < minimum:
            stop(f"{name} is older than the minimum supported Fedora 44 version: {versions[name]}")
        if strict_upper_bound and current >= upper_exclusive:
            stop(
                f"{name} is newer than the reviewed Fedora 44 package family ({versions[name]}); "
                "re-audit or pass --allow-newer-packages if intentional"
            )
    return versions


def ensure_service_active(name: str) -> None:
    result = run(["/usr/bin/systemctl", "is-active", "--quiet", name])
    if result.code != 0:
        stop(f"Required service is not active: {name}")


def _proc_uid_ppid(pid: int) -> tuple[int, int] | None:
    """Read real UID and PPid from one /proc status snapshot."""
    try:
        lines = pathlib.Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    uid: int | None = None
    ppid: int | None = None
    for line in lines:
        if line.startswith("Uid:"):
            fields = line.split()
            if len(fields) >= 2 and fields[1].isdigit():
                uid = int(fields[1])
        elif line.startswith("PPid:"):
            value = line.split(":", 1)[1].strip()
            if value.isdigit():
                ppid = int(value)
    if uid is None or ppid is None:
        return None
    return uid, ppid


def _proc_audit_session(pid: int) -> str | None:
    try:
        value = pathlib.Path(f"/proc/{pid}/sessionid").read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None
    if not value.isdigit() or value == "4294967295":
        return None
    return value


def _sudo_invoker_audit_sessions(login_uid: int) -> list[str]:
    """Recover audit-session IDs from the actual non-root ancestors of sudo.

    sudo may open a fresh PAM/logind session for the privileged command.  The
    resulting root process can therefore have a different audit session from
    the terminal shell that invoked sudo.  Walk the parent chain and trust only
    audit IDs carried by ancestors whose real UID equals the kernel loginuid.
    """
    found: list[str] = []
    seen: set[int] = set()
    pid = os.getppid()
    for _ in range(64):
        if pid <= 1 or pid in seen:
            break
        seen.add(pid)
        ident = _proc_uid_ppid(pid)
        if ident is None:
            break
        uid, ppid = ident
        if uid == login_uid:
            audit = _proc_audit_session(pid)
            if audit is not None and audit not in found:
                found.append(audit)
        pid = ppid
    return found


def require_local_recovery_session() -> None:
    """Bind mutation to the real local interactive session that invoked sudo.

    The privileged command itself may receive a new PAM/logind audit session.
    Therefore /proc/self/sessionid is diagnostic only.  The security decision
    is made from the kernel loginuid plus the audit session of the actual
    non-root ancestor process in the sudo parent chain, then cross-checked with
    logind Active/Remote/Class/Type properties.
    """
    try:
        login_uid_raw = LOGINUID_PATH.read_text(encoding="ascii").strip()
        root_audit = SESSIONID_PATH.read_text(encoding="ascii").strip()
    except OSError:
        stop("Cannot establish the invoking login/audit identity")
    if not login_uid_raw.isdigit() or login_uid_raw == "4294967295":
        stop("Mutation requires an attributable local login session")
    login_uid = int(login_uid_raw)

    sudo_uid = os.environ.get("SUDO_UID", "")
    sudo_tty = os.environ.get("SUDO_TTY", "")
    if not sudo_uid.isdigit() or int(sudo_uid) != login_uid:
        stop("Mutation must be invoked through sudo by the kernel login user")
    if not sudo_tty.startswith("/dev/"):
        stop("Mutation requires sudo from an attached terminal")
    try:
        tty_st = os.stat(sudo_tty, follow_symlinks=False)
    except OSError:
        stop("Cannot validate the sudo terminal")
    if not stat.S_ISCHR(tty_st.st_mode) or tty_st.st_uid != login_uid:
        stop("The sudo terminal is not a character device owned by the invoking login user")

    invoker_audits = _sudo_invoker_audit_sessions(login_uid)
    if not invoker_audits:
        stop("Cannot bind sudo to a non-root ancestor audit session")

    interactive_classes = {"user", "user-early", "user-light", "user-early-light"}
    interactive_types = {"wayland", "x11", "tty"}
    rows = run(["/usr/bin/loginctl", "list-sessions", "--no-legend"], timeout=15)
    if rows.code != 0:
        stop("Cannot query active logind sessions")

    inspected: list[str] = []
    for line in rows.output.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[1] != login_uid_raw:
            continue
        sid = fields[0]
        res = run(
            [
                "/usr/bin/loginctl",
                "show-session",
                sid,
                "-p", "Active",
                "-p", "Remote",
                "-p", "Type",
                "-p", "Class",
                "-p", "Audit",
                "-p", "User",
            ],
            timeout=10,
        )
        if res.code != 0:
            continue
        props: dict[str, str] = {}
        for row in res.output.splitlines():
            if "=" in row:
                key, value = row.split("=", 1)
                props[key] = value.strip()
        inspected.append(
            f"sid={sid},audit={props.get('Audit','?')},active={props.get('Active','?')},"
            f"remote={props.get('Remote','?')},class={props.get('Class','?')},type={props.get('Type','?')}"
        )
        if props.get("User") != login_uid_raw or props.get("Audit") not in invoker_audits:
            continue
        if (
            props.get("Active") == "yes"
            and props.get("Remote") == "no"
            and props.get("Class") in interactive_classes
            and props.get("Type") in interactive_types
        ):
            return

    detail = "; ".join(inspected[:8]) if inspected else "no matching-UID logind sessions"
    # A graphical terminal may belong to user@UID.service (Class=manager) even
    # while the user's physical Wayland login is a separate logind session.
    # Merely seeing an active Wayland session with the same UID is NOT proof
    # that this particular command originated from that physical seat: a
    # remote/background process can also run in the user manager. Do not
    # grant implicit manager-session exceptions to this privilege gate.
    if any(
        f"audit={audit}" in entry and "class=manager" in entry
        for audit in invoker_audits for entry in inspected
    ):
        stop(
            "Invoking terminal belongs to a systemd user-manager audit session; "
            "this is not a verifiable local-seat provenance. "
            "For unchanged strict security, log in on a physical virtual console "
            "(e.g. Ctrl+Alt+F3), confirm an active local Class=user, Type=tty session, "
            "then run sudo there. "
            f"(loginuid={login_uid_raw}, root_audit={root_audit}, "
            f"invoker_audits={','.join(invoker_audits)}; {detail})"
        )
    stop(
        "Mutation must originate from the active local interactive session that invoked sudo "
        f"(loginuid={login_uid_raw}, root_audit={root_audit}, invoker_audits={','.join(invoker_audits)}; {detail})"
    )

def require_break_glass_tty() -> None:
    """Minimal break-glass gate; deliberately avoids the normal logind dependency chain."""
    if not sys.stdin.isatty():
        stop("Break-glass quarantine requires an interactive TTY")
    try:
        login_uid = LOGINUID_PATH.read_text(encoding="ascii").strip()
    except OSError:
        stop("Cannot establish break-glass login identity")
    if not login_uid.isdigit() or login_uid == "4294967295":
        stop("Break-glass quarantine requires an attributable login session")


def ensure_service_inactive(name: str) -> None:
    result = run(["/usr/bin/systemctl", "is-active", "--quiet", name])
    if result.code == 0:
        stop(f"Conflicting service is active: {name}")


def require_systemd_invocation(unit_name: str) -> None:
    """Bind an internal action to the exact systemd unit/cgroup invocation."""
    invocation = os.environ.get("INVOCATION_ID", "")
    if not re.fullmatch(r"[0-9a-f]{32}", invocation):
        stop("This internal action may only be invoked by a systemd service transaction")
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,240}\.service", unit_name):
        stop("Unsafe systemd unit identity")
    props = systemd_properties(unit_name, ("InvocationID", "ControlGroup"))
    if props.get("InvocationID") != invocation:
        stop("Systemd invocation identity mismatch")
    control_group = props.get("ControlGroup", "")
    if not control_group.startswith("/") or ".." in control_group:
        stop("Systemd control-group identity is unavailable")
    try:
        memberships = pathlib.Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError):
        stop("Cannot verify the systemd control-group boundary")
    member = False
    for line in memberships:
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        path = parts[2]
        if path == control_group or path.startswith(control_group.rstrip("/") + "/"):
            member = True
            break
    if not member:
        stop("Internal action is not running inside the expected systemd unit")


def installed_runtime_sha256() -> str:
    """Inspect and hash INSTALL_PATH atomically over one O_NOFOLLOW descriptor."""
    state = inspect_optional_file(INSTALL_PATH)
    if not state["exists"]:
        stop(f"Installed runtime is missing: {INSTALL_PATH}")
    if state["mode"] != 0o755:
        stop("Installed runtime mode must be 0755")
    return str(state["sha256"])


def require_installed_runtime() -> None:
    actual = pathlib.Path(os.path.realpath(sys.argv[0]))
    if actual != INSTALL_PATH:
        stop(f"Run mutating/runtime actions from the installed copy: {INSTALL_PATH}")
    installed_runtime_sha256()


def safe_iface(name: str) -> bool:
    return bool(IFACE_RE.fullmatch(name)) and name not in {".", ".."}


def resolve_dot_uid() -> int:
    try:
        uid = pwd.getpwnam("systemd-resolve").pw_uid
    except KeyError:
        stop("System user systemd-resolve does not exist; cannot bind strict DoT lock")
    if uid <= 0:
        stop("Unsafe systemd-resolve UID")
    return int(uid)


def normalize_dot_servers(servers: Iterable[str]) -> list[str]:
    cleaned: list[str] = []
    for raw in servers:
        try:
            addr = ipaddress.ip_address(raw.strip())
        except ValueError:
            stop(f"Invalid DoT server IP address: {raw}")
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
            stop(f"Unsafe DoT server IP address: {addr}")
        cleaned.append(str(addr))
    unique = sorted(set(cleaned))
    if not unique or len(unique) > 16:
        stop("Provide between 1 and 16 valid DoT server IP addresses")
    return unique


def normalize_dot_server_name(value: str) -> str:
    name = value.strip().rstrip(".").lower()
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", name):
        stop(f"Invalid DoT TLS server name: {value}")
    return name


def dot_resolver_attestation(servers: Iterable[str], server_name: str) -> list[str]:
    """Verify strict systemd-resolved DoT prerequisites without changing resolver state."""
    findings: list[str] = []
    approved = set(normalize_dot_servers(servers))
    expected_name = normalize_dot_server_name(server_name)
    if run(["/usr/bin/systemctl", "is-active", "--quiet", "systemd-resolved.service"]).code != 0:
        return ["systemd-resolved.service is not active"]
    if shutil.which("resolvectl", path=CHILD_ENV["PATH"]) is None:
        return ["resolvectl is unavailable"]
    tls = run(["/usr/bin/resolvectl", "dnsovertls"], timeout=20, cap=256 * 1024)
    if tls.code != 0:
        findings.append("cannot query systemd-resolved DNSOverTLS state")
    else:
        global_yes = any(
            line.strip().lower().startswith("global:") and line.split(":", 1)[1].strip().lower() == "yes"
            for line in tls.output.splitlines() if ":" in line
        )
        if not global_yes:
            findings.append("systemd-resolved global DNSOverTLS is not set to yes")
    dns = run(["/usr/bin/resolvectl", "dns"], timeout=20, cap=256 * 1024)
    if dns.code != 0:
        findings.append("cannot query systemd-resolved DNS server state")
    else:
        matches: set[str] = set()
        for token in dns.output.replace("\n", " ").split():
            token = token.strip(",")
            if "#" not in token:
                continue
            address_part, name_part = token.rsplit("#", 1)
            if "%" in address_part:
                address_part = address_part.split("%", 1)[0]
            address_part = address_part.strip("[]")
            try:
                address = str(ipaddress.ip_address(address_part))
            except ValueError:
                continue
            if address in approved and name_part.rstrip(".").lower() == expected_name:
                matches.add(address)
        if not matches:
            findings.append(
                f"systemd-resolved has no approved DoT server configured as IP#{expected_name}"
            )
    try:
        current_uid = resolve_dot_uid()
    except Stop as exc:
        findings.append(str(exc))
    else:
        if current_uid <= 0:
            findings.append("systemd-resolve UID is unsafe")
    return findings


def parse_vpn_endpoint(spec: str) -> dict[str, Any]:
    """Parse IP:PORT[/udp|tcp] or [IPv6]:PORT[/udp|tcp] strictly."""
    raw = spec.strip()
    proto = "udp"
    if "/" in raw:
        addr_port, proto_part = raw.rsplit("/", 1)
        proto = proto_part.lower()
        if proto not in {"udp", "tcp"}:
            stop(f"VPN endpoint protocol must be udp or tcp: {spec}")
    else:
        addr_port = raw
    if addr_port.startswith("["):
        if "]:" not in addr_port:
            stop(f"Invalid IPv6 VPN endpoint syntax (expected [IPv6]:PORT): {spec}")
        host_s, port_s = addr_port[1:].rsplit("]:", 1)
    else:
        if addr_port.count(":") != 1:
            stop(f"Invalid VPN endpoint syntax (expected IP:PORT or [IPv6]:PORT): {spec}")
        host_s, port_s = addr_port.rsplit(":", 1)
    try:
        addr = ipaddress.ip_address(host_s)
    except ValueError:
        stop(f"Invalid VPN endpoint IP: {spec}")
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        stop(f"Unsafe VPN endpoint IP: {addr}")
    if not port_s.isdigit() or not (1 <= int(port_s) <= 65535):
        stop(f"Invalid VPN endpoint port: {spec}")
    return {"ip": str(addr), "family": addr.version, "port": int(port_s), "proto": proto}


def normalize_foreign_tables(values: Iterable[str]) -> list[str]:
    result: set[str] = set()
    for item in values:
        val = item.strip()
        if not FOREIGN_TABLE_RE.fullmatch(val):
            stop(f"Invalid foreign table specification (expected family:name): {item}")
        result.add(val)
    if len(result) > 32:
        stop("Too many allowed foreign tables")
    return sorted(result)


def parse_block_target(raw: str) -> tuple[str, int]:
    """Validate IP/CIDR for dynamic blocklist, refusing loopback and default-route footguns."""
    try:
        net = ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError:
        stop(f"Invalid IP/CIDR target: {raw}")
    if net.prefixlen == 0 or net.is_loopback or net.is_unspecified or net.is_multicast:
        stop(f"Refusing to block unsafe/reserved network: {net}")
    if net.version == 4 and ipaddress.IPv4Address("127.0.0.1") in net:
        stop(f"Refusing to block CIDR overlapping loopback: {net}")
    if net.version == 6 and ipaddress.IPv6Address("::1") in net:
        stop(f"Refusing to block CIDR overlapping loopback: {net}")
    return str(net), net.version


def parse_ttl_seconds(raw: str) -> int:
    match = TTL_RE.fullmatch(raw.strip())
    if not match:
        stop("Invalid TTL format (examples: 300s, 30m, 24h, 7d)")
    amount, unit = int(match.group(1)), match.group(2)
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    seconds = amount * mult
    if seconds < 60 or seconds > 30 * 86400:
        stop("TTL must be between 60s and 30d")
    return seconds


def ensure_dir(path: pathlib.Path, mode: int, *, root_owned: bool = True, exact_mode: bool = True) -> None:
    """Create an absolute directory without following writable/symlink ancestors."""
    if not path.is_absolute():
        stop(f"Directory path must be absolute: {path}")
    current = pathlib.Path("/")
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        if part in {"", ".", ".."}:
            stop(f"Unsafe directory component: {path}")
        current /= part
        final = index == len(parts) - 1
        target_mode = mode if final else 0o755
        try:
            st = current.lstat()
        except FileNotFoundError:
            try:
                os.mkdir(current, target_mode)
                os.chmod(current, target_mode)
            except FileExistsError:
                pass
            st = current.lstat()
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
            stop(f"Unsafe directory: {current}")
        if root_owned and st.st_uid != 0:
            stop(f"Directory is not root-owned: {current}")
        if stat.S_IMODE(st.st_mode) & 0o022:
            stop(f"Directory is group/world writable: {current}")
    if exact_mode and stat.S_IMODE(path.lstat().st_mode) != mode:
        os.chmod(path, mode)


def check_parent_chain(path: pathlib.Path) -> None:
    current = pathlib.Path("/")
    for part in path.parts[1:-1]:
        current /= part
        if not current.exists():
            break
        st = current.lstat()
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0:
            stop(f"Unsafe path ancestry: {current}")
        if stat.S_IMODE(st.st_mode) & 0o022:
            stop(f"Writable path ancestry: {current}")


def inspect_optional_file(path: pathlib.Path, *, max_size: int = MAX_FILE) -> dict[str, Any]:
    check_parent_chain(path)
    if not os.path.lexists(path):
        return {"exists": False}
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        stop(f"Cannot safely open managed file {path}: {exc}")
    try:
        st = os.fstat(fd)
        lst = os.lstat(path)
        if (st.st_dev, st.st_ino) != (lst.st_dev, lst.st_ino):
            stop(f"Managed path changed while opening: {path}")
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(lst.st_mode):
            stop(f"Managed path is not a regular non-symlink file: {path}")
        if st.st_uid != 0 or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) & 0o022:
            stop(f"Unsafe managed file ownership/mode/link count: {path}")
        if st.st_size > max_size:
            stop(f"Managed file is too large: {path}")
        chunks = bytearray()
        while True:
            chunk = os.read(fd, min(65536, max_size + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > max_size:
                stop(f"Managed file grew beyond the size limit: {path}")
        data = bytes(chunks)
        final = os.fstat(fd)
        if (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != (
            st.st_dev,
            st.st_ino,
            st.st_size,
            st.st_mtime_ns,
        ):
            stop(f"Managed file changed during inspection: {path}")
        return {
            "exists": True,
            "mode": stat.S_IMODE(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "sha256": sha256_bytes(data),
            "data": data,
        }
    finally:
        os.close(fd)


def read_managed_text(path: pathlib.Path, *, max_size: int = MAX_FILE, encoding: str = "utf-8") -> str | None:
    state = inspect_optional_file(path, max_size=max_size)
    if not state["exists"]:
        return None
    try:
        return state["data"].decode(encoding)
    except UnicodeDecodeError:
        stop(f"Managed file has invalid {encoding} encoding: {path}")


def read_managed_json(path: pathlib.Path, *, max_size: int = MAX_FILE) -> Any:
    text = read_managed_text(path, max_size=max_size)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        stop(f"Managed JSON file is corrupt: {path}")


def atomic_write(path: pathlib.Path, data: bytes, mode: int) -> None:
    shared_parent = path.parent in {NFT_DIR, UNIT_DIR, NM_DROPIN_DIR, NM_DISPATCH_DIR, NM_DISPATCH_PRE_UP_DIR, NM_DISPATCH_PRE_DOWN_DIR}
    parent_mode = 0o755 if shared_parent else 0o700
    ensure_dir(path.parent, parent_mode, exact_mode=not shared_parent)
    check_parent_chain(path)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp = pathlib.Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, 0, 0)
        with os.fdopen(fd, "wb", closefd=True) as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


class Lock:
    def __init__(self, wait: float = 0.0):
        self.fd = -1
        self.wait = wait

    def __enter__(self) -> Lock:
        ensure_dir(RUNTIME, 0o700)
        self.fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        st = os.fstat(self.fd)
        path_st = os.lstat(LOCK)
        if (
            not stat.S_ISREG(st.st_mode)
            or stat.S_ISLNK(path_st.st_mode)
            or st.st_uid != 0
            or st.st_nlink != 1
            or stat.S_IMODE(st.st_mode) != 0o600
            or (st.st_dev, st.st_ino) != (path_st.st_dev, path_st.st_ino)
        ):
            os.close(self.fd)
            self.fd = -1
            stop("Unsafe lock inode")
        deadline = time.monotonic() + self.wait
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                final = os.lstat(LOCK)
                if (final.st_dev, final.st_ino) != (st.st_dev, st.st_ino):
                    os.close(self.fd)
                    self.fd = -1
                    stop("Lock path changed after acquisition")
                return self
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(self.fd)
                    self.fd = -1
                    stop("BUSY: another Firewall Sentinel operation holds the lock")
                time.sleep(0.1)

    def __exit__(self, *_: Any) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def is_session_lock_held() -> bool:
    if not os.path.lexists(LOCK):
        return False
    try:
        fd = os.open(LOCK, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False
        except BlockingIOError:
            return True
    finally:
        os.close(fd)


def verify_network_runtime_file() -> None:
    state = inspect_optional_file(NETWORK_SCRIPT)
    if not state["exists"]:
        stop(f"AEGIS Network Hardening is not installed: {NETWORK_SCRIPT}")
    if state["mode"] != 0o755:
        stop("AEGIS Network Hardening runtime mode is unsafe")
    if state["sha256"] != NETWORK_SHA256:
        stop("AEGIS Network Hardening runtime hash differs from the reviewed 0.7.0-rc4 source")


def run_network_script(action: str, *, timeout: float = 60.0, check: bool = False) -> CommandResult:
    verify_network_runtime_file()
    return run(["/usr/bin/bash", "-p", "--", str(NETWORK_SCRIPT), action], timeout=timeout, check=check)


def network_version() -> str:
    return run_network_script("version", timeout=30.0, check=True).output.strip()


def verify_network_layer() -> None:
    version = network_version()
    if version != NETWORK_VERSION:
        stop(f"This release requires AEGIS Network Hardening {NETWORK_VERSION}; found {version}")
    result = run_network_script("verify", timeout=60.0)
    if result.code != 0:
        stop(
            "AEGIS Network Hardening verify failed; Firewall Sentinel will not build on a drifting base\n"
            + result.output.rstrip()
        )


def read_network_identity() -> tuple[str, str]:
    uuid_path = pathlib.Path("/var/lib/aegis/network-hardening/managed/profile.uuid")
    device_path = pathlib.Path("/var/lib/aegis/network-hardening/managed/profile.device")
    uuid_raw = read_managed_text(uuid_path, max_size=128, encoding="ascii")
    device_raw = read_managed_text(device_path, max_size=64, encoding="ascii")
    if uuid_raw is None or device_raw is None:
        stop("Committed Network Hardening profile identity is absent")
    uuid = uuid_raw.strip()
    device = device_raw.strip()
    if (
        not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", uuid)
        or not safe_iface(device)
    ):
        stop("Network Hardening profile identity is malformed")
    return uuid.lower(), device


def base_watched_hashes() -> dict[str, str]:
    digests: dict[str, str] = {}
    for path in BASE_WATCHED_PATHS:
        state = inspect_optional_file(path)
        digests[str(path)] = state.get("sha256", "ABSENT") if state["exists"] else "ABSENT"
    return digests


def render_policy(
    trusted_interfaces: list[str],
    quarantine: bool,
    *,
    trusted_connection_uuids: Iterable[str],
    allow_lan_smb: bool,
    allow_lan_ssdp: bool,
    block_direct_dns: bool = False,
    strict_dot_resolver: bool = False,
    dot_servers: Iterable[str] = DEFAULT_DOT_SERVERS,
    dot_server_name: str = DOT_SERVER_NAME_DEFAULT,
    vpn_killswitch: dict[str, Any] | None = None,
    allowed_foreign_tables: Iterable[str] = (),
) -> dict[str, Any]:
    if not trusted_interfaces or any(not safe_iface(x) for x in trusted_interfaces):
        stop("At least one valid reviewed physical interface is required")
    trusted_uuids = sorted(set(str(x).lower() for x in trusted_connection_uuids))
    if not trusted_uuids or any(
        not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", x)
        for x in trusted_uuids
    ):
        stop("At least one valid trusted NetworkManager connection UUID is required")
    trusted_discovery = [3702, 5353]
    if allow_lan_ssdp:
        trusted_discovery.append(1900)
    dot_uid = resolve_dot_uid() if strict_dot_resolver else None
    normalized_dot = normalize_dot_servers(dot_servers) if strict_dot_resolver else []
    normalized_dot_name = normalize_dot_server_name(dot_server_name) if strict_dot_resolver else ""
    vpn_cfg = vpn_killswitch or {"enabled": False, "interface": "", "endpoints": [], "allow_lan": False}
    if vpn_cfg.get("enabled"):
        iface = str(vpn_cfg.get("interface", ""))
        if not safe_iface(iface) or iface == "lo":
            stop(f"Invalid VPN tunnel interface: {iface}")
        endpoints = vpn_cfg.get("endpoints", [])
        if not isinstance(endpoints, list) or len(endpoints) > 16:
            stop("VPN endpoints must be a list of at most 16 entries")
        vpn_cfg = {
            "enabled": True,
            "interface": iface,
            "endpoints": sorted(endpoints, key=lambda x: (x["family"], x["ip"], x["proto"], x["port"])),
            "allow_lan": bool(vpn_cfg.get("allow_lan", False)),
        }
    else:
        vpn_cfg = {"enabled": False, "interface": "", "endpoints": [], "allow_lan": False}

    return {
        "schema": 2,
        "version": VERSION,
        "network_dependency": NETWORK_VERSION,
        # Interface names are candidates only. Trust is activated at runtime only when one
        # of the reviewed NetworkManager UUIDs is actually active on that interface.
        "trusted_interfaces": sorted(set(trusted_interfaces)),
        "trusted_connection_uuids": trusted_uuids,
        "quarantine": bool(quarantine),
        "nflog_group": NFLOG_GROUP,
        "nflog_rate": f"{NFLOG_RATE}/second",
        "nflog_burst": NFLOG_BURST,
        "allowed_foreign_tables": normalize_foreign_tables(allowed_foreign_tables),
        "vpn_killswitch": vpn_cfg,
        "egress": {
            "block_llmnr_everywhere": True,
            "block_natpmp_pcp_everywhere": True,
            "block_direct_dns": bool(block_direct_dns or strict_dot_resolver),
            "strict_dot_resolver": bool(strict_dot_resolver),
            "dot_resolver_uid": dot_uid,
            "dot_servers": normalized_dot,
            "dot_server_name": normalized_dot_name,
            "trusted_discovery_udp": sorted(trusted_discovery),
            "trusted_discovery_multicast": {
                "mdns": {"udp": 5353, "ipv4": "224.0.0.251", "ipv6": "ff02::fb"},
                "ws_discovery": {"udp": 3702, "ipv4": "239.255.255.250", "ipv6": "ff02::c"},
                "ssdp": {
                    "udp": 1900,
                    "ipv4": "239.255.255.250",
                    "ipv6": "ff02::c",
                    "enabled": bool(allow_lan_ssdp),
                },
            },
            "block_discovery_outside_trusted": [1900, 3702, 5353],
            "allow_lan_smb": bool(allow_lan_smb),
            "trusted_smb_destinations": EXPECTED_SMB_DESTINATIONS,
            "block_smb_netbios_outside_trusted": {"tcp": [135, 139, 445], "udp": [135, 137, 138]},
        },
    }


def nft_quote(value: str) -> str:
    if not safe_iface(value):
        stop(f"Unsafe interface name: {value}")
    return json.dumps(value, ensure_ascii=True)


def _nft_port_set(values: Iterable[int]) -> str:
    ports = sorted({int(value) for value in values})
    if not ports or any(value < 1 or value > 65535 for value in ports):
        stop("Invalid nftables port set")
    return "{ " + ", ".join(str(value) for value in ports) + " }"


def _nflog(tag: str) -> str:
    return f'log prefix "{tag} " group {NFLOG_GROUP} snaplen {NFLOG_SNAPLEN}'


def _logged_verdict(match: str, tag: str, verdict: str, *, indent: str = "        ") -> str:
    """Rate-limit telemetry only; enforcement remains unconditional in a second rule."""
    prefix = (match.strip() + " ") if match.strip() else ""
    return (
        f"{indent}{prefix}limit rate {NFLOG_RATE}/second burst {NFLOG_BURST} packets {_nflog(tag)}\n"
        f'{indent}{prefix}counter {verdict} comment "{tag}"\n'
    )


def render_nft(policy: dict[str, Any]) -> bytes:
    quarantine = bool(policy["quarantine"])
    egress = policy["egress"]
    vpn = policy.get("vpn_killswitch", {"enabled": False})
    all_discovery = _nft_port_set(egress["block_discovery_outside_trusted"])
    smb_tcp = _nft_port_set(egress["block_smb_netbios_outside_trusted"]["tcp"])
    smb_udp = _nft_port_set(egress["block_smb_netbios_outside_trusted"]["udp"])
    discovery = egress["trusted_discovery_multicast"]

    trusted_discovery = (
        f'        oifname @trusted_ifaces ip daddr {discovery["mdns"]["ipv4"]} udp dport 5353 return comment "aegis:allow-lan-mdns-v4"\n'
        f'        oifname @trusted_ifaces ip6 daddr {discovery["mdns"]["ipv6"]} udp dport 5353 return comment "aegis:allow-lan-mdns-v6"\n'
        f'        oifname @trusted_ifaces ip daddr {discovery["ws_discovery"]["ipv4"]} udp dport 3702 return comment "aegis:allow-lan-wsd-v4"\n'
        f'        oifname @trusted_ifaces ip6 daddr {discovery["ws_discovery"]["ipv6"]} udp dport 3702 return comment "aegis:allow-lan-wsd-v6"\n'
    )
    if discovery["ssdp"]["enabled"]:
        trusted_discovery += (
            f'        oifname @trusted_ifaces ip daddr {discovery["ssdp"]["ipv4"]} udp dport 1900 return comment "aegis:allow-lan-ssdp-v4"\n'
            f'        oifname @trusted_ifaces ip6 daddr {discovery["ssdp"]["ipv6"]} udp dport 1900 return comment "aegis:allow-lan-ssdp-v6"\n'
        )

    trusted_smb = ""
    if egress["allow_lan_smb"]:
        ipv4_destinations = "{ " + ", ".join(egress["trusted_smb_destinations"]["ipv4"]) + " }"
        ipv6_destinations = "{ " + ", ".join(egress["trusted_smb_destinations"]["ipv6"]) + " }"
        trusted_smb = (
            f'\n        oifname @trusted_ifaces ip daddr {ipv4_destinations} tcp dport {smb_tcp} return comment "aegis:allow-lan-smb-ipv4"\n'
            f'        oifname @trusted_ifaces ip daddr {ipv4_destinations} udp dport {smb_udp} return comment "aegis:allow-lan-netbios-ipv4"\n'
            f'        oifname @trusted_ifaces ip6 daddr {ipv6_destinations} tcp dport {smb_tcp} return comment "aegis:allow-lan-smb-ipv6"\n'
        )

    dns_rules = ""
    if egress.get("strict_dot_resolver", False):
        uid = int(egress["dot_resolver_uid"])
        dot_v4 = [x for x in egress.get("dot_servers", []) if ipaddress.ip_address(x).version == 4]
        dot_v6 = [x for x in egress.get("dot_servers", []) if ipaddress.ip_address(x).version == 6]
        lines: list[str] = [""]
        if dot_v4:
            lines.append(
                f'        meta skuid {uid} ip daddr {{ {", ".join(dot_v4)} }} tcp dport 853 return comment "aegis:allow-dot-resolver-v4"'
            )
        if dot_v6:
            lines.append(
                f'        meta skuid {uid} ip6 daddr {{ {", ".join(dot_v6)} }} tcp dport 853 return comment "aegis:allow-dot-resolver-v6"'
            )
        lines.append(_logged_verdict('udp dport { 53, 853 }', 'aegis:block-dns-udp', 'reject').rstrip())
        lines.append(_logged_verdict('tcp dport { 53, 853 }', 'aegis:block-dns-tcp', 'reject with tcp reset').rstrip())
        dns_rules = "\n".join(lines) + "\n"
    elif egress.get("block_direct_dns", False):
        dns_rules = "\n" + _logged_verdict("udp dport 53", "aegis:block-direct-dns-udp", "reject")
        dns_rules += _logged_verdict("tcp dport 53", "aegis:block-direct-dns-tcp", "reject with tcp reset")

    vpn_chain = ""
    output_suffix = ""
    if vpn.get("enabled"):
        vpn_iface = nft_quote(vpn["interface"])
        vpn_lines = [
            '        oifname "lo" return comment "aegis:vpn-allow-loopback"',
            f'        oifname {vpn_iface} return comment "aegis:vpn-allow-tunnel"',
            '        udp sport 68 udp dport 67 return comment "aegis:vpn-allow-dhcpv4"',
            '        udp sport 546 udp dport 547 return comment "aegis:vpn-allow-dhcpv6"',
            '        meta l4proto ipv6-icmp icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } return comment "aegis:vpn-allow-ndp"',
        ]
        if vpn.get("allow_lan"):
            ipv4_lan = "{ " + ", ".join(EXPECTED_SMB_DESTINATIONS["ipv4"]) + " }"
            ipv6_lan = "{ " + ", ".join(EXPECTED_SMB_DESTINATIONS["ipv6"]) + " }"
            vpn_lines.append(f'        oifname @trusted_ifaces ip daddr {ipv4_lan} return comment "aegis:vpn-allow-lan-v4"')
            vpn_lines.append(f'        oifname @trusted_ifaces ip6 daddr {ipv6_lan} return comment "aegis:vpn-allow-lan-v6"')
        for idx, ep in enumerate(vpn.get("endpoints", [])):
            fam_kw = "ip" if ep["family"] == 4 else "ip6"
            vpn_lines.append(
                f'        {fam_kw} daddr {ep["ip"]} {ep["proto"]} dport {ep["port"]} return comment "aegis:vpn-allow-endpoint-{idx}"'
            )
        vpn_lines.append(_logged_verdict("", "aegis:vpn-killswitch-drop", "reject with icmpx type admin-prohibited").rstrip())
        vpn_body = "\n".join(vpn_lines)
        vpn_chain = f"""
    chain vpn_killswitch {{
{vpn_body}
    }}
"""
        output_suffix = "        jump vpn_killswitch\n"

    containment = ""
    output_prefix = ""
    if quarantine:
        quarantine_in = _logged_verdict("", "aegis:quarantine-in", "drop").rstrip()
        quarantine_out = _logged_verdict("", "aegis:quarantine-out", "reject with icmpx type admin-prohibited").rstrip()
        quarantine_fwd = _logged_verdict("", "aegis:quarantine-forward", "drop").rstrip()
        containment = f"""
    chain quarantine_in {{
        iifname "lo" return
{quarantine_in}
    }}

    chain quarantine_out {{
        oifname "lo" return
{quarantine_out}
    }}

    chain quarantine_forward {{
{quarantine_fwd}
    }}

    chain input_guard {{
        type filter hook input priority filter - 10; policy accept;
        comment "AEGIS emergency input containment"
        jump quarantine_in
    }}

    chain forward_guard {{
        type filter hook forward priority filter - 10; policy accept;
        comment "AEGIS emergency forwarding containment"
        jump quarantine_forward
    }}
"""
        output_prefix = "        jump quarantine_out\n"

    llmnr_tcp = _logged_verdict("tcp dport 5355", "aegis:block-llmnr-tcp", "reject with tcp reset").rstrip()
    llmnr_udp = _logged_verdict("udp dport 5355", "aegis:block-llmnr-udp", "reject").rstrip()
    natpmp = _logged_verdict("udp dport 5351", "aegis:block-natpmp-pcp", "drop").rstrip()
    public_discovery = _logged_verdict(f"udp dport {all_discovery}", "aegis:block-public-discovery", "drop").rstrip()
    public_smb = _logged_verdict(f"tcp dport {smb_tcp}", "aegis:block-public-smb", "reject with tcp reset").rstrip()
    public_netbios = _logged_verdict(f"udp dport {smb_udp}", "aegis:block-public-netbios", "reject").rstrip()

    text = f"""#!/usr/sbin/nft -f
# Managed by AEGIS Firewall Sentinel {VERSION}. Do not edit manually.
destroy table inet {TABLE_NAME}

table inet {TABLE_NAME} {{
    set trusted_ifaces {{
        type ifname
        comment "AEGIS runtime-trusted interfaces; populated only for reviewed active connection UUIDs"
    }}

    chain egress_guard {{
        oifname "lo" return comment "aegis:allow-loopback"
{llmnr_tcp}
{llmnr_udp}
{natpmp}

{trusted_discovery}{public_discovery}
{trusted_smb}
{public_smb}
{public_netbios}\n{dns_rules}    }}
{vpn_chain}{containment}    chain output_guard {{
        type filter hook output priority filter - 10; policy accept;
        comment "AEGIS egress containment before the firewalld filter chain"
{output_prefix}        jump egress_guard
{output_suffix}    }}
}}
"""
    return text.encode("utf-8")


def networkmanager_dropin_text() -> bytes:
    return f"""# Managed by AEGIS Firewall Sentinel {VERSION}.
[Unit]
Wants=aegis-firewall-sentinel.service
After=aegis-firewall-sentinel.service

[Service]
ExecStartPre=+/usr/bin/python3 -I {INSTALL_PATH} network-gate
""".encode()


def networkmanager_dispatcher_text() -> bytes:
    return f"""#!/usr/bin/bash
# Managed by AEGIS Firewall Sentinel {VERSION}.
set -eu
exec /usr/bin/python3 -I {INSTALL_PATH} trust-sync --dispatcher "${{1-}}" "${{2-}}"
""".encode()


def unit_texts() -> dict[pathlib.Path, bytes]:
    script = str(INSTALL_PATH)
    enforce = f"""# Managed by AEGIS Firewall Sentinel {VERSION}.
[Unit]
Description=AEGIS Firewall Sentinel egress and quarantine policy
Documentation=https://github.com/Ozhana/Fedora_Hardening_for_Surface
Wants=firewalld.service network-pre.target
After=firewalld.service local-fs.target
Before=network-pre.target NetworkManager.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 -I {script} runtime-load
ExecReload=/usr/bin/python3 -I {script} runtime-load
TimeoutStartSec=45s
MemoryMax=256M
TasksMax=64
LimitNOFILE=1024
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectProc=invisible
PrivateTmp=yes
PrivateDevices=yes
RuntimeDirectory=aegis/firewall-sentinel
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
SocketBindDeny=any
RestrictNamespaces=yes
RestrictRealtime=yes
RemoveIPC=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
"""
    monitor = f"""# Managed by AEGIS Firewall Sentinel {VERSION}.
[Unit]
Description=AEGIS Firewall Sentinel drift monitor
After=firewalld.service NetworkManager.service aegis-firewall-sentinel.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I {script} monitor-now --systemd
TimeoutStartSec=90s
MemoryMax=384M
TasksMax=96
LimitNOFILE=1024
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
SocketBindDeny=any
StateDirectory=aegis/firewall-sentinel
StateDirectoryMode=0700
RuntimeDirectory=aegis/firewall-sentinel
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RemoveIPC=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
"""
    timer = f"""# Managed by AEGIS Firewall Sentinel {VERSION}.
[Unit]
Description=Periodic AEGIS Firewall Sentinel drift check

[Timer]
OnBootSec=7min
OnUnitActiveSec=15min
AccuracySec=5min
RandomizedDelaySec=2min
Persistent=false
Unit=aegis-firewall-sentinel-monitor.service

[Install]
WantedBy=timers.target
"""
    path = f"""# Managed by AEGIS Firewall Sentinel {VERSION}.
[Unit]
Description=Event-driven AEGIS firewall configuration drift check

[Path]
PathChanged=/etc/firewalld/firewalld.conf
PathChanged=/etc/firewalld/zones/aegis-public.xml
PathChanged=/etc/firewalld/zones/aegis-lan.xml
PathChanged=/etc/NetworkManager/conf.d/90-aegis-network-hardening.conf
PathChanged=/etc/sysctl.d/91-aegis-network-hardening.conf
PathChanged={INSTALL_PATH}
PathChanged={POLICY_FILE}
PathChanged={NFT_FILE}
PathChanged={ENFORCE_UNIT}
PathChanged={MONITOR_UNIT}
PathChanged={TIMER_UNIT}
PathChanged={PATH_UNIT}
PathChanged={NM_DROPIN}
PathChanged=/var/lib/aegis/network-hardening/managed/profile.uuid
PathChanged=/var/lib/aegis/network-hardening/managed/profile.device
Unit=aegis-firewall-sentinel-monitor.service
TriggerLimitIntervalSec=30s
TriggerLimitBurst=3

[Install]
WantedBy=multi-user.target
"""
    return {
        ENFORCE_UNIT: enforce.encode(),
        MONITOR_UNIT: monitor.encode(),
        TIMER_UNIT: timer.encode(),
        PATH_UNIT: path.encode(),
    }


def _nft_stdin_transaction(data: bytes, *, load: bool) -> None:
    """Validate and optionally load nft payload strictly via stdin (zero disk/tmpfs writes)."""
    if not data or len(data) > MAX_FILE or b"\x00" in data:
        stop("Invalid nftables policy payload")
    run(["/usr/sbin/nft", "--check", "--file", "-"], timeout=30, check=True, stdin=data)
    if load:
        run(["/usr/sbin/nft", "--file", "-"], timeout=30, check=True, stdin=data)


def compile_nft(data: bytes) -> None:
    _nft_stdin_transaction(data, load=False)


def normalize_nft_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: normalize_nft_json(val)
            for key, val in sorted(value.items())
            if key not in {"handle", "packets", "bytes"}
        }
    if isinstance(value, list):
        normalized = [normalize_nft_json(x) for x in value]
        if normalized and isinstance(normalized[0], dict) and "metainfo" in normalized[0]:
            normalized = normalized[1:]
        return normalized
    return value


def nft_table_json(table_name: str = TABLE_NAME) -> dict[str, Any] | None:
    result = run(["/usr/sbin/nft", "--json", "--stateless", "--numeric", "list", "table", TABLE_FAMILY, table_name])
    if result.code != 0:
        return None
    try:
        raw = json.loads(result.output)
    except json.JSONDecodeError:
        stop("nft returned malformed JSON")
    return normalize_nft_json(raw)


def _nft_seal_view(value: Any) -> Any:
    """Remove only runtime-managed trusted_ifaces elements from the structural seal."""
    if isinstance(value, list):
        out: list[Any] = []
        for item in value:
            if isinstance(item, dict):
                elem = item.get("element")
                if isinstance(elem, dict) and elem.get("name") == "trusted_ifaces":
                    continue
            out.append(_nft_seal_view(item))
        return out
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, val in value.items():
            if key == "set" and isinstance(val, dict) and val.get("name") == "trusted_ifaces":
                val = {k: v for k, v in val.items() if k not in {"elem", "elements"}}
            result[key] = _nft_seal_view(val)
        return result
    return value


def nft_table_hash() -> str | None:
    table = nft_table_json(TABLE_NAME)
    return sha256_bytes(canonical_json(_nft_seal_view(table))) if table is not None else None


def _active_trusted_interfaces(policy: dict[str, Any]) -> set[str]:
    trusted_uuids = set(policy.get("trusted_connection_uuids", []))
    candidates = set(policy.get("trusted_interfaces", []))
    if not trusted_uuids or not candidates:
        return set()
    # Never invoke nmcli while NetworkManager is inactive/activating: doing so on the
    # NetworkManager ExecStartPre path could cause D-Bus activation/reentrancy.
    if run(["/usr/bin/systemctl", "is-active", "--quiet", "NetworkManager.service"], timeout=10).code != 0:
        return set()
    result = run(["/usr/bin/nmcli", "-t", "-f", "UUID,DEVICE", "connection", "show", "--active"], timeout=15)
    if result.code != 0:
        return set()
    active: set[str] = set()
    for line in result.output.splitlines():
        if ":" not in line:
            continue
        uuid, device = line.split(":", 1)
        uuid = uuid.strip().lower()
        device = device.replace("\\:", ":").strip()
        if uuid in trusted_uuids and device in candidates and safe_iface(device):
            active.add(device)
    return active


def sync_trusted_interfaces(*, force_clear: bool = False) -> None:
    if nft_table_json(TABLE_NAME) is None:
        return
    desired: set[str] = set()
    if not force_clear:
        policy = read_policy(allow_version_upgrade=True)
        desired = _active_trusted_interfaces(policy)
    lines = [f"flush set inet {TABLE_NAME} trusted_ifaces"]
    if desired:
        elements = ", ".join(nft_quote(x) for x in sorted(desired))
        lines.append(f"add element inet {TABLE_NAME} trusted_ifaces {{ {elements} }}")
    _nft_stdin_transaction(("\n".join(lines) + "\n").encode("utf-8"), load=True)


def trust_sync_dispatcher(interface: str, action: str) -> None:
    """Fail-closed NM dispatcher sync; stale queued events recompute live NM state."""
    if not safe_iface(interface) and interface not in {"", "none"}:
        return
    if action in {"pre-up", "pre-down", "down", "vpn-pre-up", "vpn-pre-down"}:
        # Clear first without trusting policy.json. This guarantees that a corrupt policy
        # cannot leave LAN exceptions attached to a device during a connection transition.
        sync_trusted_interfaces(force_clear=True)
        return
    sync_trusted_interfaces(force_clear=False)


def _set_elements(raw: dict[str, Any], set_name: str) -> set[str]:
    values: set[str] = set()
    for entry in raw.get("nftables", []):
        if not isinstance(entry, dict):
            continue
        for obj_key in ("set", "element"):
            obj = entry.get(obj_key)
            if isinstance(obj, dict) and obj.get("name") == set_name:
                elem = obj.get("elem", [])
                if not isinstance(elem, list):
                    elem = [elem]
                for item in elem:
                    if isinstance(item, str):
                        values.add(item)
                    elif isinstance(item, dict) and isinstance(item.get("elem"), dict):
                        val = item["elem"].get("val")
                        if isinstance(val, str):
                            values.add(val)
    return values


def _nft_priority(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]+", value):
        return int(value)
    return None


def table_semantic_findings(policy: dict[str, Any], raw: dict[str, Any] | None) -> list[str]:
    if raw is None:
        return ["AEGIS Sentinel nftables table is absent"]
    findings: list[str] = []
    chains: dict[str, dict[str, Any]] = {}
    rules_by_chain: dict[str, int] = {}
    comments: list[str] = []
    sets: dict[str, dict[str, Any]] = {}
    table_seen = 0
    for entry in raw.get("nftables", []):
        if not isinstance(entry, dict):
            findings.append("Unexpected nftables JSON entry")
            continue
        if "table" in entry:
            obj = entry["table"]
            if obj.get("family") == TABLE_FAMILY and obj.get("name") == TABLE_NAME:
                table_seen += 1
        elif "chain" in entry:
            obj = entry["chain"]
            chains[str(obj.get("name"))] = obj
        elif "rule" in entry:
            obj = entry["rule"]
            chain = str(obj.get("chain"))
            rules_by_chain[chain] = rules_by_chain.get(chain, 0) + 1
            comment = obj.get("comment")
            if isinstance(comment, str):
                comments.append(comment)
        elif "set" in entry:
            obj = entry["set"]
            sets[str(obj.get("name"))] = obj
        elif "element" in entry:
            pass
        else:
            findings.append("Unexpected object exists in the AEGIS Sentinel nftables table")
    if table_seen != 1:
        findings.append("AEGIS Sentinel nftables table identity/count mismatch")

    quarantine = bool(policy["quarantine"])
    egress = policy["egress"]
    vpn = policy.get("vpn_killswitch", {"enabled": False})
    expected_chains = {"egress_guard", "output_guard"}
    # loopback + four trusted discovery returns + six unconditional block verdicts,
    # with a separate rate-limited NFLOG rule before each block verdict.
    egress_count = 17
    expected_comments = {
        "aegis:allow-loopback",
        "aegis:block-llmnr-tcp",
        "aegis:block-llmnr-udp",
        "aegis:block-natpmp-pcp",
        "aegis:allow-lan-mdns-v4",
        "aegis:allow-lan-mdns-v6",
        "aegis:allow-lan-wsd-v4",
        "aegis:allow-lan-wsd-v6",
        "aegis:block-public-discovery",
        "aegis:block-public-smb",
        "aegis:block-public-netbios",
    }
    if egress["trusted_discovery_multicast"]["ssdp"]["enabled"]:
        egress_count += 2
        expected_comments |= {"aegis:allow-lan-ssdp-v4", "aegis:allow-lan-ssdp-v6"}
    if egress["allow_lan_smb"]:
        egress_count += 3
        expected_comments |= {
            "aegis:allow-lan-smb-ipv4",
            "aegis:allow-lan-netbios-ipv4",
            "aegis:allow-lan-smb-ipv6",
        }
    if egress.get("strict_dot_resolver", False):
        dot_v4 = [x for x in egress.get("dot_servers", []) if ipaddress.ip_address(x).version == 4]
        dot_v6 = [x for x in egress.get("dot_servers", []) if ipaddress.ip_address(x).version == 6]
        if dot_v4:
            egress_count += 1
            expected_comments.add("aegis:allow-dot-resolver-v4")
        if dot_v6:
            egress_count += 1
            expected_comments.add("aegis:allow-dot-resolver-v6")
        egress_count += 4
        expected_comments |= {"aegis:block-dns-udp", "aegis:block-dns-tcp"}
    elif egress.get("block_direct_dns", False):
        egress_count += 4
        expected_comments |= {"aegis:block-direct-dns-udp", "aegis:block-direct-dns-tcp"}

    output_count = 1
    expected_counts: dict[str, int] = {"egress_guard": egress_count}
    if vpn.get("enabled"):
        expected_chains.add("vpn_killswitch")
        output_count += 1
        vpn_count = 7
        expected_comments |= {
            "aegis:vpn-allow-loopback",
            "aegis:vpn-allow-tunnel",
            "aegis:vpn-allow-dhcpv4",
            "aegis:vpn-allow-dhcpv6",
            "aegis:vpn-allow-ndp",
            "aegis:vpn-killswitch-drop",
        }
        if vpn.get("allow_lan"):
            vpn_count += 2
            expected_comments |= {"aegis:vpn-allow-lan-v4", "aegis:vpn-allow-lan-v6"}
        for idx in range(len(vpn.get("endpoints", []))):
            vpn_count += 1
            expected_comments.add(f"aegis:vpn-allow-endpoint-{idx}")
        expected_counts["vpn_killswitch"] = vpn_count

    if quarantine:
        expected_chains |= {"quarantine_in", "quarantine_out", "quarantine_forward", "input_guard", "forward_guard"}
        output_count += 1
        expected_counts.update({
            "quarantine_in": 3,
            "quarantine_out": 3,
            "quarantine_forward": 2,
            "input_guard": 1,
            "forward_guard": 1,
        })
        expected_comments |= {"aegis:quarantine-in", "aegis:quarantine-out", "aegis:quarantine-forward"}

    expected_counts["output_guard"] = output_count
    if set(chains) != expected_chains:
        findings.append(f"Unexpected chain set: {sorted(chains)}")
    if rules_by_chain != expected_counts:
        findings.append(f"Unexpected rule counts: {rules_by_chain} != {expected_counts}")
    if set(comments) != expected_comments or len(comments) != len(expected_comments):
        findings.append(f"Unexpected/missing rule comments: {sorted(comments)}")
    output = chains.get("output_guard", {})
    if (
        output.get("type") != "filter"
        or output.get("hook") != "output"
        or _nft_priority(output.get("prio")) != -10
        or output.get("policy") != "accept"
    ):
        findings.append("output_guard hook/type/priority/policy mismatch")
    if quarantine:
        for name, hook in (("input_guard", "input"), ("forward_guard", "forward")):
            obj = chains.get(name, {})
            if (
                obj.get("type") != "filter"
                or obj.get("hook") != hook
                or _nft_priority(obj.get("prio")) != -10
                or obj.get("policy") != "accept"
            ):
                findings.append(f"{name} hook/type/priority/policy mismatch")
    trusted = sets.get("trusted_ifaces")
    if not trusted or trusted.get("type") != "ifname":
        findings.append("trusted_ifaces set is absent or has the wrong type")
    expected_runtime_trust = _active_trusted_interfaces(policy)
    if _set_elements(raw, "trusted_ifaces") != expected_runtime_trust:
        findings.append(
            f"trusted_ifaces runtime elements do not match active reviewed connection UUIDs: "
            f"actual={sorted(_set_elements(raw, 'trusted_ifaces'))} expected={sorted(expected_runtime_trust)}"
        )
    return findings


def stable_semantic_table_hash(policy: dict[str, Any]) -> tuple[str | None, list[str]]:
    first = nft_table_json()
    findings = table_semantic_findings(policy, first)
    if findings:
        return None, findings
    first_hash = sha256_bytes(canonical_json(_nft_seal_view(first)))
    second = nft_table_json()
    second_findings = table_semantic_findings(policy, second)
    if second_findings:
        return None, second_findings
    second_hash = sha256_bytes(canonical_json(_nft_seal_view(second)))
    if first_hash != second_hash:
        return None, ["AEGIS Sentinel nftables structural table changed during verification"]
    return first_hash, []


def terminate_non_loopback_sockets() -> list[str]:
    """Best-effort cleanup only; nft panic/containment is the security boundary."""
    notes: list[str] = []
    if shutil.which("ss", path=CHILD_ENV["PATH"]) is None:
        return ["ss is unavailable; firewall isolation is active but socket cleanup was skipped"]
    queries = (
        ("-t", "-4", "state", "connected", "dst != 127.0.0.0/8"),
        ("-t", "-6", "state", "connected", "dst != ::1"),
        ("-u", "-4", "state", "established", "dst != 127.0.0.0/8"),
        ("-u", "-6", "state", "established", "dst != ::1"),
    )
    for query in queries:
        res = run(["/usr/sbin/ss", "-K", *query], timeout=15)
        if res.code != 0:
            notes.append(f"ss -K {' '.join(query[:2])} returned {res.code}: {res.output.strip()}")
    return notes


def terminate_sockets_for_cidr(cidr: str, family: int) -> None:
    if shutil.which("ss", path=CHILD_ENV["PATH"]) is None:
        return
    fam_flag = "-4" if family == 4 else "-6"
    for proto_flag, state in (("-t", "connected"), ("-u", "established")):
        run(["/usr/sbin/ss", "-K", proto_flag, fam_flag, "state", state, "dst", cidr], timeout=10)
        run(["/usr/sbin/ss", "-K", proto_flag, fam_flag, "state", state, "src", cidr], timeout=10)


def _live_applying_plan() -> dict[str, Any] | None:
    if not TRANSACTIONS.exists():
        return None
    matches: list[dict[str, Any]] = []
    for directory in sorted(TRANSACTIONS.glob("T-*")):
        if not directory.is_dir() or directory.is_symlink() or not TX_RE.fullmatch(directory.name):
            continue
        status_raw = read_managed_text(directory / "status", max_size=64, encoding="ascii")
        if status_raw is None or status_raw.strip() != "APPLYING":
            continue
        if not _is_live_applying_transaction(directory):
            continue
        plan = read_managed_json(directory / "plan.json")
        if not isinstance(plan, dict):
            stop("Live APPLYING transaction has a corrupt plan")
        matches.append(plan)
    if len(matches) > 1:
        stop("Multiple live APPLYING Sentinel transactions detected")
    return matches[0] if matches else None


def _runtime_manifest() -> dict[str, Any]:
    manifest = read_managed_json(COMMITTED_MANIFEST)
    if not isinstance(manifest, dict) or manifest.get("schema") not in {1, 2} or not isinstance(manifest.get("files"), dict):
        stop("Committed Sentinel manifest is missing or invalid")
    return manifest


def _verify_runtime_source_authority(nft_state: dict[str, Any], policy_state: dict[str, Any]) -> None:
    plan = _live_applying_plan()
    if plan is not None:
        desired = plan.get("desired_files")
        if not isinstance(desired, dict):
            stop("Live APPLYING transaction has invalid desired-file metadata")
        if desired.get(str(NFT_FILE)) != nft_state.get("sha256") or desired.get(str(POLICY_FILE)) != policy_state.get("sha256"):
            stop("Runtime source differs from the live APPLYING plan")
        return
    manifest = _runtime_manifest()
    files = manifest["files"]
    for path, state in ((NFT_FILE, nft_state), (POLICY_FILE, policy_state)):
        if files.get(str(path)) != state.get("sha256"):
            stop(f"Runtime source differs from the last committed manifest: {path}")
    committed_runtime = manifest.get("runtime_sha256")
    if isinstance(committed_runtime, str) and HEX64_RE.fullmatch(committed_runtime):
        actual_runtime = installed_runtime_sha256()
        if actual_runtime != committed_runtime:
            print("<4>WARNING: runtime executable changed after commit; exact committed nft bytes will still be loaded", file=sys.stderr)


def load_runtime_policy() -> None:
    nft_state = inspect_optional_file(NFT_FILE)
    policy_state = inspect_optional_file(POLICY_FILE)
    if not nft_state["exists"] or not policy_state["exists"]:
        stop("Committed Sentinel policy source is incomplete")
    _verify_runtime_source_authority(nft_state, policy_state)
    _nft_stdin_transaction(nft_state["data"], load=True)
    # At early boot NetworkManager is not active, so trust remains empty (fail-closed).
    # On manual reload with NM already active, immediately restore UUID-derived trust.
    if run(["/usr/bin/systemctl", "is-active", "--quiet", "NetworkManager.service"]).code == 0:
        sync_trusted_interfaces(force_clear=False)


def unload_runtime_policy() -> None:
    if nft_table_json() is None:
        return
    run(["/usr/sbin/nft", "destroy", "table", TABLE_FAMILY, TABLE_NAME], timeout=20, check=True)


def read_policy(*, allow_version_upgrade: bool = False) -> dict[str, Any]:
    policy = read_managed_json(POLICY_FILE)
    if policy is None:
        stop("Firewall Sentinel policy is not installed")
    if not isinstance(policy, dict) or policy.get("schema") not in {1, 2}:
        stop("Firewall Sentinel policy schema is invalid")
    if not isinstance(policy.get("version"), str) or not policy["version"]:
        stop("Firewall Sentinel policy version is invalid")
    if not allow_version_upgrade and policy.get("version") != VERSION:
        stop(f"Firewall Sentinel policy version mismatch: found {policy.get('version')}, expected {VERSION}")
    if not isinstance(policy.get("trusted_interfaces"), list):
        stop("Firewall Sentinel trusted interface list is invalid")
    if any(not isinstance(x, str) or not safe_iface(x) for x in policy["trusted_interfaces"]):
        stop("Firewall Sentinel trusted interface value is unsafe")
    trusted_uuids = policy.get("trusted_connection_uuids")
    if policy.get("schema") == 2:
        if not isinstance(trusted_uuids, list) or not trusted_uuids:
            stop("Firewall Sentinel trusted connection UUID list is missing")
        for uuid in trusted_uuids:
            if not isinstance(uuid, str) or not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", uuid
            ):
                stop("Firewall Sentinel trusted connection UUID is invalid")
    else:
        # Upgrade compatibility only. A schema-1 policy may be read to build a schema-2 plan,
        # but it is not accepted as the final current-version policy.
        if not allow_version_upgrade:
            stop("Firewall Sentinel schema-1 policy must be upgraded before verification")
        policy["trusted_connection_uuids"] = []
    egress = policy.get("egress")
    if not isinstance(egress, dict) or egress.get("block_llmnr_everywhere") is not True:
        stop("Firewall Sentinel egress policy is invalid")
    if not allow_version_upgrade and egress.get("block_natpmp_pcp_everywhere") is not True:
        stop("Firewall Sentinel NAT-PMP/PCP policy is invalid")
    if "block_direct_dns" in egress and not isinstance(egress["block_direct_dns"], bool):
        stop("Firewall Sentinel direct DNS policy is invalid")
    if "strict_dot_resolver" in egress and not isinstance(egress["strict_dot_resolver"], bool):
        stop("Firewall Sentinel strict DoT resolver flag is invalid")
    if egress.get("strict_dot_resolver"):
        if not isinstance(egress.get("dot_resolver_uid"), int) or egress["dot_resolver_uid"] <= 0:
            stop("Firewall Sentinel DoT resolver UID is invalid")
        if not isinstance(egress.get("dot_servers"), list) or not egress["dot_servers"]:
            stop("Firewall Sentinel DoT server list is invalid")
        normalize_dot_servers(egress["dot_servers"])
        normalize_dot_server_name(str(egress.get("dot_server_name", "")))
    if egress.get("block_discovery_outside_trusted") != [1900, 3702, 5353]:
        stop("Firewall Sentinel discovery policy is invalid")
    if egress.get("trusted_smb_destinations") != EXPECTED_SMB_DESTINATIONS:
        stop("Firewall Sentinel trusted SMB destination policy is invalid")
    smb_ports = egress.get("block_smb_netbios_outside_trusted")
    valid_smb = (
        {"tcp": [135, 139, 445], "udp": [135, 137, 138]},
        {"tcp": [139, 445], "udp": [137, 138]},
    )
    if (not allow_version_upgrade and smb_ports != valid_smb[0]) or (allow_version_upgrade and smb_ports not in valid_smb):
        stop("Firewall Sentinel SMB/NetBIOS policy is invalid")
    trusted_discovery = egress.get("trusted_discovery_udp")
    if trusted_discovery not in ([3702, 5353], [1900, 3702, 5353]):
        stop("Firewall Sentinel trusted discovery policy is invalid")
    expected_multicast = {
        "mdns": {"udp": 5353, "ipv4": "224.0.0.251", "ipv6": "ff02::fb"},
        "ws_discovery": {"udp": 3702, "ipv4": "239.255.255.250", "ipv6": "ff02::c"},
        "ssdp": {
            "udp": 1900,
            "ipv4": "239.255.255.250",
            "ipv6": "ff02::c",
            "enabled": 1900 in trusted_discovery,
        },
    }
    if egress.get("trusted_discovery_multicast") != expected_multicast:
        stop("Firewall Sentinel multicast discovery policy is invalid")
    if not isinstance(egress.get("allow_lan_smb"), bool):
        stop("Firewall Sentinel LAN SMB policy is invalid")
    if not isinstance(policy.get("quarantine"), bool):
        stop("Firewall Sentinel quarantine policy is invalid")
    if "allowed_foreign_tables" in policy:
        if not isinstance(policy["allowed_foreign_tables"], list):
            stop("Firewall Sentinel allowed_foreign_tables is invalid")
        normalize_foreign_tables(policy["allowed_foreign_tables"])
    if "vpn_killswitch" in policy:
        vpn = policy["vpn_killswitch"]
        if not isinstance(vpn, dict) or not isinstance(vpn.get("enabled"), bool):
            stop("Firewall Sentinel vpn_killswitch policy is invalid")
        if vpn["enabled"] and not safe_iface(str(vpn.get("interface", ""))):
            stop("Firewall Sentinel VPN interface is invalid")
    elif not allow_version_upgrade:
        stop("Firewall Sentinel vpn_killswitch section is missing")
    return policy


def service_state(name: str) -> dict[str, str]:
    enabled = run(["/usr/bin/systemctl", "is-enabled", name]).output.strip() or "unknown"
    active = run(["/usr/bin/systemctl", "is-active", name]).output.strip() or "unknown"
    return {"enabled": enabled, "active": active}


def validate_stable_unit_states(units: dict[str, dict[str, str]]) -> None:
    allowed_enabled = {
        "enabled", "enabled-runtime", "disabled", "not-found",
        "static", "indirect", "generated", "transient", "alias",
    }
    for name, state in units.items():
        enabled = state.get("enabled", "unknown")
        active = state.get("active", "unknown")
        if enabled not in allowed_enabled:
            stop(f"Unstable/unsupported unit enablement state for {name}: {enabled}")
        if active not in {"active", "inactive"}:
            stop(f"Unstable unit activity state for {name}: {active}")


def current_facts(*, strict_upper_bound: bool = True) -> dict[str, Any]:
    versions = require_platform(mutation=False, strict_upper_bound=strict_upper_bound)
    _, device = read_network_identity()
    table_hash = nft_table_hash()
    files: dict[str, str] = {}
    for path in MANAGED_PATHS:
        state = inspect_optional_file(path)
        files[str(path)] = state.get("sha256", "ABSENT") if state["exists"] else "ABSENT"
    units = {name: service_state(name) for name in PERSISTENT_UNIT_NAMES}
    return {
        "versions": versions,
        "network_version": network_version(),
        "network_device": device,
        "files": files,
        "base_files": base_watched_hashes(),
        "units": units,
        "nft_table_sha256": table_hash or "ABSENT",
    }


def validate_managed_destinations() -> None:
    for path in MANAGED_PATHS:
        state = inspect_optional_file(path)
        if not state["exists"]:
            continue
        data = state["data"]
        if path == POLICY_FILE:
            try:
                obj = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                stop(f"Foreign or corrupt policy file uses the reserved path: {path}")
            if not isinstance(obj, dict) or obj.get("schema") not in {1, 2} or not isinstance(obj.get("version"), str):
                stop(f"Foreign policy file uses the reserved path: {path}")
        elif path == NFT_FILE:
            if not data.startswith(b"#!/usr/sbin/nft -f\n# Managed by AEGIS Firewall Sentinel "):
                stop(f"Foreign nftables file uses the reserved path: {path}")
        else:
            if path in {NM_TRUST_DISPATCH, NM_TRUST_PRE_UP, NM_TRUST_PRE_DOWN}:
                if not data.startswith(b"#!/usr/bin/bash\n# Managed by AEGIS Firewall Sentinel "):
                    stop(f"Foreign NetworkManager dispatcher uses the reserved path: {path}")
            elif not data.startswith(b"# Managed by AEGIS Firewall Sentinel "):
                stop(f"Foreign systemd/unit file uses the reserved path: {path}")


def _is_live_applying_transaction(directory: pathlib.Path) -> bool:
    if not is_session_lock_held():
        return False
    boot_id = read_managed_text(directory / "boot-id", max_size=128, encoding="ascii")
    if boot_id is None:
        return False
    try:
        current_boot = BOOT_ID_PATH.read_text(encoding="ascii").strip()
    except OSError:
        return False
    if boot_id.strip() != current_boot:
        return False
    pid_text = read_managed_text(directory / "owner.pid", max_size=32, encoding="ascii")
    expected_start = read_managed_text(directory / "owner.starttime", max_size=64, encoding="ascii")
    if pid_text is None or expected_start is None:
        return False
    pid_s, start_s = pid_text.strip(), expected_start.strip()
    if not pid_s.isdigit() or not start_s.isdigit():
        return False
    pid = int(pid_s)
    if pid <= 1 or process_starttime(pid) != start_s:
        return False
    try:
        cmdline = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")
    except OSError:
        return False
    return str(INSTALL_PATH) in cmdline and any(
        f" {action}" in cmdline for action in ("apply", "quarantine-on", "quarantine-off")
    )


def incomplete_transactions(*, allow_live_applying: bool = False) -> list[str]:
    if not TRANSACTIONS.exists():
        return []
    incomplete: list[str] = []
    live_applying: list[pathlib.Path] = []
    for directory in sorted(TRANSACTIONS.glob("T-*")):
        if not directory.is_dir() or directory.is_symlink() or not TX_RE.fullmatch(directory.name):
            continue
        try:
            status_raw = read_managed_text(directory / "status", max_size=64, encoding="ascii")
            status = status_raw.strip() if status_raw is not None else "UNKNOWN"
        except Stop:
            status = "UNKNOWN"
        if status in {"COMMITTED", "ROLLED_BACK"}:
            continue
        if allow_live_applying and status == "APPLYING" and _is_live_applying_transaction(directory):
            live_applying.append(directory)
            continue
        incomplete.append(f"{directory.name}:{status}")
    if len(live_applying) > 1:
        incomplete.extend(f"{d.name}:APPLYING_MULTIPLE" for d in live_applying)
    return incomplete


def ensure_no_incomplete_transactions(*, allow_live_applying: bool = False) -> None:
    pending = incomplete_transactions(allow_live_applying=allow_live_applying)
    if pending:
        stop("Incomplete Firewall Sentinel transaction requires review/rollback: " + ", ".join(pending))


def revalidate_plan_facts(plan: dict[str, Any], *, strict_upper_bound: bool = True) -> None:
    verify_network_layer()
    validate_managed_destinations()
    current = current_facts(strict_upper_bound=strict_upper_bound)
    if current != plan.get("facts"):
        stop("System state changed after the plan was reviewed; run plan again")


def verify_committed_manifest() -> list[str]:
    findings: list[str] = []
    try:
        manifest = _runtime_manifest()
    except Stop as exc:
        return [str(exc)]
    if manifest.get("version") != VERSION:
        findings.append(f"Committed manifest version mismatch: {manifest.get('version')}")
    files = manifest.get("files")
    if not isinstance(files, dict):
        return ["Committed manifest files map is invalid"]
    for path in MANAGED_PATHS:
        state = inspect_optional_file(path)
        actual = state.get("sha256", "ABSENT") if state["exists"] else "ABSENT"
        if files.get(str(path)) != actual:
            findings.append(f"Committed manifest file digest mismatch: {path}")
    committed_runtime = manifest.get("runtime_sha256")
    if not isinstance(committed_runtime, str) or not HEX64_RE.fullmatch(committed_runtime):
        findings.append("Committed manifest runtime_sha256 is missing or malformed")
    elif committed_runtime != installed_runtime_sha256():
        findings.append("Installed Sentinel runtime executable differs from committed manifest")
    expected_base = manifest.get("base_files")
    if not isinstance(expected_base, dict):
        findings.append("Committed manifest base_files map is missing")
    else:
        actual_base = base_watched_hashes()
        for path_str, expected in expected_base.items():
            if actual_base.get(path_str) != expected:
                findings.append(f"Committed manifest base-file digest mismatch: {path_str}")
    seal_raw = read_managed_text(MANAGED / "nft-table.sha256", max_size=128, encoding="ascii")
    seal = seal_raw.strip() if seal_raw is not None else ""
    if not HEX64_RE.fullmatch(seal):
        findings.append("Managed nft table seal is missing or malformed")
    elif manifest.get("nft_table_sha256") != seal:
        findings.append("Committed manifest nft_table_sha256 differs from managed seal")
    policy = read_policy(allow_version_upgrade=False)
    if policy["egress"].get("strict_dot_resolver") and not policy.get("quarantine", False):
        findings.extend(dot_resolver_attestation(
            policy["egress"]["dot_servers"], policy["egress"]["dot_server_name"]
        ))
    foreign_map = manifest.get("approved_foreign_hook_fingerprints")
    if not isinstance(foreign_map, dict):
        findings.append("Committed manifest approved_foreign_hook_fingerprints is missing")
    return findings


def panic_is_active() -> bool:
    return run(["/usr/sbin/nft", "list", "table", TABLE_FAMILY, PANIC_TABLE_NAME], timeout=10).code == 0


def _manifest_boot_findings() -> list[str]:
    findings: list[str] = []
    try:
        manifest = _runtime_manifest()
    except Stop as exc:
        return [str(exc)]
    files = manifest.get("files")
    if not isinstance(files, dict):
        return ["Committed manifest files map is invalid"]
    for path in (POLICY_FILE, NFT_FILE):
        state = inspect_optional_file(path)
        actual = state.get("sha256", "ABSENT") if state["exists"] else "ABSENT"
        if files.get(str(path)) != actual:
            findings.append(f"Committed boot-source digest mismatch: {path}")
    expected_base = manifest.get("base_files")
    if not isinstance(expected_base, dict):
        findings.append("Committed manifest base_files map is missing")
    else:
        actual_base = base_watched_hashes()
        for path_str, expected in expected_base.items():
            if actual_base.get(path_str) != expected:
                findings.append(f"Committed Network Hardening base drift: {path_str}")
    seal_raw = read_managed_text(MANAGED / "nft-table.sha256", max_size=128, encoding="ascii")
    seal = seal_raw.strip() if seal_raw is not None else ""
    if not HEX64_RE.fullmatch(seal):
        findings.append("Sentinel runtime table seal is missing or malformed")
    if manifest.get("nft_table_sha256") != seal:
        findings.append("Committed manifest table seal differs from managed seal")
    return findings


def _wordset(text: str) -> set[str]:
    return {item for item in text.split() if item}


def _boot_firewalld_findings() -> list[str]:
    findings: list[str] = []
    state = run(["/usr/bin/firewall-cmd", "--state"], timeout=10)
    if state.code != 0 or state.output.strip() != "running":
        return ["firewalld is not running"]
    default = run(["/usr/bin/firewall-cmd", "--get-default-zone"], timeout=10)
    if default.code != 0 or default.output.strip() != "aegis-public":
        findings.append("firewalld default zone is not aegis-public")
    for zone, expected_services in (
        ("aegis-public", {"dhcpv6-client"}),
        ("aegis-lan", {"dhcpv6-client", "ipp-client", "mdns", "ws-discovery-client"}),
    ):
        services = run(["/usr/bin/firewall-cmd", f"--zone={zone}", "--list-services"], timeout=10)
        if services.code != 0 or _wordset(services.output) != expected_services:
            findings.append(f"{zone} runtime services differ from the committed Network Hardening contract")
        ports = run(["/usr/bin/firewall-cmd", f"--zone={zone}", "--list-ports"], timeout=10)
        if ports.code != 0 or ports.output.strip():
            findings.append(f"{zone} has unexpected runtime ports")
    return findings


def network_gate() -> None:
    """Fail-closed NetworkManager ExecStartPre gate with no RPM DB access."""
    require_boot_runtime_platform()
    # A NetworkManager restart must never inherit LAN trust from the previous connection.
    # Clear the runtime set before validating/startup; dispatcher up events repopulate it only
    # after the reviewed UUID is actually active again.
    sync_trusted_interfaces(force_clear=True)
    findings = _manifest_boot_findings()
    findings.extend(_boot_firewalld_findings())
    if not findings:
        seal_raw = read_managed_text(MANAGED / "nft-table.sha256", max_size=128, encoding="ascii")
        seal = seal_raw.strip() if seal_raw is not None else ""
        policy = read_policy(allow_version_upgrade=True)
        if policy.get("version") == VERSION:
            table_hash, semantic = stable_semantic_table_hash(policy)
            findings.extend(semantic)
        else:
            print(
                f"<4>WARNING: network-gate verifying pre-upgrade committed policy ({policy.get('version')}) against its seal",
                file=sys.stderr,
            )
            first_hash = nft_table_hash()
            second_hash = nft_table_hash()
            if first_hash is None or first_hash != second_hash:
                table_hash = None
                findings.append("live Sentinel table is absent or changed during verification")
            else:
                table_hash = first_hash
        if table_hash is None or table_hash != seal:
            findings.append("live Sentinel table does not match the committed runtime seal")
    if findings:
        stop("Network gate refused startup: " + "; ".join(findings))


def _proc_sysctl(key: str) -> str | None:
    path = pathlib.Path("/proc/sys") / pathlib.Path(*key.split("."))
    try:
        return path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None


def _zone_readonly_findings(zone: str, expected_services: set[str]) -> list[str]:
    findings: list[str] = []
    # firewall-cmd --get-target is a PERMANENT-only query: it is not a valid
    # runtime target attestation. Parse the live zone's --list-all output instead.
    # Require precisely one explicit target line; missing/ambiguous output
    # fails closed rather than silently interpreting an absent field as default.
    live_zone = run(["/usr/bin/firewall-cmd", f"--zone={zone}", "--list-all"], timeout=15)
    targets = re.findall(r"(?m)^\s*target:\s*(\S+)\s*$", live_zone.output) if live_zone.code == 0 else []
    if targets != ["default"]:
        findings.append(f"{zone} runtime target drift")
    services = run(["/usr/bin/firewall-cmd", f"--zone={zone}", "--list-services"], timeout=15)
    if services.code != 0 or _wordset(services.output) != expected_services:
        findings.append(f"{zone} runtime service drift")
    for arg in (
        "--list-ports", "--list-source-ports", "--list-protocols",
        "--list-forward-ports", "--list-rich-rules", "--list-sources", "--list-icmp-blocks",
    ):
        result = run(["/usr/bin/firewall-cmd", f"--zone={zone}", arg], timeout=15)
        if result.code != 0 or result.output.strip():
            findings.append(f"{zone} unexpected runtime {arg}")
    for arg, label in (
        ("--query-forward", "forward"),
        ("--query-masquerade", "masquerade"),
        ("--query-icmp-block-inversion", "icmp-block-inversion"),
    ):
        result = run(["/usr/bin/firewall-cmd", f"--zone={zone}", arg], timeout=15)
        if result.code == 0:
            findings.append(f"{zone} unexpected runtime {label}=yes")
        elif result.code not in {1}:
            findings.append(f"{zone} cannot query runtime {label}")
    return findings


def _network_sysctl_readonly_findings(device: str) -> list[str]:
    findings: list[str] = []
    expected_v4 = {
        "net.ipv4.conf.default.rp_filter": "2",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.default.accept_redirects": "0",
        "net.ipv4.conf.all.secure_redirects": "0",
        "net.ipv4.conf.default.secure_redirects": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.default.send_redirects": "0",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.default.accept_source_route": "0",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.ipv4.icmp_ignore_bogus_error_responses": "1",
        "net.ipv4.tcp_syncookies": "1",
    }
    for key, wanted in expected_v4.items():
        if _proc_sysctl(key) != wanted:
            findings.append(f"live sysctl drift: {key}")
    if safe_iface(device) and pathlib.Path(f"/proc/sys/net/ipv4/conf/{device}/rp_filter").exists():
        if _proc_sysctl(f"net.ipv4.conf.{device}.rp_filter") != "2":
            findings.append(f"live sysctl drift: {device} rp_filter")
    ipv4_root = pathlib.Path("/proc/sys/net/ipv4/conf")
    if ipv4_root.is_dir():
        for entry in ipv4_root.iterdir():
            iface = entry.name
            if iface in {"all", "default", "lo"} or not safe_iface(iface) or not entry.is_dir():
                continue
            for key in ("accept_redirects", "secure_redirects", "send_redirects", "accept_source_route"):
                if _proc_sysctl(f"net.ipv4.conf.{iface}.{key}") != "0":
                    findings.append(f"live sysctl drift: {iface} IPv4 {key}")
    ipv6_root = pathlib.Path("/proc/sys/net/ipv6/conf")
    if ipv6_root.is_dir():
        expected_v6 = {
            "net.ipv6.conf.all.accept_redirects": "0",
            "net.ipv6.conf.default.accept_redirects": "0",
            "net.ipv6.conf.all.accept_source_route": "-1",
            "net.ipv6.conf.default.accept_source_route": "-1",
        }
        for key, wanted in expected_v6.items():
            if _proc_sysctl(key) != wanted:
                findings.append(f"live sysctl drift: {key}")
        for entry in ipv6_root.iterdir():
            iface = entry.name
            if iface in {"all", "default", "lo"} or not safe_iface(iface) or not entry.is_dir():
                continue
            if _proc_sysctl(f"net.ipv6.conf.{iface}.accept_redirects") != "0":
                findings.append(f"live sysctl drift: {iface} IPv6 accept_redirects")
            if _proc_sysctl(f"net.ipv6.conf.{iface}.accept_source_route") != "-1":
                findings.append(f"live sysctl drift: {iface} IPv6 accept_source_route")
    return findings


def build_plan(
    *,
    quarantine: bool | None,
    extra_interfaces: Iterable[str],
    remove_interfaces: Iterable[str] = (),
    lan_smb: bool | None = None,
    lan_ssdp: bool | None = None,
    block_direct_dns: bool | None = None,
    strict_dot_resolver: bool | None = None,
    dot_servers: Iterable[str] | None = None,
    dot_server_name: str | None = None,
    vpn_only: str | None = None,
    vpn_off: bool = False,
    vpn_endpoints: Iterable[str] | None = None,
    vpn_allow_lan: bool | None = None,
    allow_foreign_tables: Iterable[str] = (),
    remove_foreign_tables: Iterable[str] = (),
    strict_upper_bound: bool = True,
    action: str = "apply",
) -> dict[str, Any]:
    require_platform(mutation=True, strict_upper_bound=strict_upper_bound)
    ensure_service_active("firewalld.service")
    ensure_service_active("NetworkManager.service")
    ensure_service_inactive("nftables.service")
    verify_network_layer()
    validate_managed_destinations()
    ensure_no_incomplete_transactions()
    if list(extra_interfaces) or list(remove_interfaces):
        stop(
            "Legacy --trust-interface/--untrust-interface is disabled: LAN trust is now bound to the reviewed NetworkManager UUID"
        )

    current_table = nft_table_hash()
    sealed_raw = read_managed_text(MANAGED / "nft-table.sha256", max_size=128, encoding="ascii")
    sealed_table = sealed_raw.strip() if sealed_raw is not None else ""
    if sealed_table and not HEX64_RE.fullmatch(sealed_table):
        stop("The Sentinel runtime seal is malformed")
    if current_table and (not POLICY_FILE.exists() or not sealed_table):
        stop("A foreign or unsealed inet aegis_sentinel table already exists")
    if current_table and sealed_table and current_table != sealed_table:
        stop("Live Sentinel nftables structural drift exists; inspect verify/monitor/history before any repair")

    uuid, device = read_network_identity()
    old_policy: dict[str, Any] | None = None
    if POLICY_FILE.exists():
        old_policy = read_policy(allow_version_upgrade=True)
    if quarantine is None:
        quarantine = bool(old_policy.get("quarantine", False)) if old_policy else False
    if panic_is_active() and not quarantine:
        stop("RAM-only panic isolation is active; run panic-off before applying a non-quarantine policy")

    old_egress = old_policy.get("egress", {}) if old_policy else {}
    if lan_smb is None:
        lan_smb = bool(old_egress.get("allow_lan_smb", False))
    if lan_ssdp is None:
        lan_ssdp = 1900 in old_egress.get("trusted_discovery_udp", [])
    if strict_dot_resolver is None:
        strict_dot_resolver = bool(old_egress.get("strict_dot_resolver", False))
    if block_direct_dns is None:
        block_direct_dns = bool(old_egress.get("block_direct_dns", False))
    if dot_servers is None:
        resolved_dot_servers = old_egress.get("dot_servers") or list(DEFAULT_DOT_SERVERS)
    else:
        resolved_dot_servers = list(dot_servers)
    if dot_server_name is None:
        resolved_dot_name = str(old_egress.get("dot_server_name") or DOT_SERVER_NAME_DEFAULT)
    else:
        resolved_dot_name = dot_server_name
    if strict_dot_resolver and not quarantine:
        dot_findings = dot_resolver_attestation(resolved_dot_servers, resolved_dot_name)
        if dot_findings:
            stop("Strict DoT preflight failed: " + "; ".join(dot_findings))

    old_vpn = old_policy.get("vpn_killswitch", {"enabled": False, "interface": "", "endpoints": [], "allow_lan": False}) if old_policy else {"enabled": False, "interface": "", "endpoints": [], "allow_lan": False}
    if vpn_off:
        vpn_cfg: dict[str, Any] = {"enabled": False, "interface": "", "endpoints": [], "allow_lan": False}
    elif vpn_only is not None:
        eps = [parse_vpn_endpoint(x) for x in (vpn_endpoints or [])]
        if not eps and old_vpn.get("enabled") and old_vpn.get("interface") == vpn_only and vpn_endpoints is None:
            eps = list(old_vpn.get("endpoints", []))
        vpn_cfg = {
            "enabled": True,
            "interface": vpn_only,
            "endpoints": eps,
            "allow_lan": bool(old_vpn.get("allow_lan", False) if vpn_allow_lan is None else vpn_allow_lan),
        }
    else:
        vpn_cfg = dict(old_vpn)
        if vpn_cfg.get("enabled"):
            if vpn_endpoints is not None:
                vpn_cfg["endpoints"] = [parse_vpn_endpoint(x) for x in vpn_endpoints]
            if vpn_allow_lan is not None:
                vpn_cfg["allow_lan"] = bool(vpn_allow_lan)

    foreign_tables = set(old_policy.get("allowed_foreign_tables", [])) if old_policy else set()
    foreign_tables.update(normalize_foreign_tables(allow_foreign_tables))
    for rem in normalize_foreign_tables(remove_foreign_tables):
        foreign_tables.discard(rem)

    policy = render_policy(
        [device],
        quarantine,
        trusted_connection_uuids=[uuid],
        allow_lan_smb=bool(lan_smb),
        allow_lan_ssdp=bool(lan_ssdp),
        block_direct_dns=bool(block_direct_dns),
        strict_dot_resolver=bool(strict_dot_resolver),
        dot_servers=resolved_dot_servers,
        dot_server_name=resolved_dot_name,
        vpn_killswitch=vpn_cfg,
        allowed_foreign_tables=sorted(foreign_tables),
    )
    # Approval of a foreign table is approval of its current base-hook fingerprint, not a blank cheque.
    foreign_fingerprints = foreign_table_hook_fingerprints(policy, require_present=True)
    nft_data = render_nft(policy)
    compile_nft(nft_data)
    units = unit_texts()
    dispatcher = networkmanager_dispatcher_text()
    desired_files = {
        str(POLICY_FILE): sha256_bytes(pretty_json(policy)),
        str(NFT_FILE): sha256_bytes(nft_data),
        str(NM_DROPIN): sha256_bytes(networkmanager_dropin_text()),
        str(NM_TRUST_DISPATCH): sha256_bytes(dispatcher),
        str(NM_TRUST_PRE_UP): sha256_bytes(dispatcher),
        str(NM_TRUST_PRE_DOWN): sha256_bytes(dispatcher),
        **{str(path): sha256_bytes(data) for path, data in units.items()},
    }
    facts = current_facts(strict_upper_bound=strict_upper_bound)
    validate_stable_unit_states(facts["units"])
    file_changes = [path for path, digest in desired_files.items() if facts["files"].get(path, "ABSENT") != digest]
    unit_changes = [
        name for name in PERSISTENT_UNIT_NAMES
        if facts["units"][name]["enabled"] != "enabled" or facts["units"][name]["active"] != "active"
    ]
    manifest_ok = False
    if not file_changes and COMMITTED_MANIFEST.exists():
        try:
            manifest = _runtime_manifest()
            manifest_ok = (
                manifest.get("version") == VERSION
                and manifest.get("files") == desired_files
                and manifest.get("base_files") == facts["base_files"]
                and manifest.get("nft_table_sha256") == sealed_table
                and manifest.get("runtime_sha256") == installed_runtime_sha256()
                and manifest.get("approved_foreign_hook_fingerprints", {}) == foreign_fingerprints
            )
        except Stop:
            manifest_ok = False
    table_ok = bool(
        POLICY_FILE.exists() and NFT_FILE.exists() and not file_changes and sealed_table
        and sealed_table == facts["nft_table_sha256"]
    )
    runtime_change = "LOAD_EXPECTED_TABLE" if not table_ok else ("REFRESH_MANIFEST" if not manifest_ok else "NONE")
    no_op = not file_changes and not unit_changes and table_ok and manifest_ok
    plan: dict[str, Any] = {
        "schema": 2,
        "version": VERSION,
        "action": action,
        "policy": policy,
        "facts": facts,
        "desired_files": desired_files,
        "approved_foreign_hook_fingerprints": foreign_fingerprints,
        "file_changes": file_changes,
        "unit_changes": unit_changes,
        "runtime_change": runtime_change,
        "no_op": no_op,
        "ownership": {
            "owns": [
                str(POLICY_FILE), str(NFT_FILE), str(NM_DROPIN), str(NM_TRUST_DISPATCH),
                str(NM_TRUST_PRE_UP), str(NM_TRUST_PRE_DOWN),
                f"{TABLE_FAMILY} {TABLE_NAME}", f"{TABLE_FAMILY} {PANIC_TABLE_NAME}",
                f"{TABLE_FAMILY} {BLOCKLIST_TABLE_NAME}", f"{TABLE_FAMILY} {CGROUP_TABLE_NAME}",
                *[str(x) for x in units],
            ],
            "does_not_own": [
                "/etc/firewalld/firewalld.conf",
                "/etc/firewalld/zones/aegis-public.xml",
                "/etc/firewalld/zones/aegis-lan.xml",
                "/etc/NetworkManager/conf.d/90-aegis-network-hardening.conf",
                "/etc/sysctl.d/91-aegis-network-hardening.conf",
            ],
        },
    }
    plan["plan_sha256"] = sha256_bytes(canonical_json(plan))
    return plan


def print_plan(plan: dict[str, Any]) -> None:
    policy = plan["policy"]
    egress = policy["egress"]
    vpn = policy.get("vpn_killswitch", {"enabled": False})
    say(f"AEGIS Firewall Sentinel {VERSION} | ACTION={plan['action']} | PLAN_SHA256={plan['plan_sha256']}")
    say(f"Reviewed physical interfaces: {', '.join(policy['trusted_interfaces'])}")
    say(f"Trusted connection UUIDs: {', '.join(policy.get('trusted_connection_uuids', []))}")
    say(f"Quarantine: {'ON' if policy['quarantine'] else 'OFF'}")
    say(f"LAN SMB/RPC/NetBIOS egress: {'ALLOWED' if egress['allow_lan_smb'] else 'BLOCKED'}")
    say(f"LAN SSDP egress: {'ALLOWED' if 1900 in egress['trusted_discovery_udp'] else 'BLOCKED'}")
    if egress.get("strict_dot_resolver"):
        say(f"DNS/DoT lock: STRICT (UID={egress['dot_resolver_uid']} -> {', '.join(egress['dot_servers'])} TCP/853 only)")
    else:
        say(f"Direct plaintext DNS (53) egress: {'BLOCKED' if egress.get('block_direct_dns') else 'PASSTHROUGH'}")
    if vpn.get("enabled"):
        eps = ", ".join(f"{e['ip']}:{e['port']}/{e['proto']}" for e in vpn.get("endpoints", [])) or "NONE (tunnel-up only)"
        say(f"VPN kill-switch: ON (iface={vpn['interface']}, allow_lan={vpn['allow_lan']}, endpoints={eps})")
    else:
        say("VPN kill-switch: OFF")
    if policy.get("allowed_foreign_tables"):
        say(f"Approved foreign tables: {', '.join(policy['allowed_foreign_tables'])}")
    say(f"Live forensics telemetry: NFLOG group {policy.get('nflog_group', NFLOG_GROUP)}; rate={NFLOG_RATE}/s burst={NFLOG_BURST} (zero disk writes by Sentinel)")
    say("")
    say("=== FIREWALL ACTIONS ===")
    say("- Keep AEGIS Network Hardening as the owner of zones, NetworkManager binding, and network sysctls.")
    say("- Own only separate nftables tables: inet aegis_sentinel (+ RAM-only panic/blocklist/cgroup tables).")
    say("- Gate every NetworkManager start with a non-propagating ExecStartPre=+ Sentinel integrity check.")
    say("- Block LLMNR (5355) and NAT-PMP/PCP (5351) egress on all interfaces.")
    say("- Populate LAN trust dynamically only when the reviewed NetworkManager connection UUID is active.")
    say("- Block mDNS/SSDP/WS-Discovery egress outside that UUID-derived trusted interface set.")
    say("- Keep SMB/MS-RPC/NetBIOS egress blocked everywhere unless explicitly enabled for trusted LAN interfaces.")
    say("- Emit zero-disk-I/O NFLOG events on all drop/reject rules for live `watch` inspection.")
    say("- Seal base Network Hardening watched files into committed manifest for sandboxed drift monitoring.")
    say("")
    say("=== CHANGES ===")
    for item in plan["file_changes"]:
        say(f"FILE {item}")
    for item in plan["unit_changes"]:
        say(f"UNIT {item}")
    if plan.get("runtime_change") != "NONE":
        say(f"RUNTIME {plan['runtime_change']}")
    if plan["no_op"]:
        say("NO-OP: files, services, manifest, and runtime table already match.")
    say("")
    say("=== INTENTIONALLY NOT DONE ===")
    say("- No rewrite of AEGIS Network Hardening files or zones.")
    say("- No userspace NFQUEUE pop-ups, TLS MITM, per-packet disk logging, or automatic repair of foreign drift.")


def tx_id() -> str:
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"T-{stamp}-{os.urandom(6).hex()}"


def snapshot_file(path: pathlib.Path, dest: pathlib.Path) -> None:
    state = inspect_optional_file(path)
    record = {k: v for k, v in state.items() if k != "data"}
    atomic_write(dest.with_suffix(".json"), pretty_json(record), 0o600)
    if state["exists"]:
        atomic_write(dest.with_suffix(".data"), state["data"], 0o600)


def restore_snapshot(path: pathlib.Path, dest: pathlib.Path) -> bool:
    record = read_managed_json(dest.with_suffix(".json"))
    if not isinstance(record, dict) or "exists" not in record:
        stop(f"Corrupt rollback snapshot metadata: {dest}")
    if not record["exists"]:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return False
    data_state = inspect_optional_file(dest.with_suffix(".data"))
    if not data_state["exists"]:
        stop(f"Missing rollback snapshot payload: {dest}")
    atomic_write(path, data_state["data"], int(record["mode"]))
    os.chown(path, int(record["uid"]), int(record["gid"]))
    return True


def write_status(directory: pathlib.Path, value: str) -> None:
    atomic_write(directory / "status", (value + "\n").encode(), 0o600)


def process_starttime(pid: int) -> str | None:
    try:
        raw = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError):
        return None
    end = raw.rfind(") ")
    if end < 0:
        return None
    fields = raw[end + 2 :].split()
    if len(fields) <= 19 or not fields[19].isdigit():
        return None
    return fields[19]


def stop_transaction_owner(directory: pathlib.Path) -> None:
    """Stop only the exact apply process recorded by this transaction using race-free pidfd."""
    pid_raw = read_managed_text(directory / "owner.pid", max_size=32, encoding="ascii")
    start_raw = read_managed_text(directory / "owner.starttime", max_size=64, encoding="ascii")
    if pid_raw is None or start_raw is None:
        return
    pid_text, expected_start = pid_raw.strip(), start_raw.strip()
    if not pid_text.isdigit() or not expected_start.isdigit():
        return
    pid = int(pid_text)
    if pid <= 1:
        return
    try:
        pidfd = os.pidfd_open(pid, 0)
    except OSError:
        return
    try:
        if process_starttime(pid) != expected_start:
            return
        try:
            cmdline = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")
        except OSError:
            return
        if str(INSTALL_PATH) not in cmdline or not any(
            f" {action}" in cmdline for action in ("apply", "quarantine-on", "quarantine-off")
        ):
            return
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        except OSError:
            return
        sel = selectors.DefaultSelector()
        try:
            sel.register(pidfd, selectors.EVENT_READ)
            if not sel.select(5.0):
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except OSError:
                    return
                sel.select(3.0)
        finally:
            sel.close()
    finally:
        os.close(pidfd)


def snapshot_transaction(plan: dict[str, Any]) -> pathlib.Path:
    ensure_dir(STATE, 0o700)
    ensure_dir(TRANSACTIONS, 0o700)
    ensure_dir(MANAGED, 0o700)
    ident = tx_id()
    directory = TRANSACTIONS / ident
    ensure_dir(directory, 0o700)
    ensure_dir(directory / "before", 0o700)
    ensure_dir(directory / "after", 0o700)
    atomic_write(directory / "plan.json", pretty_json(plan), 0o600)
    for idx, path in enumerate(MANAGED_PATHS):
        snapshot_file(path, directory / "before" / f"file-{idx}")
    for idx, path in enumerate(STATE_PATHS):
        snapshot_file(path, directory / "before" / f"state-{idx}")
    before_units = {name: service_state(name) for name in PERSISTENT_UNIT_NAMES}
    atomic_write(directory / "before" / "units.json", pretty_json(before_units), 0o600)
    atomic_write(directory / "before" / "table.json", pretty_json(nft_table_json()), 0o600)
    atomic_write(directory / "boot-id", BOOT_ID_PATH.read_bytes(), 0o600)
    owner_start = process_starttime(os.getpid())
    if owner_start is None:
        stop("Cannot record transaction owner identity")
    atomic_write(directory / "owner.pid", f"{os.getpid()}\n".encode(), 0o600)
    atomic_write(directory / "owner.starttime", f"{owner_start}\n".encode(), 0o600)
    write_status(directory, "PREPARED")
    return directory


def snapshot_after(directory: pathlib.Path) -> None:
    hashes = {}
    for path in MANAGED_PATHS:
        state = inspect_optional_file(path)
        hashes[str(path)] = state.get("sha256", "ABSENT") if state["exists"] else "ABSENT"
    atomic_write(directory / "after" / "files.json", pretty_json(hashes), 0o600)
    atomic_write(
        directory / "after" / "units.json",
        pretty_json({name: service_state(name) for name in PERSISTENT_UNIT_NAMES}),
        0o600,
    )
    state_hashes: dict[str, str] = {}
    for path in STATE_PATHS:
        state = inspect_optional_file(path)
        state_hashes[str(path)] = state.get("sha256", "ABSENT") if state["exists"] else "ABSENT"
    atomic_write(directory / "after" / "state.json", pretty_json(state_hashes), 0o600)
    table_hash = nft_table_hash()
    if not table_hash:
        stop("AEGIS Sentinel nft table is missing after activation")
    atomic_write(directory / "after" / "nft-table.sha256", f"{table_hash}\n".encode(), 0o600)


def guard_unit_name(ident: str) -> str:
    return "aegis-firewall-sentinel-rollback-" + ident.lower().replace("_", "-")


def schedule_guard(directory: pathlib.Path) -> None:
    ident = directory.name
    run(
        [
            "/usr/bin/systemd-run",
            "--quiet",
            "--unit", guard_unit_name(ident),
            "--on-active=180s",
            "--timer-property=AccuracySec=1s",
            "/usr/bin/python3", "-I", str(INSTALL_PATH), "emergency-rollback", ident,
        ],
        timeout=20,
        check=True,
    )


def cancel_guard(ident: str) -> None:
    unit = guard_unit_name(ident)
    run(["/usr/bin/systemctl", "stop", unit + ".timer", unit + ".service"], timeout=15)
    run(["/usr/bin/systemctl", "reset-failed", unit + ".timer", unit + ".service"], timeout=15)


def publish(plan: dict[str, Any]) -> None:
    policy = plan["policy"]
    nft_data = render_nft(policy)
    compile_nft(nft_data)
    stop_loaded_units(["aegis-firewall-sentinel-monitor.path"])
    atomic_write(POLICY_FILE, pretty_json(policy), 0o600)
    atomic_write(NFT_FILE, nft_data, 0o600)
    units = unit_texts()
    for path, data in units.items():
        atomic_write(path, data, 0o644)
    atomic_write(NM_DROPIN, networkmanager_dropin_text(), 0o644)
    dispatcher = networkmanager_dispatcher_text()
    atomic_write(NM_TRUST_DISPATCH, dispatcher, 0o755)
    atomic_write(NM_TRUST_PRE_UP, dispatcher, 0o755)
    atomic_write(NM_TRUST_PRE_DOWN, dispatcher, 0o755)
    run(
        [
            "/usr/sbin/restorecon", "-RF", str(CONFIG_DIR), str(NFT_FILE),
            *(str(x) for x in units), str(NM_DROPIN_DIR), str(NM_DISPATCH_DIR),
        ],
        timeout=30,
        check=True,
    )
    run(["/usr/bin/systemctl", "daemon-reload"], timeout=30, check=True)
    run(["/usr/bin/systemctl", "reset-failed", "aegis-firewall-sentinel-monitor.service"], timeout=15)
    run(["/usr/bin/systemctl", "enable", *PERSISTENT_UNIT_NAMES], timeout=45, check=True)
    active = run(["/usr/bin/systemctl", "is-active", "--quiet", "aegis-firewall-sentinel.service"])
    if active.code == 0:
        run(["/usr/bin/systemctl", "reload", "aegis-firewall-sentinel.service"], timeout=45, check=True)
    else:
        run(["/usr/bin/systemctl", "start", "aegis-firewall-sentinel.service"], timeout=45, check=True)
    sync_trusted_interfaces(force_clear=False)
    if policy["quarantine"]:
        for note in terminate_non_loopback_sockets():
            print(f"WARNING: {note}", file=sys.stderr)
    run(["/usr/bin/systemctl", "start", *MONITOR_PERSISTENT_UNITS], timeout=45, check=True)


def verify_files() -> list[str]:
    findings: list[str] = []
    if not POLICY_FILE.exists() or not NFT_FILE.exists():
        return ["Managed policy files are missing"]
    policy = read_policy(allow_version_upgrade=False)
    desired = {
        POLICY_FILE: pretty_json(policy),
        NFT_FILE: render_nft(policy),
        NM_DROPIN: networkmanager_dropin_text(),
        NM_TRUST_DISPATCH: networkmanager_dispatcher_text(),
        NM_TRUST_PRE_UP: networkmanager_dispatcher_text(),
        NM_TRUST_PRE_DOWN: networkmanager_dispatcher_text(),
        **unit_texts(),
    }
    for path, data in desired.items():
        state = inspect_optional_file(path)
        if not state["exists"] or state["sha256"] != sha256_bytes(data):
            findings.append(f"Managed file drift: {path}")
    return findings


def extract_counter_map(raw: dict[str, Any] | None) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    if not raw:
        return result
    for entry in raw.get("nftables", []):
        rule = entry.get("rule") if isinstance(entry, dict) else None
        if not isinstance(rule, dict):
            continue
        comment = rule.get("comment")
        if not isinstance(comment, str) or not comment.startswith(("aegis:block-", "aegis:quarantine-", "aegis:vpn-killswitch-")):
            continue
        packets = bytes_ = 0
        for expr in rule.get("expr", []):
            if isinstance(expr, dict) and isinstance(expr.get("counter"), dict):
                packets = int(expr["counter"].get("packets", 0))
                bytes_ = int(expr["counter"].get("bytes", 0))
        result[comment] = {"packets": packets, "bytes": bytes_}
    return result


def live_nft_json_with_counters() -> dict[str, Any] | None:
    result = run(["/usr/sbin/nft", "--json", "--numeric", "list", "table", TABLE_FAMILY, TABLE_NAME])
    if result.code != 0:
        return None
    try:
        return json.loads(result.output)
    except json.JSONDecodeError:
        stop("nft returned malformed counter JSON")


def verify_runtime(*, allow_unsealed: bool = False, allow_panic: bool = False) -> list[str]:
    findings: list[str] = []
    policy = read_policy(allow_version_upgrade=False)
    current, semantic = stable_semantic_table_hash(policy)
    findings.extend(semantic)
    expected_raw = read_managed_text(MANAGED / "nft-table.sha256", max_size=128, encoding="ascii")
    if current is not None:
        if expected_raw is not None:
            if expected_raw.strip() != current:
                findings.append("AEGIS Sentinel nftables table drift")
        elif not allow_unsealed:
            findings.append("AEGIS Sentinel nftables table is not sealed")
    if not allow_unsealed:
        findings.extend(verify_committed_manifest())
        try:
            findings.extend(foreign_table_drift_findings(policy))
        except Stop as exc:
            findings.append(str(exc))
    findings.extend(cgroup_lan_findings())
    if not allow_panic and panic_is_active():
        findings.append("RAM-only break-glass panic isolation is active")
    for name in PERSISTENT_UNIT_NAMES:
        state = service_state(name)
        if state["enabled"] != "enabled" or state["active"] != "active":
            findings.append(f"Systemd unit is not enabled+active: {name} ({state})")
    monitor_state = systemd_properties(
        "aegis-firewall-sentinel-monitor.service",
        ("LoadState", "ActiveState", "Result"),
    )
    if monitor_state.get("LoadState") != "loaded":
        findings.append(f"Monitor service is not loaded: {monitor_state}")
    if monitor_state.get("ActiveState") == "failed" or monitor_state.get("Result") not in {"", "success"}:
        findings.append(f"Monitor service last result is unhealthy: {monitor_state}")
    return findings


def verify_all(
    *,
    show: bool = True,
    allow_unsealed: bool = False,
    allow_panic: bool = False,
    strict_upper_bound: bool = True,
) -> list[str]:
    require_platform(mutation=False, strict_upper_bound=strict_upper_bound)
    ensure_service_active("firewalld.service")
    findings: list[str] = []
    result = run_network_script("verify", timeout=60.0)
    if result.code != 0:
        findings.append("AEGIS Network Hardening verification failed")
    findings.extend(verify_files())
    findings.extend(verify_runtime(allow_unsealed=allow_unsealed, allow_panic=allow_panic))
    if show:
        say("=== AEGIS Firewall Sentinel verification ===")
        if findings:
            for item in findings:
                say("FAIL " + item)
        else:
            say("VERIFIED: base Network Hardening, Sentinel egress policy, manifest, quarantine state, units, and runtime table match.")
    return findings


def seal_runtime_table() -> str:
    ensure_dir(MANAGED, 0o700)
    policy = read_policy(allow_version_upgrade=False)
    nft_state = inspect_optional_file(NFT_FILE)
    expected = render_nft(policy)
    if not nft_state["exists"] or nft_state["data"] != expected:
        stop("Cannot seal a drifted Sentinel nftables source file")
    _nft_stdin_transaction(expected, load=True)
    sync_trusted_interfaces(force_clear=False)
    table_hash, findings = stable_semantic_table_hash(policy)
    if findings or table_hash is None:
        stop("Cannot seal Sentinel table: " + "; ".join(findings))
    atomic_write(MANAGED / "nft-table.sha256", f"{table_hash}\n".encode(), 0o600)
    return table_hash


def record_latest_transaction(directory: pathlib.Path) -> None:
    ensure_dir(MANAGED, 0o700)
    atomic_write(MANAGED / "latest-transaction", f"{directory.name}\n".encode(), 0o600)


def write_committed_manifest(directory: pathlib.Path) -> None:
    files: dict[str, str] = {}
    for path in MANAGED_PATHS:
        state = inspect_optional_file(path)
        files[str(path)] = state.get("sha256", "ABSENT") if state["exists"] else "ABSENT"
    seal_raw = read_managed_text(MANAGED / "nft-table.sha256", max_size=128, encoding="ascii")
    seal = seal_raw.strip() if seal_raw is not None else ""
    if not HEX64_RE.fullmatch(seal):
        stop("Cannot commit manifest without a valid live-table seal")
    policy = read_policy(allow_version_upgrade=False)
    manifest = {
        "schema": 2,
        "version": VERSION,
        "transaction": directory.name,
        "runtime_sha256": installed_runtime_sha256(),
        "nft_table_sha256": seal,
        "files": files,
        "base_files": base_watched_hashes(),
        "approved_foreign_hook_fingerprints": foreign_table_hook_fingerprints(policy, require_present=True),
    }
    atomic_write(COMMITTED_MANIFEST, pretty_json(manifest), 0o600)


def apply_plan(plan: dict[str, Any], approve: str | None, *, strict_upper_bound: bool = True) -> None:
    allow_panic = bool(plan["policy"].get("quarantine", False))
    if plan["no_op"]:
        say("NO-OP: files, units, manifest, and runtime table already match.")
        findings = verify_all(show=True, allow_panic=allow_panic, strict_upper_bound=strict_upper_bound)
        if findings:
            raise SystemExit(3)
        return
    require_local_recovery_session()
    expected = plan["plan_sha256"]
    if approve:
        if approve != expected:
            stop("Plan approval digest mismatch")
    else:
        if not sys.stdin.isatty():
            stop("No interactive terminal; use --approve with the current plan hash")
        answer = input(f'Type exactly "APPLY {expected}" to continue: ')
        if answer != f"APPLY {expected}":
            stop("Apply cancelled")
    revalidate_plan_facts(plan, strict_upper_bound=strict_upper_bound)
    directory = snapshot_transaction(plan)
    write_status(directory, "APPLYING")
    try:
        schedule_guard(directory)
        publish(plan)
        findings = verify_all(show=True, allow_unsealed=True, allow_panic=allow_panic, strict_upper_bound=strict_upper_bound)
        if findings:
            write_status(directory, "FAILED")
            raise Stop("Post-apply verification failed")
        seal_runtime_table()
        write_committed_manifest(directory)
        record_latest_transaction(directory)
        strict_findings = verify_all(show=False, allow_unsealed=False, allow_panic=allow_panic, strict_upper_bound=strict_upper_bound)
        if strict_findings:
            write_status(directory, "FAILED")
            raise Stop("Post-seal verification failed: " + "; ".join(strict_findings))
        snapshot_after(directory)
        write_status(directory, "COMMITTED")
        cancel_guard(directory.name)
        say(f"COMMITTED: {directory.name}")
        if allow_panic and panic_is_active():
            say("NOTE: Persistent quarantine is now sealed; you may safely run `panic-off` to drop the RAM-only panic table.")
    except BaseException:
        try:
            emergency_restore(directory, allow_committed=False, reason="apply-failure")
        except BaseException as restore_error:
            print(f"RECOVERY REQUIRED: {restore_error}", file=sys.stderr)
        raise


def stop_loaded_units(names: Iterable[str]) -> None:
    to_stop: list[str] = []
    for name in names:
        props = systemd_properties(name, ("LoadState", "ActiveState"))
        if props.get("LoadState") == "loaded" and props.get("ActiveState") not in {"", "inactive"}:
            to_stop.append(name)
    if to_stop:
        run(["/usr/bin/systemctl", "stop", *to_stop], timeout=60, check=True)


def restore_unit_enablement(name: str, state: dict[str, str]) -> None:
    enabled = state.get("enabled", "unknown")
    if enabled == "enabled":
        run(["/usr/bin/systemctl", "enable", name], timeout=30, check=True)
    elif enabled == "enabled-runtime":
        run(["/usr/bin/systemctl", "enable", "--runtime", name], timeout=30, check=True)
    elif enabled == "disabled":
        run(["/usr/bin/systemctl", "disable", name], timeout=30, check=True)
    elif enabled in {"not-found", "static", "indirect", "generated", "transient", "alias"}:
        return
    else:
        stop(f"Unsupported saved unit enablement state for {name}: {enabled}")


def restore_unit_activity(name: str, state: dict[str, str]) -> None:
    if state.get("enabled") == "not-found":
        return
    active = state.get("active", "unknown")
    if active == "active":
        if run(["/usr/bin/systemctl", "is-active", "--quiet", name]).code != 0:
            run(["/usr/bin/systemctl", "start", name], timeout=45, check=True)
    elif active == "inactive":
        stop_loaded_units([name])
    else:
        stop(f"Unsupported saved unit activity state for {name}: {active}")


def check_after_conflicts(directory: pathlib.Path) -> None:
    after = read_managed_json(directory / "after" / "files.json")
    if not isinstance(after, dict):
        stop("Corrupt after/files.json snapshot")
    for path_text, expected in after.items():
        path = pathlib.Path(path_text)
        state = inspect_optional_file(path)
        actual = state.get("sha256", "ABSENT") if state["exists"] else "ABSENT"
        if actual != expected:
            stop(f"Rollback conflict: managed file changed after commit: {path}")
    expected_units = read_managed_json(directory / "after" / "units.json")
    if not isinstance(expected_units, dict):
        stop("Corrupt after/units.json snapshot")
    for name, expected_state in expected_units.items():
        if service_state(name) != expected_state:
            stop(f"Rollback conflict: systemd unit state changed after commit: {name}")
    expected_state = read_managed_json(directory / "after" / "state.json")
    if not isinstance(expected_state, dict):
        stop("Corrupt after/state.json snapshot")
    for path_text, expected_digest in expected_state.items():
        path = pathlib.Path(path_text)
        state = inspect_optional_file(path)
        actual = state.get("sha256", "ABSENT") if state["exists"] else "ABSENT"
        if actual != expected_digest:
            stop(f"Rollback conflict: Sentinel state changed after commit: {path}")
    expected_table = read_managed_text(directory / "after" / "nft-table.sha256", max_size=128, encoding="ascii")
    if expected_table is None or nft_table_hash() != expected_table.strip():
        stop("Rollback conflict: Sentinel nftables table changed after commit")


def emergency_restore(directory: pathlib.Path, *, allow_committed: bool, reason: str) -> None:
    if not directory.is_dir() or directory.is_symlink() or not TX_RE.fullmatch(directory.name):
        stop("Unsafe transaction directory")
    status_raw = read_managed_text(directory / "status", max_size=64, encoding="ascii")
    status = status_raw.strip() if status_raw is not None else "UNKNOWN"
    if status == "ROLLED_BACK":
        return
    if status == "COMMITTED":
        if not allow_committed:
            return
        check_after_conflicts(directory)
    elif status not in {"PREPARED", "APPLYING", "FAILED", "ROLLING_BACK"}:
        stop(f"Unsupported transaction state: {status}")
    write_status(directory, "ROLLING_BACK")
    try:
        before_units = read_managed_json(directory / "before" / "units.json")
        before_table = read_managed_json(directory / "before" / "table.json")
        if not isinstance(before_units, dict):
            stop("Corrupt before/units.json snapshot")

        stop_loaded_units([
            "aegis-firewall-sentinel-monitor.service",
            "aegis-firewall-sentinel-monitor.path",
            "aegis-firewall-sentinel-monitor.timer",
        ])

        restored_paths: list[str] = []
        for idx, path in enumerate(MANAGED_PATHS):
            if restore_snapshot(path, directory / "before" / f"file-{idx}"):
                restored_paths.append(str(path))
        for idx, path in enumerate(STATE_PATHS):
            restore_snapshot(path, directory / "before" / f"state-{idx}")

        if not NM_DROPIN.exists() and NM_DROPIN_DIR.is_dir() and not NM_DROPIN_DIR.is_symlink():
            try:
                NM_DROPIN_DIR.rmdir()
            except OSError:
                pass
        if NM_DROPIN.exists():
            restored_paths.append(str(NM_DROPIN_DIR))
        if restored_paths:
            run(["/usr/sbin/restorecon", "-RF", *sorted(set(restored_paths))], timeout=30, check=True)

        run(["/usr/bin/systemctl", "daemon-reload"], timeout=30, check=True)

        for name in PERSISTENT_UNIT_NAMES:
            restore_unit_enablement(name, before_units[name])

        if before_table is None:
            stop_loaded_units(["aegis-firewall-sentinel.service"])
            unload_runtime_policy()
        else:
            restored_nft = inspect_optional_file(NFT_FILE)
            if not restored_nft["exists"]:
                stop("Rollback expected a restored nft source file")
            _nft_stdin_transaction(restored_nft["data"], load=True)
            if before_units["aegis-firewall-sentinel.service"].get("active") != "active":
                stop_loaded_units(["aegis-firewall-sentinel.service"])

        atomic_write(directory / "rollback.reason", f"{reason}\n".encode(), 0o600)
        write_status(directory, "ROLLED_BACK")
        for name in PERSISTENT_UNIT_NAMES:
            restore_unit_activity(name, before_units[name])
    except BaseException:
        write_status(directory, "FAILED")
        raise


def panic_nft() -> bytes:
    pin = _logged_verdict("", "aegis:panic-in", "drop").rstrip()
    pout = _logged_verdict("", "aegis:panic-out", "drop").rstrip()
    pfwd = _logged_verdict("", "aegis:panic-forward", "drop").rstrip()
    return f"""#!/usr/sbin/nft -f
# Managed by AEGIS Firewall Sentinel {VERSION}. RAM-only break-glass isolation.
destroy table inet {PANIC_TABLE_NAME}

table inet {PANIC_TABLE_NAME} {{
    chain input_panic {{
        type filter hook input priority -301; policy accept;
        iifname "lo" return
{pin}
    }}
    chain output_panic {{
        type filter hook output priority -301; policy accept;
        oifname "lo" return
{pout}
    }}
    chain forward_panic {{
        type filter hook forward priority -301; policy accept;
{pfwd}
    }}
}}
""".encode("utf-8")


def emergency_quarantine_now() -> None:
    require_break_glass_tty()
    _nft_stdin_transaction(panic_nft(), load=True)
    for note in terminate_non_loopback_sockets():
        print(f"WARNING: best-effort socket cleanup: {note}", file=sys.stderr)
    say("EMERGENCY PANIC ISOLATION ACTIVE (RAM-ONLY): inet aegis_panic drops all non-loopback IP traffic.")
    say("The normal inet aegis_sentinel table was not modified.")


def emergency_quarantine_off() -> None:
    require_break_glass_tty()
    if not panic_is_active():
        say("EMERGENCY PANIC ISOLATION ALREADY OFF")
        return
    run(["/usr/sbin/nft", "destroy", "table", TABLE_FAMILY, PANIC_TABLE_NAME], timeout=20, check=True)
    say("EMERGENCY PANIC ISOLATION OFF")


def _ensure_blocklist_table() -> None:
    """Create/validate the separate bounded RAM-only dynamic blocklist table."""
    raw = nft_table_json(BLOCKLIST_TABLE_NAME)
    if raw is not None:
        chains: set[str] = set()
        sets: set[str] = set()
        for entry in raw.get("nftables", []):
            if not isinstance(entry, dict):
                continue
            if isinstance(entry.get("chain"), dict):
                chains.add(str(entry["chain"].get("name")))
            if isinstance(entry.get("set"), dict):
                sets.add(str(entry["set"].get("name")))
        if chains != {"input_block", "output_block"} or sets != {"blocked_v4", "blocked_v6"}:
            stop("Foreign or structurally drifted inet aegis_blocklist table already exists")
        return
    in4 = _logged_verdict("ip saddr @blocked_v4", "aegis:blocklist-in-v4", "drop").rstrip()
    in6 = _logged_verdict("ip6 saddr @blocked_v6", "aegis:blocklist-in-v6", "drop").rstrip()
    out4 = _logged_verdict("ip daddr @blocked_v4", "aegis:blocklist-out-v4", "reject with icmpx type admin-prohibited").rstrip()
    out6 = _logged_verdict("ip6 daddr @blocked_v6", "aegis:blocklist-out-v6", "reject with icmpx type admin-prohibited").rstrip()
    skeleton = f"""#!/usr/sbin/nft -f
table inet {BLOCKLIST_TABLE_NAME} {{
    set blocked_v4 {{
        type ipv4_addr
        flags interval, timeout
        size 4096
        gc-interval 30s
        comment "AEGIS dynamic IPv4 blocklist"
    }}
    set blocked_v6 {{
        type ipv6_addr
        flags interval, timeout
        size 4096
        gc-interval 30s
        comment "AEGIS dynamic IPv6 blocklist"
    }}
    chain input_block {{
        type filter hook input priority filter - 15; policy accept;
        iifname "lo" return
{in4}
{in6}
    }}
    chain output_block {{
        type filter hook output priority filter - 15; policy accept;
        oifname "lo" return
{out4}
{out6}
    }}
}}
""".encode("utf-8")
    _nft_stdin_transaction(skeleton, load=True)


def block_ip(target: str, ttl_raw: str) -> None:
    require_local_recovery_session()
    cidr, family = parse_block_target(target)
    ttl_sec = parse_ttl_seconds(ttl_raw)
    _ensure_blocklist_table()
    set_name = "blocked_v4" if family == 4 else "blocked_v6"
    # Remove any prior exact entry so TTL refreshes cleanly across nftables versions.
    run(
        ["/usr/sbin/nft", "--file", "-"],
        timeout=15,
        stdin=f"delete element inet {BLOCKLIST_TABLE_NAME} {set_name} {{ {cidr} }}\n".encode("ascii"),
    )
    add_cmd = f"add element inet {BLOCKLIST_TABLE_NAME} {set_name} {{ {cidr} timeout {ttl_sec}s }}\n".encode("ascii")
    run(["/usr/sbin/nft", "--file", "-"], timeout=15, check=True, stdin=add_cmd)
    terminate_sockets_for_cidr(cidr, family)
    say(f"BLOCKED (RAM-ONLY): {cidr} for {ttl_sec}s in inet {BLOCKLIST_TABLE_NAME} @{set_name}")


def unblock_ip(target: str) -> None:
    require_local_recovery_session()
    cidr, family = parse_block_target(target)
    if run(["/usr/sbin/nft", "list", "table", TABLE_FAMILY, BLOCKLIST_TABLE_NAME], timeout=10).code != 0:
        say("DYNAMIC BLOCKLIST TABLE IS NOT ACTIVE")
        return
    set_name = "blocked_v4" if family == 4 else "blocked_v6"
    res = run(
        ["/usr/sbin/nft", "--file", "-"],
        timeout=15,
        stdin=f"delete element inet {BLOCKLIST_TABLE_NAME} {set_name} {{ {cidr} }}\n".encode("ascii"),
    )
    if res.code != 0:
        stop(f"Entry not found or could not be removed from @{set_name}: {cidr}")
    say(f"UNBLOCKED: {cidr} from inet {BLOCKLIST_TABLE_NAME} @{set_name}")


def _dynamic_blocklist_summary() -> dict[str, list[str]]:
    raw = nft_table_json(BLOCKLIST_TABLE_NAME)
    if raw is None:
        return {"ipv4": [], "ipv6": []}
    out: dict[str, list[str]] = {"ipv4": [], "ipv6": []}
    for set_name, key in (("blocked_v4", "ipv4"), ("blocked_v6", "ipv6")):
        for entry in raw.get("nftables", []):
            obj = entry.get("set") if isinstance(entry, dict) else None
            if not isinstance(obj, dict) or obj.get("name") != set_name:
                continue
            elems = obj.get("elem", [])
            if not isinstance(elems, list):
                elems = [elems]
            for item in elems:
                out[key].append(json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item))
    return out


def list_blocked() -> None:
    res = run(["/usr/sbin/nft", "list", "table", TABLE_FAMILY, BLOCKLIST_TABLE_NAME], timeout=15)
    if res.code != 0:
        say("DYNAMIC BLOCKLIST: inactive (no blocked IPs)")
        return
    say(res.output.rstrip())


def isolate_cgroup_lan(rel_cgroup: str) -> None:
    """Runtime-only cgroupv2 LAN isolation; record inode so recreation cannot fail silently."""
    require_local_recovery_session()
    cleaned = rel_cgroup.strip().strip("/")
    if not cleaned or not CGROUP_REL_RE.fullmatch(cleaned) or ".." in cleaned.split("/"):
        stop(f"Unsafe relative cgroupv2 path: {rel_cgroup}")
    full = (CGROUP_ROOT / cleaned).resolve()
    try:
        full.relative_to(CGROUP_ROOT)
    except ValueError:
        stop("cgroupv2 path escaped /sys/fs/cgroup")
    if not full.is_dir():
        stop(f"cgroupv2 directory does not currently exist: {full}")
    inode = full.stat().st_ino
    level = len(pathlib.PurePosixPath(cleaned).parts)
    v4_lan = "{ " + ", ".join(EXPECTED_SMB_DESTINATIONS["ipv4"]) + " }"
    v6_lan = "{ " + ", ".join(EXPECTED_SMB_DESTINATIONS["ipv6"]) + " }"
    quoted = json.dumps(cleaned, ensure_ascii=True)
    b4 = _logged_verdict(
        f"socket cgroupv2 level {level} {quoted} ip daddr {v4_lan}",
        "aegis:cgroup-lan-v4", "reject with icmpx type admin-prohibited"
    ).rstrip()
    b6 = _logged_verdict(
        f"socket cgroupv2 level {level} {quoted} ip6 daddr {v6_lan}",
        "aegis:cgroup-lan-v6", "reject with icmpx type admin-prohibited"
    ).rstrip()
    payload = f"""#!/usr/sbin/nft -f
# Managed by AEGIS Firewall Sentinel {VERSION}. RAM-only cgroupv2 LAN isolation.
destroy table inet {CGROUP_TABLE_NAME}

table inet {CGROUP_TABLE_NAME} {{
    chain cgroup_lan_guard {{
        type filter hook output priority filter - 12; policy accept;
        oifname "lo" return
{b4}
{b6}
    }}
}}
""".encode("utf-8")
    _nft_stdin_transaction(payload, load=True)
    ensure_dir(RUNTIME, 0o700)
    atomic_write(
        CGROUP_STATE,
        pretty_json({"path": cleaned, "inode": inode, "level": level, "bound_at": dt.datetime.now(dt.UTC).isoformat()}),
        0o600,
    )
    say(f"CGROUP LAN ISOLATION ACTIVE (RAM-ONLY): level={level} path={cleaned} inode={inode}")


def unisolate_cgroup_lan() -> None:
    require_local_recovery_session()
    if run(["/usr/sbin/nft", "list", "table", TABLE_FAMILY, CGROUP_TABLE_NAME], timeout=10).code == 0:
        run(["/usr/sbin/nft", "destroy", "table", TABLE_FAMILY, CGROUP_TABLE_NAME], timeout=20, check=True)
    try:
        CGROUP_STATE.unlink()
    except FileNotFoundError:
        pass
    say("CGROUP LAN ISOLATION OFF")


def cgroup_lan_findings() -> list[str]:
    table_active = nft_table_json(CGROUP_TABLE_NAME) is not None
    state = read_managed_json(CGROUP_STATE) if os.path.lexists(CGROUP_STATE) else None
    if not table_active and state is None:
        return []
    if table_active and not isinstance(state, dict):
        return ["cgroup LAN isolation table is active but its runtime binding state is missing"]
    if not table_active and isinstance(state, dict):
        return ["cgroup LAN isolation binding state exists but nft table is absent"]
    assert isinstance(state, dict)
    path = str(state.get("path", ""))
    inode = state.get("inode")
    if not path or not isinstance(inode, int):
        return ["cgroup LAN isolation runtime binding state is malformed"]
    full = CGROUP_ROOT / path
    if not full.is_dir():
        return [f"cgroup LAN isolation target disappeared: {path}; run rebind after the cgroup is recreated"]
    if full.stat().st_ino != inode:
        return [f"cgroup LAN isolation target was recreated with a new cgroup ID: {path}; run rebind-cgroup-lan"]
    return []


def rebind_cgroup_lan() -> None:
    state = read_managed_json(CGROUP_STATE)
    if not isinstance(state, dict) or not isinstance(state.get("path"), str):
        stop("No prior cgroup LAN isolation binding is available to rebind")
    isolate_cgroup_lan(state["path"])


def watch_nflog() -> None:
    """Stream rate-limited NFLOG samples live; Sentinel itself writes no packet log to disk."""
    tcpdump = command_path("tcpdump")
    say(
        f"Listening on nflog:{NFLOG_GROUP}; telemetry is rate-limited to {NFLOG_RATE}/s burst {NFLOG_BURST} per rule. "
        "Sentinel writes no packet capture to disk. Press Ctrl+C to stop."
    )
    proc = subprocess.Popen(
        [tcpdump, "-l", "-n", "-v", "-i", f"nflog:{NFLOG_GROUP}"],
        stdin=subprocess.DEVNULL,
        stdout=sys.stdout,
        stderr=sys.stderr,
        env=CHILD_ENV,
        cwd="/",
        start_new_session=True,
        close_fds=True,
    )
    try:
        proc.wait()
    except (KeyboardInterrupt, SignalExit):
        _terminate_process_group(proc)


def history() -> None:
    if not TRANSACTIONS.exists():
        say("NO TRANSACTIONS")
        return
    for directory in sorted(TRANSACTIONS.glob("T-*")):
        if directory.is_dir() and not directory.is_symlink() and TX_RE.fullmatch(directory.name):
            try:
                status_raw = read_managed_text(directory / "status", max_size=64, encoding="ascii")
                status = status_raw.strip() if status_raw is not None else "UNKNOWN"
            except Stop:
                status = "UNKNOWN"
            say(f"{directory.name} {status}")


def rollback(tx: str | None, approve: str | None) -> None:
    require_local_recovery_session()
    if tx is None:
        latest_raw = read_managed_text(MANAGED / "latest-transaction", max_size=128, encoding="ascii")
        if latest_raw is None:
            stop("No latest transaction")
        tx = latest_raw.strip()
    if not TX_RE.fullmatch(tx):
        stop("Invalid transaction id")
    directory = TRANSACTIONS / tx
    if not directory.is_dir() or directory.is_symlink():
        stop("Transaction not found")
    digest = sha256_file(directory / "plan.json")
    if approve:
        if approve != digest:
            stop("Rollback approval digest mismatch")
    else:
        if not sys.stdin.isatty():
            stop("No interactive terminal; use --approve with the transaction plan hash")
        answer = input(f'Type exactly "ROLLBACK {tx} {digest}" to continue: ')
        if answer != f"ROLLBACK {tx} {digest}":
            stop("Rollback cancelled")
    emergency_restore(directory, allow_committed=True, reason="manual")
    say(f"ROLLED BACK: {tx}")


def list_tables() -> list[dict[str, str]]:
    result = run(["/usr/sbin/nft", "--json", "list", "tables"], check=True)
    try:
        raw = json.loads(result.output)
    except json.JSONDecodeError:
        stop("Cannot parse nft table list")
    tables: list[dict[str, str]] = []
    for entry in raw.get("nftables", []):
        table = entry.get("table") if isinstance(entry, dict) else None
        if isinstance(table, dict) and isinstance(table.get("family"), str) and isinstance(table.get("name"), str):
            tables.append({"family": table["family"], "name": table["name"]})
    return tables


def list_base_hooks() -> list[dict[str, Any]]:
    result = run(["/usr/sbin/nft", "--json", "--numeric", "list", "ruleset"], timeout=30, cap=MAX_OUTPUT, check=True)
    try:
        raw = json.loads(result.output)
    except json.JSONDecodeError:
        stop("Cannot parse nftables ruleset for base-chain inventory")
    hooks: list[dict[str, Any]] = []
    for entry in raw.get("nftables", []):
        chain = entry.get("chain") if isinstance(entry, dict) else None
        if not isinstance(chain, dict) or "hook" not in chain:
            continue
        family = chain.get("family")
        table = chain.get("table")
        name = chain.get("name")
        hook = chain.get("hook")
        priority = _nft_priority(chain.get("prio"))
        policy = chain.get("policy", "none")
        if all(isinstance(x, str) for x in (family, table, name, hook)) and priority is not None:
            hooks.append({
                "family": family,
                "table": table,
                "chain": name,
                "hook": hook,
                "priority": priority,
                "policy": str(policy),
            })
    return sorted(hooks, key=lambda x: (x["family"], x["table"], x["hook"], x["priority"], x["chain"]))[:256]


def systemd_properties(name: str, properties: tuple[str, ...]) -> dict[str, str]:
    args = ["/usr/bin/systemctl", "show", "--no-pager", name]
    for item in properties:
        args.extend(["--property", item])
    result = run(args, timeout=20)
    values: dict[str, str] = {}
    if result.code != 0:
        return values
    for line in result.output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def listener_summary() -> list[str]:
    result = run(["/usr/sbin/ss", "-H", "-lntu"], timeout=15)
    if result.code != 0:
        return ["UNKNOWN: ss failed"]
    listeners: list[str] = []
    for line in result.output.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        proto = fields[0]
        local = fields[4]
        if local.startswith(("0.0.0.0:", "[::]:", "*:")):
            listeners.append(f"{proto} {local}")
    return sorted(set(listeners))[:128]


def network_layer_readonly_attestation() -> list[str]:
    findings: list[str] = []
    try:
        verify_network_runtime_file()
        uuid, device = read_network_identity()
        zone = run(["/usr/bin/nmcli", "-g", "connection.zone", "connection", "show", "uuid", uuid], timeout=20)
        if zone.code != 0 or zone.output.strip() != "aegis-lan":
            findings.append(f"Network Hardening profile zone drift for {device}")
        llmnr = run(["/usr/bin/nmcli", "-g", "connection.llmnr", "connection", "show", "uuid", uuid], timeout=20)
        if llmnr.code != 0 or llmnr.output.strip() not in {"0", "no"}:
            findings.append(f"Network Hardening profile LLMNR drift for {device}")
        mdns = run(["/usr/bin/nmcli", "-g", "connection.mdns", "connection", "show", "uuid", uuid], timeout=20)
        if mdns.code != 0 or mdns.output.strip() not in {"1", "resolve"}:
            findings.append(f"Network Hardening profile mDNS drift for {device}")
        default_zone = run(["/usr/bin/firewall-cmd", "--get-default-zone"], timeout=20)
        if default_zone.code != 0 or default_zone.output.strip() != "aegis-public":
            findings.append("Network Hardening default zone is not aegis-public")
        findings.extend(_zone_readonly_findings("aegis-public", {"dhcpv6-client"}))
        findings.extend(_zone_readonly_findings(
            "aegis-lan",
            {"dhcpv6-client", "ipp-client", "mdns", "ws-discovery-client"},
        ))
        manifest = _runtime_manifest()
        expected_base = manifest.get("base_files")
        if not isinstance(expected_base, dict):
            findings.append("Committed manifest is missing Network Hardening base_files baseline")
        else:
            actual_base = base_watched_hashes()
            for path_str, expected_digest in expected_base.items():
                if actual_base.get(path_str) != expected_digest:
                    findings.append(f"Network Hardening base file drift: {path_str}")
        findings.extend(_network_sysctl_readonly_findings(device))
        forward_chain = run(
            ["/usr/sbin/nft", "list", "chain", "inet", "firewalld", "filter_FORWARD"],
            timeout=20,
            cap=256 * 1024,
        )
        if forward_chain.code != 0:
            findings.append("Cannot inspect firewalld filter_FORWARD chain")
        elif "ct status dnat accept" in forward_chain.output or "ct status 0x20 accept" in forward_chain.output:
            findings.append("StrictForwardPorts runtime invariant failed: generic DNAT accept is present")
    except Stop as exc:
        findings.append(str(exc))
    return findings


def foreign_table_hook_fingerprints(policy: dict[str, Any], *, require_present: bool) -> dict[str, str]:
    approved = normalize_foreign_tables(policy.get("allowed_foreign_tables", []))
    if not approved:
        return {}
    tables = {(x["family"], x["name"]) for x in list_tables()}
    hooks = list_base_hooks()
    out: dict[str, str] = {}
    for spec in approved:
        family, name = spec.split(":", 1)
        if (family, name) not in tables:
            if require_present:
                stop(f"Approved foreign nftables table is not currently present: {spec}")
            out[spec] = "ABSENT"
            continue
        view = [
            {
                "chain": h["chain"], "hook": h["hook"], "priority": h["priority"], "policy": h["policy"]
            }
            for h in hooks if h["family"] == family and h["table"] == name
        ]
        out[spec] = sha256_bytes(canonical_json(view))
    return out


def foreign_table_drift_findings(policy: dict[str, Any]) -> list[str]:
    try:
        manifest = _runtime_manifest()
    except Stop as exc:
        return [str(exc)]
    expected = manifest.get("approved_foreign_hook_fingerprints", {})
    if not isinstance(expected, dict):
        return ["Committed manifest foreign-table hook fingerprint map is invalid"]
    current = foreign_table_hook_fingerprints(policy, require_present=False)
    findings: list[str] = []
    for spec in sorted(set(expected) | set(current)):
        if expected.get(spec) != current.get(spec):
            findings.append(
                f"approved foreign table hook fingerprint changed: {spec} expected={expected.get(spec)} current={current.get(spec)}"
            )
    return findings


def monitor_report() -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    pending = incomplete_transactions()
    if pending:
        findings.append({
            "severity": "critical",
            "code": "INCOMPLETE_TRANSACTION",
            "message": ", ".join(pending),
        })
    try:
        platform = require_platform(mutation=False, strict_upper_bound=False)
        for pkg_warn in unreviewed_package_versions(platform):
            findings.append({
                "severity": "warning",
                "code": "UNREVIEWED_PACKAGE_VERSION",
                "message": pkg_warn,
            })
    except Stop as exc:
        platform = {}
        findings.append({"severity": "critical", "code": "PLATFORM", "message": str(exc)})
    policy_approved_tables: set[tuple[str, str]] = set()
    try:
        pol = read_policy(allow_version_upgrade=True)
        for spec in pol.get("allowed_foreign_tables", []):
            fam, name = spec.split(":", 1)
            policy_approved_tables.add((fam, name))
    except Stop:
        pass
    try:
        for item in verify_files():
            findings.append({"severity": "critical", "code": "FILE_DRIFT", "message": item})
        for item in verify_runtime():
            findings.append({"severity": "critical", "code": "RUNTIME_DRIFT", "message": item})
    except Stop as exc:
        findings.append({"severity": "critical", "code": "VERIFY", "message": str(exc)})
    for item in network_layer_readonly_attestation():
        findings.append({"severity": "critical", "code": "NETWORK_LAYER", "message": item})
    for item in cgroup_lan_findings():
        findings.append({"severity": "critical", "code": "CGROUP_LAN_STALE", "message": item})
    try:
        current_policy = read_policy(allow_version_upgrade=False)
        for item in foreign_table_drift_findings(current_policy):
            findings.append({"severity": "warning", "code": "APPROVED_FOREIGN_TABLE_DRIFT", "message": item})
    except Stop as exc:
        findings.append({"severity": "critical", "code": "FOREIGN_TABLE_ATTESTATION", "message": str(exc)})

    firewalld_state = systemd_properties("firewalld.service", ("LoadState", "ActiveState", "SubState", "Result", "NRestarts"))
    if (
        firewalld_state.get("LoadState") != "loaded"
        or firewalld_state.get("ActiveState") != "active"
        or firewalld_state.get("SubState") != "running"
    ):
        findings.append({"severity": "critical", "code": "FIREWALLD_STATE", "message": json.dumps(firewalld_state, sort_keys=True)})
    elif firewalld_state.get("Result") not in {"", "success"}:
        findings.append({"severity": "warning", "code": "FIREWALLD_RESULT", "message": json.dumps(firewalld_state, sort_keys=True)})

    firewalld_consistency, firewalld_findings = firewalld_runtime_permanent_state()
    findings.extend(firewalld_findings)
    if run(["/usr/bin/systemctl", "is-active", "--quiet", "nftables.service"]).code == 0:
        findings.append({
            "severity": "critical",
            "code": "NFTABLES_SERVICE",
            "message": "nftables.service is active and can compete with the AEGIS/firewalld ownership model",
        })
    try:
        tables = list_tables()
    except Stop as exc:
        tables = []
        findings.append({"severity": "critical", "code": "NFT_TABLE_INVENTORY", "message": str(exc)})
    if any(x["family"] == TABLE_FAMILY and x["name"] == PANIC_TABLE_NAME for x in tables):
        findings.append({
            "severity": "critical",
            "code": "PANIC_ISOLATION_ACTIVE",
            "message": "RAM-only break-glass table inet aegis_panic is active; host is isolated",
        })
    blocklist = _dynamic_blocklist_summary()
    total_blocked = len(blocklist["ipv4"]) + len(blocklist["ipv6"])
    if total_blocked:
        findings.append({
            "severity": "info",
            "code": "DYNAMIC_BLOCKLIST_ACTIVE",
            "message": f"ipv4={len(blocklist['ipv4'])} ipv6={len(blocklist['ipv6'])}",
        })
    allowed_tables = {
        ("inet", "firewalld"),
        (TABLE_FAMILY, TABLE_NAME),
        (TABLE_FAMILY, PANIC_TABLE_NAME),
        (TABLE_FAMILY, BLOCKLIST_TABLE_NAME),
        (TABLE_FAMILY, CGROUP_TABLE_NAME),
        *policy_approved_tables,
    }
    foreign = [f"{x['family']} {x['name']}" for x in tables if (x["family"], x["name"]) not in allowed_tables]
    if foreign:
        findings.append({"severity": "info", "code": "FOREIGN_NFT_TABLES", "message": ", ".join(foreign[:32])})
    try:
        hooks = list_base_hooks()
    except Stop as exc:
        hooks = []
        findings.append({"severity": "critical", "code": "NFT_HOOK_INVENTORY", "message": str(exc)})
    foreign_hooks = [item for item in hooks if (item["family"], item["table"]) not in allowed_tables]
    if foreign_hooks:
        findings.append({"severity": "warning", "code": "FOREIGN_NFT_HOOKS", "message": json.dumps(foreign_hooks[:32], sort_keys=True)})

    raw = live_nft_json_with_counters()
    counters = extract_counter_map(raw)
    previous_counters: dict[str, dict[str, int]] = {}
    try:
        old_report = read_managed_json(RUNTIME_REPORT)
        if isinstance(old_report, dict) and isinstance(old_report.get("counters"), dict):
            previous_counters = old_report["counters"]
    except Stop:
        previous_counters = {}

    deltas: dict[str, dict[str, int]] = {}
    for name, values in counters.items():
        old = previous_counters.get(name, {"packets": 0, "bytes": 0})
        cur_p, old_p = int(values["packets"]), int(old.get("packets", 0))
        cur_b, old_b = int(values["bytes"]), int(old.get("bytes", 0))
        packet_delta = cur_p if cur_p < old_p else (cur_p - old_p)
        byte_delta = cur_b if cur_b < old_b else (cur_b - old_b)
        if packet_delta:
            deltas[name] = {"packets": packet_delta, "bytes": byte_delta}
    if deltas:
        findings.append({"severity": "warning", "code": "NEW_BLOCKED_EGRESS", "message": json.dumps(deltas, sort_keys=True)})

    listeners = listener_summary()
    if listeners:
        findings.append({"severity": "info", "code": "WILDCARD_LISTENERS", "message": "; ".join(listeners)})
    severity_rank = {"healthy": 0, "info": 1, "warning": 2, "critical": 3}
    status = "healthy"
    for item in findings:
        if severity_rank[item["severity"]] > severity_rank[status]:
            status = item["severity"]
    return {
        "schema": 1,
        "version": VERSION,
        "status": status,
        "findings": findings,
        "counters": counters,
        "listeners": listeners,
        "tables": tables,
        "hooks": hooks,
        "firewalld_state": firewalld_state,
        "firewalld_runtime_permanent": firewalld_consistency,
        "platform": platform,
    }


def durable_monitor_projection(report: dict[str, Any]) -> dict[str, Any]:
    volatile_codes = {"NEW_BLOCKED_EGRESS", "WILDCARD_LISTENERS", "DYNAMIC_BLOCKLIST_ACTIVE"}
    findings = [item for item in report.get("findings", []) if item.get("code") not in volatile_codes]
    severity_rank = {"healthy": 0, "info": 1, "warning": 2, "critical": 3}
    status = "healthy"
    for item in findings:
        severity = str(item.get("severity", "critical"))
        if severity_rank.get(severity, 3) > severity_rank[status]:
            status = severity if severity in severity_rank else "critical"
    return {
        "schema": report.get("schema"),
        "version": report.get("version"),
        "status": status,
        "findings": findings,
        "listeners": [],
        "tables": report.get("tables", []),
        "hooks": report.get("hooks", []),
        "firewalld_state": report.get("firewalld_state", {}),
        "firewalld_runtime_permanent": report.get("firewalld_runtime_permanent", {}),
        "platform": report.get("platform", {}),
    }


def persist_monitor(report: dict[str, Any], *, systemd_mode: bool) -> bool:
    ensure_dir(RUNTIME, 0o700)
    ensure_dir(STATE, 0o700)
    ensure_dir(MONITOR_STATE, 0o700)
    runtime_report = dict(report)
    runtime_report["checked_at"] = dt.datetime.now(dt.UTC).isoformat()
    atomic_write(RUNTIME_REPORT, pretty_json(runtime_report), 0o600)
    durable = durable_monitor_projection(report)
    state_hash = sha256_bytes(canonical_json(durable))
    old_hash_raw = read_managed_text(LATEST_HASH, max_size=128, encoding="ascii")
    old_hash = old_hash_raw.strip() if old_hash_raw is not None else ""
    changed = state_hash != old_hash
    if systemd_mode:
        for item in report["findings"]:
            if item["code"] == "NEW_BLOCKED_EGRESS":
                say(f"<4>WARNING {item['code']}: {item['message']}")
    if changed:
        event = dict(runtime_report)
        event["durable_state"] = durable
        event["state_sha256"] = state_hash
        atomic_write(LATEST_EVENT, pretty_json(event), 0o600)
        atomic_write(LATEST_HASH, f"{state_hash}\n".encode(), 0o600)
        if systemd_mode:
            level = "<2>" if durable["status"] == "critical" else ("<4>" if durable["status"] == "warning" else "<6>")
            say(f"{level}AEGIS_FIREWALL_SENTINEL status={durable['status']} state={state_hash}")
            for item in durable["findings"]:
                if item["severity"] in {"warning", "critical"}:
                    p = "<2>" if item["severity"] == "critical" else "<4>"
                    say(f"{p}{item['severity'].upper()} {item['code']}: {item['message']}")
    return changed


def show_monitor(report: dict[str, Any]) -> None:
    say(f"AEGIS Firewall Sentinel monitor: {report['status'].upper()}")
    if not report["findings"]:
        say("No monitored drift or blocked-attempt counter was observed.")
    for item in report["findings"]:
        say(f"{item['severity'].upper():8} {item['code']}: {item['message']}")


def validate_candidate_units() -> list[str]:
    findings: list[str] = []
    ensure_dir(RUNTIME, 0o700)
    with tempfile.TemporaryDirectory(prefix="unit-verify.", dir=str(RUNTIME)) as directory_text:
        directory = pathlib.Path(directory_text)
        paths: list[str] = []
        for installed_path, data in unit_texts().items():
            candidate = directory / installed_path.name
            candidate.write_bytes(data)
            candidate.chmod(0o644)
            paths.append(str(candidate))
        result = run(
            ["/usr/bin/systemd-analyze", "verify", "--recursive-errors=no", *paths],
            timeout=60,
            cap=512 * 1024,
        )
        if result.code != 0:
            findings.append("generated systemd unit validation failed: " + result.output.strip())
    return findings


def _firewall_words(args: list[str]) -> tuple[set[str], str | None]:
    result = run(["/usr/bin/firewall-cmd", *args], timeout=20, cap=256 * 1024)
    if result.code != 0:
        return set(), result.output.strip() or f"firewall-cmd {' '.join(args)} failed"
    return {word for word in result.output.split() if word}, None


def firewalld_runtime_permanent_state() -> tuple[dict[str, Any], list[dict[str, str]]]:
    findings: list[dict[str, str]] = []
    state: dict[str, Any] = {}
    # --get-default-zone is a stand-alone firewall-cmd option and cannot be
    # combined with --permanent.  Disk DefaultZone integrity is already sealed
    # through the managed firewalld.conf baseline, while runtime default-zone
    # semantics are checked by Network Hardening attestation.
    pairs = {
        "zones": (["--get-zones"], ["--permanent", "--get-zones"]),
        "policies": (["--get-policies"], ["--permanent", "--get-policies"]),
    }
    for label, (runtime_args, permanent_args) in pairs.items():
        runtime_values, runtime_error = _firewall_words(runtime_args)
        permanent_values, permanent_error = _firewall_words(permanent_args)
        state[label] = {
            "runtime": sorted(runtime_values),
            "permanent": sorted(permanent_values),
        }
        if runtime_error or permanent_error:
            findings.append({
                "severity": "critical",
                "code": "FIREWALLD_QUERY_" + label.upper(),
                "message": "; ".join(x for x in (runtime_error, permanent_error) if x),
            })
        elif runtime_values != permanent_values:
            findings.append({
                "severity": "warning",
                "code": "FIREWALLD_RUNTIME_PERMANENT_" + label.upper(),
                "message": json.dumps(state[label], sort_keys=True),
            })
    return state, findings


def validate(*, strict_upper_bound: bool = True) -> int:
    require_platform(mutation=False, strict_upper_bound=strict_upper_bound)
    findings: list[str] = []
    offline = run(["/usr/bin/firewall-offline-cmd", "--check-config"], timeout=45)
    if offline.code != 0:
        findings.append("firewalld disk configuration validation failed: " + offline.output.strip())
    try:
        verify_network_layer()
        _, device = read_network_identity()
        if POLICY_FILE.exists():
            policy = read_policy(allow_version_upgrade=False)
        else:
            uuid, device = read_network_identity()
            policy = render_policy(
                [device], False, trusted_connection_uuids=[uuid], allow_lan_smb=False, allow_lan_ssdp=False
            )
        candidate_nft = render_nft(policy)
        compile_nft(candidate_nft)
        if policy.get("egress", {}).get("strict_dot_resolver") and not policy.get("quarantine", False):
            findings.extend(dot_resolver_attestation(
                policy["egress"]["dot_servers"], policy["egress"]["dot_server_name"]
            ))
        if NFT_FILE.exists():
            nft_state = inspect_optional_file(NFT_FILE)
            if not nft_state["exists"] or nft_state["data"] != candidate_nft:
                findings.append("installed Sentinel nftables file does not match the current policy")
    except Stop as exc:
        findings.append("Sentinel candidate nftables validation failed: " + str(exc))
    findings.extend(validate_candidate_units())
    gate = networkmanager_dropin_text().decode("utf-8")
    if (
        "[Unit]\n" not in gate
        or "Wants=aegis-firewall-sentinel.service" not in gate
        or "After=aegis-firewall-sentinel.service" not in gate
        or "Requires=aegis-firewall-sentinel.service" in gate
        or "ExecStartPre=+/usr/bin/python3 -I " not in gate
        or " network-gate" not in gate
    ):
        findings.append("NetworkManager non-propagating fail-closed boot gate is invalid")
    dispatcher = networkmanager_dispatcher_text().decode("utf-8")
    if " trust-sync --dispatcher " not in dispatcher or not dispatcher.startswith("#!/usr/bin/bash\n# Managed by AEGIS Firewall Sentinel "):
        findings.append("NetworkManager trust dispatcher candidate is invalid")
    if any(os.path.lexists(path) for path in MANAGED_PATHS):
        try:
            validate_managed_destinations()
            if POLICY_FILE.exists() and NFT_FILE.exists():
                findings.extend(verify_files())
        except Stop as exc:
            findings.append("installed managed-file validation failed: " + str(exc))
    if findings:
        for item in findings:
            say("FAIL " + item)
        return 3
    say("VALIDATED: firewalld disk config, candidate nftables syntax, generated systemd units, and Network Hardening base passed.")
    return 0


def audit() -> None:
    platform_warning = ""
    try:
        versions = require_platform(mutation=False, strict_upper_bound=True)
    except Stop as exc:
        platform_warning = str(exc)
        versions = platform_inventory()
    say(f"AEGIS Firewall Sentinel {VERSION} — READ-ONLY AUDIT")
    say("No package install, firewall mutation, daemon restart, scan, DNS query, or automatic repair is performed.")
    if platform_warning:
        say("PLATFORM_WARNING: " + platform_warning)
    say(json.dumps({"platform": versions}, sort_keys=True))
    initial = systemd_properties(
        "firewalld.service",
        ("LoadState", "ActiveState", "SubState", "Result", "NRestarts", "InvocationID", "FragmentPath", "DropInPaths"),
    )
    say("=== firewalld unit ===")
    say(json.dumps(initial, sort_keys=True, indent=2))
    say("=== Network Hardening state ===")
    try:
        result = run_network_script("status", timeout=30.0)
        say(result.output.rstrip())
        say("=== Network Hardening verification ===")
        result = run_network_script("verify", timeout=60.0)
        say(result.output.rstrip())
        say(f"NETWORK_VERIFY_EXIT={result.code}")
    except Stop as exc:
        say(f"NETWORK_LAYER_ERROR: {exc}")
    say("=== firewalld runtime overview ===")
    for args in (["--state"], ["--get-default-zone"], ["--get-active-zones"], ["--get-policies"], ["--list-all-policies"]):
        result = run(["/usr/bin/firewall-cmd", *args], timeout=30)
        say(f"$ firewall-cmd {' '.join(args)}")
        say(result.output.rstrip())
        say(f"EXIT={result.code}")
    say("=== firewalld permanent overview ===")
    say("DefaultZone disk integrity is covered by the sealed /etc/firewalld/firewalld.conf baseline; firewall-cmd --get-default-zone is stand-alone.")
    for args in (["--permanent", "--get-policies"], ["--permanent", "--list-all-policies"]):
        result = run(["/usr/bin/firewall-cmd", *args], timeout=30)
        say(f"$ firewall-cmd {' '.join(args)}")
        say(result.output.rstrip())
        say(f"EXIT={result.code}")
    say("=== nftables tables ===")
    try:
        for item in list_tables():
            say(f"{item['family']} {item['name']}")
    except Stop as exc:
        say(f"NFT_TABLES_ERROR: {exc}")
    say("=== nftables base hooks ===")
    try:
        for item in list_base_hooks():
            say(json.dumps(item, sort_keys=True))
    except Stop as exc:
        say(f"NFT_HOOKS_ERROR: {exc}")
    say("=== Sentinel counters ===")
    try:
        say(json.dumps(extract_counter_map(live_nft_json_with_counters()), sort_keys=True, indent=2))
    except Stop as exc:
        say(f"NFT_COUNTERS_ERROR: {exc}")
    say("=== Wildcard listeners (local endpoints; not proof of remote reachability) ===")
    for item in listener_summary():
        say(item)
    say("=== Recent firewalld warnings/errors in this boot (bounded sample) ===")
    journal = run(
        ["/usr/bin/journalctl", "--system", "--no-pager", "--quiet", "-b", "-u", "firewalld.service", "-p", "warning..alert", "-n", "50", "-o", "short-iso"],
        timeout=30,
        cap=256 * 1024,
    )
    say(journal.output.rstrip() or "NO MATCHING ENTRIES")
    final = systemd_properties("firewalld.service", ("InvocationID", "ActiveState", "SubState"))
    if initial.get("InvocationID") and final.get("InvocationID") != initial.get("InvocationID"):
        say("WARNING: firewalld invocation changed during this sequential audit; observations are not one atomic snapshot.")
    say("AUDIT NOTE: wildcard listeners and local rules are evidence, not remote exposure proof.")


def status() -> None:
    policy = read_policy(allow_version_upgrade=True) if POLICY_FILE.exists() else None
    say(f"VERSION={VERSION}")
    say(f"POLICY_INSTALLED={'yes' if policy else 'no'}")
    if policy:
        egress = policy["egress"]
        vpn = policy.get("vpn_killswitch", {"enabled": False})
        say(f"POLICY_VERSION={policy['version']}")
        say(f"QUARANTINE={'on' if policy['quarantine'] else 'off'}")
        say(f"TRUSTED_INTERFACES={','.join(policy['trusted_interfaces'])}")
        say(f"STRICT_DOT_RESOLVER={'yes' if egress.get('strict_dot_resolver') else 'no'}")
        say(f"DIRECT_DNS_BLOCKED={'yes' if egress.get('block_direct_dns') else 'no'}")
        say(f"VPN_KILLSWITCH={'on:' + vpn['interface'] if vpn.get('enabled') else 'off'}")
    say(f"NFT_TABLE={'present' if nft_table_hash() else 'absent'}")
    say(f"PANIC_ISOLATION={'on' if panic_is_active() else 'off'}")
    bl = _dynamic_blocklist_summary()
    say(f"DYNAMIC_BLOCKLIST=v4:{len(bl['ipv4'])},v6:{len(bl['ipv6'])}")
    cgroup_on = run(["/usr/sbin/nft", "list", "table", TABLE_FAMILY, CGROUP_TABLE_NAME], timeout=10).code == 0
    cgroup_findings = cgroup_lan_findings()
    say(f"CGROUP_LAN_ISOLATION={'stale' if cgroup_findings else ('on' if cgroup_on else 'off')}")
    latest_raw = read_managed_text(MANAGED / "latest-transaction", max_size=128, encoding="ascii")
    if latest_raw is not None:
        latest = latest_raw.strip()
        say(f"LATEST_TRANSACTION={latest}")
        if TX_RE.fullmatch(latest):
            tx_status = read_managed_text(TRANSACTIONS / latest / "status", max_size=64, encoding="ascii")
            if tx_status is not None:
                say(f"TRANSACTION_STATUS={tx_status.strip()}")
    try:
        report = read_managed_json(RUNTIME_REPORT)
        if isinstance(report, dict):
            say(f"MONITOR_STATUS={report.get('status', 'unknown')}")
            say(f"MONITOR_CHECKED_AT={report.get('checked_at', 'unknown')}")
    except Stop:
        say("MONITOR_STATUS=corrupt")


def verify_install(source: pathlib.Path | None) -> None:
    installed = installed_runtime_sha256()
    say(f"INSTALLED_SHA256={installed}")
    result = run(["/usr/bin/python3", "-I", str(INSTALL_PATH), "version"], check=True)
    say(f"INSTALLED_VERSION={result.output.strip()}")
    if source:
        source_hash = sha256_file(source)
        say(f"SOURCE_SHA256={source_hash}")
        if source_hash != installed:
            stop("Installed runtime does not match the supplied source")
    say("VERIFIED_INSTALL: root-owned runtime is present and version-readable.")


def packages() -> None:
    say("No package is installed, removed, or updated by this script.")
    for name in ("firewalld", "nftables", "NetworkManager", "systemd"):
        try:
            say(f"{name}={package_version(name)}")
        except Stop as exc:
            say(str(exc))
    for cmd in (
        "python3", "nft", "firewall-cmd", "firewall-offline-cmd", "systemctl",
        "systemd-run", "systemd-analyze", "journalctl", "nmcli", "ss", "restorecon", "tcpdump", "resolvectl",
    ):
        say(f"{cmd}={'PRESENT' if shutil.which(cmd, path=CHILD_ENV['PATH']) else 'MISSING'}")


def quarantine_change(enable: bool, approve: str | None, *, strict_upper_bound: bool = True, force_emergency: bool = False) -> None:
    if enable and force_emergency:
        stop("Break-glass quarantine must be dispatched before the normal transaction lock")
    policy = read_policy(allow_version_upgrade=True)
    egress = policy["egress"]
    plan = build_plan(
        quarantine=enable,
        extra_interfaces=[],
        remove_interfaces=[],
        lan_smb=bool(egress.get("allow_lan_smb", False)),
        lan_ssdp=1900 in egress.get("trusted_discovery_udp", []),
        block_direct_dns=bool(egress.get("block_direct_dns", False)),
        strict_dot_resolver=bool(egress.get("strict_dot_resolver", False)),
        dot_servers=egress.get("dot_servers") or None,
        dot_server_name=egress.get("dot_server_name") or DOT_SERVER_NAME_DEFAULT,
        strict_upper_bound=strict_upper_bound,
        action="quarantine-on" if enable else "quarantine-off",
    )
    print_plan(plan)
    apply_plan(plan, approve, strict_upper_bound=strict_upper_bound)


def emergency_rollback(tx: str) -> None:
    ensure_root()
    if not TX_RE.fullmatch(tx):
        stop("Invalid emergency transaction id")
    directory = TRANSACTIONS / tx
    if not directory.is_dir() or directory.is_symlink():
        stop("Emergency transaction not found")
    boot_raw = read_managed_text(directory / "boot-id", max_size=128, encoding="ascii")
    if boot_raw is None or boot_raw.strip() != BOOT_ID_PATH.read_text(encoding="ascii").strip():
        stop("Emergency rollback transaction belongs to another boot")
    stop_transaction_owner(directory)
    with Lock(wait=30):
        emergency_restore(directory, allow_committed=False, reason="systemd-guard")


def _add_policy_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--trust-interface", action="append", default=[], metavar="IFACE",
                        help=argparse.SUPPRESS)
    parser.add_argument("--untrust-interface", action="append", default=[], metavar="IFACE",
                        help=argparse.SUPPRESS)
    smb = parser.add_mutually_exclusive_group()
    smb.add_argument("--allow-lan-smb", dest="lan_smb", action="store_const", const=True, default=None,
                     help="allow SMB/RPC/NetBIOS egress only on trusted interfaces")
    smb.add_argument("--deny-lan-smb", dest="lan_smb", action="store_const", const=False,
                     help="block SMB/RPC/NetBIOS egress on every interface (default)")
    ssdp = parser.add_mutually_exclusive_group()
    ssdp.add_argument("--allow-lan-ssdp", dest="lan_ssdp", action="store_const", const=True, default=None,
                      help="allow SSDP egress only on trusted interfaces")
    ssdp.add_argument("--deny-lan-ssdp", dest="lan_ssdp", action="store_const", const=False,
                      help="block SSDP egress on every interface (default)")
    dns = parser.add_mutually_exclusive_group()
    dns.add_argument("--block-direct-dns", dest="block_direct_dns", action="store_const", const=True, default=None,
                     help="block direct non-loopback UDP/TCP port 53 egress")
    dns.add_argument("--allow-direct-dns", dest="block_direct_dns", action="store_const", const=False,
                     help="do not filter outbound port 53 (unless --strict-dot-resolver is on)")
    dot = parser.add_mutually_exclusive_group()
    dot.add_argument("--strict-dot-resolver", dest="strict_dot_resolver", action="store_const", const=True, default=None,
                     help="allow outbound TCP/853 ONLY for systemd-resolve to approved DoT IPs; block all other 53/853")
    dot.add_argument("--no-strict-dot-resolver", dest="strict_dot_resolver", action="store_const", const=False,
                     help="disable strict UID-pinned DoT lock")
    parser.add_argument("--dot-server", action="append", default=None, metavar="IP",
                        help="approved DoT server IP (repeatable; defaults to Quad9 when --strict-dot-resolver is enabled)")
    parser.add_argument("--dot-server-name", default=None, metavar="SNI",
                        help="DoT TLS/SNI server name required in systemd-resolved (default: dns.quad9.net)")
    vpn = parser.add_mutually_exclusive_group()
    vpn.add_argument("--vpn-only", metavar="IFACE", default=None,
                     help="enable VPN kill-switch allowing egress only via tunnel IFACE (plus --vpn-endpoint)")
    vpn.add_argument("--vpn-off", action="store_true", help="disable VPN kill-switch")
    parser.add_argument("--vpn-endpoint", action="append", default=None, metavar="IP:PORT[/udp|tcp]",
                        help="VPN gateway endpoint allowed outside the tunnel for handshake/rekey")
    vlan = parser.add_mutually_exclusive_group()
    vlan.add_argument("--vpn-allow-lan", dest="vpn_allow_lan", action="store_const", const=True, default=None,
                      help="permit trusted-interface RFC1918/ULA traffic while VPN kill-switch is active")
    vlan.add_argument("--vpn-deny-lan", dest="vpn_allow_lan", action="store_const", const=False,
                      help="block LAN egress while VPN kill-switch is active (default)")
    parser.add_argument("--allow-foreign-table", action="append", default=[], metavar="FAMILY:NAME",
                        help="approve an expected external nftables table (e.g. ip:docker-bridges) in drift monitoring")
    parser.add_argument("--remove-foreign-table", action="append", default=[], metavar="FAMILY:NAME",
                        help="remove a previously approved external nftables table")
    quar = parser.add_mutually_exclusive_group()
    quar.add_argument("--quarantine-on", dest="quarantine", action="store_const", const=True, default=None,
                      help="preview/apply quarantine ON")
    quar.add_argument("--quarantine-off", dest="quarantine", action="store_const", const=False,
                      help="preview/apply quarantine OFF")
    parser.add_argument("--allow-newer-packages", action="store_true",
                        help="allow Fedora 44 packages newer than the statically reviewed minor family")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AEGIS Firewall Sentinel: isolated nftables egress containment, quarantine, kill-switch, active response, and drift monitoring",
        epilog="Mutations require Fedora 44, the verified Network Hardening 0.7.0-rc4 base, and a local recovery session.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="show the program version")
    sub.add_parser("packages", help="show reviewed package versions and dependencies; install nothing")
    sub.add_parser("audit", help="collect a bounded read-only firewall/runtime evidence report")
    val_p = sub.add_parser("validate", help="validate firewalld disk config, installed nft syntax, units, and the base layer")
    val_p.add_argument("--allow-newer-packages", action="store_true")
    plan = sub.add_parser("plan", help="show the exact proposed policy and approval digest")
    _add_policy_options(plan)
    apply_p = sub.add_parser("apply", help="transactionally apply the reviewed current plan")
    _add_policy_options(apply_p)
    apply_p.add_argument("--approve", metavar="PLAN_SHA256", help="non-interactive approval for the exact current plan")
    ver_p = sub.add_parser("verify", help="verify files, units, base layer, and live nftables semantics")
    ver_p.add_argument("--allow-newer-packages", action="store_true")
    sub.add_parser("status", help="show concise managed state")
    sub.add_parser("history", help="list transaction status records")
    sub.add_parser("watch", help="stream rate-limited live drop/reject samples from NFLOG group 10 (Sentinel writes no packet log to disk)")
    b_ip = sub.add_parser("block-ip", help="dynamically block an IP/CIDR with auto-expiring TTL (RAM-only)")
    b_ip.add_argument("target", metavar="IP_OR_CIDR")
    b_ip.add_argument("--ttl", default="24h", help="expiration timeout (60s..30d, default 24h)")
    u_ip = sub.add_parser("unblock-ip", help="remove an IP/CIDR from the dynamic blocklist")
    u_ip.add_argument("target", metavar="IP_OR_CIDR")
    sub.add_parser("list-blocked", help="show active entries in the RAM-only dynamic blocklist")
    cg_on = sub.add_parser("isolate-cgroup-lan", help="block RFC1918/ULA LAN egress for an active cgroupv2 slice (RAM-only)")
    cg_on.add_argument("cgroup", metavar="RELATIVE_CGROUP_PATH")
    sub.add_parser("unisolate-cgroup-lan", help="remove RAM-only cgroupv2 LAN isolation")
    sub.add_parser("rebind-cgroup-lan", help="rebind RAM-only cgroup LAN isolation after a cgroup recreation")
    monitor = sub.add_parser("monitor-now", help="run the drift monitor immediately")
    monitor.add_argument("--systemd", action="store_true", help=argparse.SUPPRESS)
    install = sub.add_parser("verify-install", help="verify the protected installed runtime")
    install.add_argument("--source", type=pathlib.Path, help="also compare the installed runtime with this source file")
    rollback_parser = sub.add_parser("rollback", help="conflict-aware rollback of a committed transaction")
    rollback_parser.add_argument("tx", nargs="?", metavar="TX_ID")
    rollback_parser.add_argument("--approve", metavar="PLAN_JSON_SHA256")
    q_on = sub.add_parser("quarantine-on", help="enable explicit emergency host isolation")
    q_on.add_argument("--approve", metavar="PLAN_SHA256")
    q_on.add_argument("--allow-newer-packages", action="store_true")
    q_on.add_argument("--force-emergency", action="store_true", help="break-glass RAM-only host isolation bypassing drift checks")
    q_off = sub.add_parser("quarantine-off", help="disable emergency isolation and restore the normal Sentinel policy")
    q_off.add_argument("--approve", metavar="PLAN_SHA256")
    q_off.add_argument("--allow-newer-packages", action="store_true")
    sub.add_parser("panic-off", help="remove RAM-only break-glass isolation")
    sub.add_parser("runtime-load", help=argparse.SUPPRESS)
    sub.add_parser("network-gate", help=argparse.SUPPRESS)
    trust_sync = sub.add_parser("trust-sync", help=argparse.SUPPRESS)
    trust_sync.add_argument("--dispatcher", action="store_true", help=argparse.SUPPRESS)
    trust_sync.add_argument("interface")
    trust_sync.add_argument("action")
    emergency = sub.add_parser("emergency-rollback", help=argparse.SUPPRESS)
    emergency.add_argument("tx")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    os.umask(0o077)
    install_signal_handlers()
    args = parse_args(argv)
    if args.command == "version":
        say(VERSION)
        return 0
    if args.command == "packages":
        packages()
        return 0
    if args.command == "verify-install":
        verify_install(args.source)
        return 0
    ensure_root()
    if args.command == "watch":
        require_installed_runtime()
        watch_nflog()
        return 0
    if args.command == "quarantine-on" and getattr(args, "force_emergency", False):
        require_installed_runtime()
        command_path("nft")
        emergency_quarantine_now()
        return 0
    if args.command == "panic-off":
        require_installed_runtime()
        command_path("nft")
        emergency_quarantine_off()
        return 0
    if args.command == "network-gate":
        require_installed_runtime()
        for dep in ("nft", "firewall-cmd", "nmcli", "systemctl"):
            command_path(dep)
        network_gate()
        return 0
    if args.command == "trust-sync":
        require_installed_runtime()
        for dep in ("nft", "nmcli"):
            command_path(dep)
        trust_sync_dispatcher(args.interface, args.action)
        return 0
    for dep in (
        "rpm", "systemctl", "systemd-run", "systemd-analyze", "systemd-detect-virt",
        "loginctl", "journalctl", "getenforce", "restorecon", "nft",
        "firewall-cmd", "firewall-offline-cmd", "nmcli", "ss", "resolvectl",
    ):
        command_path(dep)
    if args.command == "emergency-rollback":
        require_systemd_invocation(guard_unit_name(args.tx) + ".service")
        emergency_rollback(args.tx)
        return 0
    require_installed_runtime()
    if args.command == "runtime-load":
        require_systemd_invocation("aegis-firewall-sentinel.service")
        require_boot_runtime_platform()
        ensure_service_active("firewalld.service")
        ensure_no_incomplete_transactions(allow_live_applying=True)
        load_runtime_policy()
        return 0
    if args.command == "monitor-now" and getattr(args, "systemd", False):
        require_systemd_invocation("aegis-firewall-sentinel-monitor.service")

    strict_upper = not getattr(args, "allow_newer_packages", False)
    lock_wait = 60.0 if args.command == "monitor-now" and getattr(args, "systemd", False) else 0.0
    with Lock(wait=lock_wait):
        if args.command == "audit":
            audit()
        elif args.command == "validate":
            return validate(strict_upper_bound=strict_upper)
        elif args.command == "plan":
            action = "quarantine-on" if args.quarantine is True else ("quarantine-off" if args.quarantine is False else "apply")
            plan = build_plan(
                quarantine=args.quarantine,
                extra_interfaces=args.trust_interface,
                remove_interfaces=args.untrust_interface,
                lan_smb=args.lan_smb,
                lan_ssdp=args.lan_ssdp,
                block_direct_dns=args.block_direct_dns,
                strict_dot_resolver=args.strict_dot_resolver,
                dot_servers=args.dot_server,
                dot_server_name=args.dot_server_name,
                vpn_only=args.vpn_only,
                vpn_off=args.vpn_off,
                vpn_endpoints=args.vpn_endpoint,
                vpn_allow_lan=args.vpn_allow_lan,
                allow_foreign_tables=args.allow_foreign_table,
                remove_foreign_tables=args.remove_foreign_table,
                strict_upper_bound=strict_upper,
                action=action,
            )
            print_plan(plan)
        elif args.command == "apply":
            action = "quarantine-on" if args.quarantine is True else ("quarantine-off" if args.quarantine is False else "apply")
            plan = build_plan(
                quarantine=args.quarantine,
                extra_interfaces=args.trust_interface,
                remove_interfaces=args.untrust_interface,
                lan_smb=args.lan_smb,
                lan_ssdp=args.lan_ssdp,
                block_direct_dns=args.block_direct_dns,
                strict_dot_resolver=args.strict_dot_resolver,
                dot_servers=args.dot_server,
                dot_server_name=args.dot_server_name,
                vpn_only=args.vpn_only,
                vpn_off=args.vpn_off,
                vpn_endpoints=args.vpn_endpoint,
                vpn_allow_lan=args.vpn_allow_lan,
                allow_foreign_tables=args.allow_foreign_table,
                remove_foreign_tables=args.remove_foreign_table,
                strict_upper_bound=strict_upper,
                action=action,
            )
            print_plan(plan)
            apply_plan(plan, args.approve, strict_upper_bound=strict_upper)
        elif args.command == "verify":
            findings = verify_all(show=True, strict_upper_bound=strict_upper)
            return 3 if findings else 0
        elif args.command == "status":
            status()
        elif args.command == "history":
            history()
        elif args.command == "block-ip":
            block_ip(args.target, args.ttl)
        elif args.command == "unblock-ip":
            unblock_ip(args.target)
        elif args.command == "list-blocked":
            list_blocked()
        elif args.command == "isolate-cgroup-lan":
            isolate_cgroup_lan(args.cgroup)
        elif args.command == "unisolate-cgroup-lan":
            unisolate_cgroup_lan()
        elif args.command == "rebind-cgroup-lan":
            rebind_cgroup_lan()
        elif args.command == "rollback":
            rollback(args.tx, args.approve)
        elif args.command == "monitor-now":
            report = monitor_report()
            persist_monitor(report, systemd_mode=args.systemd)
            if not args.systemd:
                show_monitor(report)
                return 3 if report["status"] in {"warning", "critical"} else 0
        elif args.command == "quarantine-on":
            quarantine_change(True, args.approve, strict_upper_bound=strict_upper, force_emergency=args.force_emergency)
        elif args.command == "quarantine-off":
            quarantine_change(False, args.approve, strict_upper_bound=strict_upper)
        else:
            stop("Unknown action")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Stop as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except SignalExit as exc:
        print(f"Interrupted by signal {exc.signum}", file=sys.stderr)
        raise SystemExit(exc.code)
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        raise SystemExit(130)