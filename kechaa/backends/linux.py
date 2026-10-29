"""Experimental Linux offline containment, using documented kernel interfaces.

No BPF program is loaded. These controls apply only to a trusted worker started by
the daemon. Linux validation in a disposable VM is a release requirement.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import pwd
import resource
import re
import select
import signal
import stat
import time
from contextlib import ExitStack
from pathlib import Path

from ..common import KechaaError, canonical, decode, read_bounded, require, within
from ..effects import file_digest, open_path

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long
LIBC.prctl.restype = ctypes.c_int
LL_CREATE, LL_ADD, LL_RESTRICT = 444, 445, 446
READ_FILE, READ_DIR, EXEC = 4, 8, 1
WRITE = 2 | 16 | 32 | 128 | 256 | 4096 | 8192 | 16384
HANDLED_FS = (1 << 16) - 1
CLONE_NEWNS = 0x00020000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
NAMESPACE_FLAGS = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET


def check(result: int, operation: str) -> int:
    if result < 0:
        error = ctypes.get_errno()
        raise KechaaError("kernel_control", f"Mandatory control {operation} failed: {os.strerror(error)}. No action may execute.", "compatibility_block")
    return result


def prctl(option: int, arg: int) -> None:
    check(LIBC.prctl(ctypes.c_int(option), ctypes.c_ulong(arg), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)), "prctl")


def landlock_abi() -> int:
    return check(LIBC.syscall(ctypes.c_long(LL_CREATE), ctypes.c_void_p(0), ctypes.c_size_t(0), ctypes.c_uint(1)), "Landlock ABI query")


def workspace_filesystems(roots: list[str]) -> list[dict]:
    """Require whole, separately mounted workspaces to exclude outside hardlinks.

    Mount administration is trusted. Bind mounts, shared devices, nested mounts
    and subdirectory contracts are not accepted as equivalent isolation.
    """
    mounts = []
    def unescape(value):
        return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)
    for line in read_bounded('/proc/self/mountinfo', 1048576).decode('utf-8').splitlines():
        left, right = line.split(' - ', 1)
        parts = left.split()
        mounts.append({'device': parts[2], 'root': unescape(parts[3]),
                       'path': unescape(parts[4]), 'type': right.split()[0]})
    result = []
    for root in roots:
        with open_path(root, directory=True) as fd:
            st = os.fstat(fd)
        device = f'{os.major(st.st_dev)}:{os.minor(st.st_dev)}'
        matches = [entry for entry in mounts if entry['device'] == device]
        require(len(matches) == 1 and matches[0]['path'] == root and matches[0]['root'] == '/'
                and matches[0]['type'] in ('ext4', 'tmpfs')
                and not any(entry['path'] != root and within(entry['path'], root) for entry in mounts),
                'workspace_filesystem',
                'Each confirmed workspace root must be the sole mount of a dedicated ext4 or tmpfs filesystem, without nested mounts. A shared host directory or bind mount permits pre-existing hardlink aliases and is refused. Prepare a quota-bounded volume inside the disposable VM.',
                'compatibility_block')
        result.append({'path': root, 'device': str(st.st_dev), 'inode': str(st.st_ino), 'type': matches[0]['type']})
    return result


def inspect(cgroup_root: str) -> dict:
    failures = []
    abi = 0
    arch = platform.machine()
    if arch not in ("x86_64", "aarch64"):
        failures.append("Only Linux x86_64 and aarch64 syscall tables are implemented.")
    else:
        try:
            abi = landlock_abi()
        except KechaaError as exc:
            failures.append(exc.message)
    if abi < 6:
        failures.append("Landlock ABI >= 6 is mandatory for filesystem, signal and abstract Unix-socket scope.")
    root = Path(cgroup_root)
    try:
        st = root.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                "cgroup_permissions", "Cgroup root must be a root-owned directory without group/world write access.")
        control = (root / "cgroup.subtree_control").read_text().split()
        if not {"cpu", "memory", "pids"} <= set(control):
            failures.append("Administrator must prepare a dedicated cgroup v2 subtree with cpu, memory, pids enabled.")
        if not (root / "cgroup.controllers").is_file():
            failures.append("Configured path is not a cgroup v2 subtree.")
    except (OSError, KechaaError) as exc:
        failures.append(f"Dedicated cgroup subtree unavailable: {exc}")
    if os.geteuid() != 0:
        failures.append("Experimental execution requires a root-owned daemon and a distinct unprivileged action UID.")
    if not hasattr(os, "pidfd_open"):
        failures.append("Python must expose pidfd_open for parent-death race checking.")
    return {"landlock_abi": abi, "control_plane_available": True, "execution_available": not failures,
            "candidate_profile": "linux-offline-experimental", "failures": failures,
            "runtime_checks": "seccomp, namespaces, read-only mounts, credential drop, cgroup limits and every Landlock rule are mandatory at each launch",
            "workspace_requirement": "dedicated ext4 or tmpfs filesystem; no bind aliases or nested mounts; checked at grant preparation and adoption",
            "kernel_validation": "Passing preflight does not verify this deployment; executed ARM64 scenarios are documented in docs/completion.md"}


class Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64), ("scoped", ctypes.c_uint64)]


class PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class MountAttributes(ctypes.Structure):
    _fields_ = [("attr_set", ctypes.c_uint64), ("attr_clr", ctypes.c_uint64),
                ("propagation", ctypes.c_uint64), ("userns_fd", ctypes.c_uint64)]


def restrict_mounts(envelope: dict) -> None:
    """Make this private namespace read-only, then reopen approved volumes.

    Landlock constrains content operations. Read-only mounts additionally fence
    metadata operations that Landlock does not handle. Narrow write subtrees
    retain the seccomp metadata denial instead of widening their permissions.
    """
    attributes = MountAttributes(1, 0, 0, 0)  # MOUNT_ATTR_RDONLY
    check(LIBC.syscall(442, ctypes.c_int(-100), ctypes.c_char_p(b'/'), ctypes.c_uint(0x8000),
                       ctypes.byref(attributes), ctypes.c_size_t(ctypes.sizeof(attributes))),
          'recursive read-only mount namespace')  # AT_RECURSIVE
    for root in envelope['workspace_filesystems']:
        if any(within(path, root['path']) for path in envelope['write']):
            with open_path(root['path'], directory=True) as fd:
                st = os.fstat(fd)
                require(str(st.st_dev) == root['device'] and str(st.st_ino) == root['inode'],
                        'workspace_changed', 'Workspace changed before mount restrictions.')
                attributes = MountAttributes(0, 1, 0, 0)
                check(LIBC.syscall(442, ctypes.c_int(fd), ctypes.c_char_p(b''), ctypes.c_uint(0x1000),
                                   ctypes.byref(attributes), ctypes.c_size_t(ctypes.sizeof(attributes))),
                      'approved workspace writable mount')  # AT_EMPTY_PATH


def restrict_files(envelope: dict, stack: ExitStack) -> None:
    require(landlock_abi() >= 6, "landlock_abi", "Landlock ABI >= 6 is required.", "compatibility_block")
    # Scope signal and abstract Unix sockets. TCP is denied in addition to a new
    # network namespace and a seccomp denial of all socket creation.
    attr = Ruleset(HANDLED_FS, 3, 3)
    ruleset = check(LIBC.syscall(LL_CREATE, ctypes.byref(attr), ctypes.sizeof(attr), 0), "Landlock create")
    stack.callback(os.close, ruleset)
    permissions: dict[str, int] = {}
    for path in envelope["read"]:
        permissions[path] = permissions.get(path, 0) | READ_FILE | READ_DIR
    for path in envelope["write"]:
        permissions[path] = permissions.get(path, 0) | WRITE
    for path in envelope["execute"]:
        permissions[path] = permissions.get(path, 0) | EXEC | READ_FILE
    permissions["/dev/null"] = READ_FILE | 2
    for path, rights in permissions.items():
        fd = stack.enter_context(open_path(path))
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            rights &= EXEC | READ_FILE | 2 | 16384 | 32768
        if rights:
            rule = PathRule(rights, fd)
            check(LIBC.syscall(LL_ADD, ruleset, 1, ctypes.byref(rule), 0), "Landlock add path rule")
    prctl(38, 1)  # PR_SET_NO_NEW_PRIVS
    check(LIBC.syscall(LL_RESTRICT, ruleset, 0), "Landlock restrict self")


class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]


def restrict_syscalls(*, allow_metadata: bool = False) -> None:
    # Numbers are the Linux UAPI native syscall ABI. Reject alternate ABIs before
    # inspecting syscall numbers; x86 x32 is rejected explicitly.
    arch = platform.machine()
    if arch == "x86_64":
        audit_arch, clone, clone3 = 0xC000003E, 56, 435
        denied = {
            16, 41, 53, 101, 155, 161, 163, 165, 166, 167, 168, 169, 172, 175, 176, 179,
            246, 248, 249, 250, 272, 298, 300, 303, 304, 308, 310, 311, 313, 319, 321, 323, 438,
            425, 426, 427, 428, 429, 430, 431, 432, 433, 440, 442, 448, 452, 467,
        }
        metadata = {90, 91, 92, 93, 94, 132, 188, 189, 190, 197, 198, 199, 235, 260, 261, 268, 280}
    elif arch == "aarch64":
        audit_arch, clone, clone3 = 0xC00000B7, 220, 435
        denied = {
            29, 198, 199, 117, 41, 51, 89, 39, 40, 224, 225, 142, 116, 105, 106,
            104, 28, 217, 218, 219, 97, 241, 294, 264, 265, 268, 270, 271, 273, 279, 280, 282, 438,
            425, 426, 427, 428, 429, 430, 431, 432, 433, 440, 442, 448, 452, 467,
        }
        metadata = {52, 53, 54, 55, 5, 6, 7, 14, 15, 16, 88}
    else:
        raise KechaaError("architecture", "Unsupported Linux syscall architecture.", "compatibility_block")
    if not allow_metadata:
        denied |= metadata
    else:
        denied.discard(452)  # fchmodat2 is fenced by the read-only mounts too.
    # BPF_LD|BPF_W|BPF_ABS, BPF_JMP|BPF_JEQ|BPF_K, BPF_RET|BPF_K.
    ins = [Filter(0x20, 0, 0, 4), Filter(0x15, 1, 0, audit_arch), Filter(0x06, 0, 0, 0x80000000),
           Filter(0x20, 0, 0, 0)]
    if arch == "x86_64":
        ins.extend([Filter(0x45, 0, 1, 0x40000000), Filter(0x06, 0, 0, 0x80000000)])
    # clone3 is denied with ENOSYS so maintained runtimes may fall back to clone.
    ins.extend([Filter(0x15, 0, 1, clone3), Filter(0x06, 0, 0, 0x00050000 | errno.ENOSYS)])
    # CPython's fopen path uses FIOCLEX to set close-on-exec. This only reduces
    # descriptor inheritance; every other ioctl remains denied, including
    # device controls and terminal input injection. Argument 1 is at offset 24.
    ioctl = 16 if arch == "x86_64" else 29
    ins.extend([Filter(0x15, 0, 4, ioctl), Filter(0x20, 0, 0, 24),
                Filter(0x15, 0, 1, 0x5451), Filter(0x06, 0, 0, 0x7FFF0000),
                Filter(0x06, 0, 0, 0x00050000 | errno.EPERM)])
    for number in sorted(denied):
        ins.extend([Filter(0x15, 0, 1, number), Filter(0x06, 0, 0, 0x00050000 | errno.EPERM)])
    # Legacy clone is allowed only without namespaces or CLONE_PARENT.
    ins.extend([Filter(0x15, 0, 3, clone), Filter(0x20, 0, 0, 16),
                Filter(0x45, 0, 1, NAMESPACE_FLAGS | 0x8000), Filter(0x06, 0, 0, 0x00050000 | errno.EPERM),
                Filter(0x06, 0, 0, 0x7FFF0000)])
    array = (Filter * len(ins))(*ins)
    program = Program(len(ins), array)
    check(LIBC.prctl(22, 2, ctypes.byref(program), 0, 0), "seccomp filter")


def cgroup_create(parent: str, grant_id: str, envelope: dict) -> Path:
    require(len(grant_id) == 48 and all(c in "0123456789abcdef" for c in grant_id), "cgroup_name", "Invalid action id.")
    path = Path(parent) / ("action-" + grant_id)
    path.mkdir(mode=0o700)
    limits = envelope["limits"]
    try:
        for name, value in {"memory.max": str(limits["memory_mb"] * 1048576), "memory.swap.max": "0",
                            "memory.oom.group": "1", "pids.max": str(limits["pids"]), "cpu.max": "100000 100000"}.items():
            (path / name).write_text(value)
        require((path / "cgroup.kill").is_file(), "cgroup_kill", "cgroup.kill is mandatory for action cleanup.")
    except BaseException:
        path.rmdir()
        raise
    return path


def kill_group(path: Path) -> None:
    (path / "cgroup.kill").write_text("1")


def accounting(path: Path) -> dict:
    """Bounded kernel counters, not a complete attempted-effect event stream."""
    try:
        cpu = dict(line.split() for line in read_bounded(path / 'cpu.stat', 16384).decode().splitlines())
        memory = dict(line.split() for line in read_bounded(path / 'memory.events', 16384).decode().splitlines())
        pids = dict(line.split() for line in read_bounded(path / 'pids.events', 16384).decode().splitlines())
        values = {'cpu_usage_usec': int(cpu['usage_usec']), 'oom_kills': int(memory['oom_kill']),
                  'pids_limit_events': int(pids['max']),
                  'memory_peak_bytes': int(read_bounded(path / 'memory.peak', 128))}
        require(all(0 <= value <= 9007199254740991 for value in values.values()),
                'accounting_range', 'Kernel accounting counter exceeds the supported range.')
        return {'complete': True, **values}
    except (OSError, ValueError, KeyError, KechaaError):
        return {'complete': False, 'reason': 'Kernel resource counters unavailable; enforcement outcome must not be inferred from missing counters.'}


def recover(parent: str) -> list[str]:
    recovered = []
    # Only exact names created by KECHAA are eligible for reconciliation.
    for path in Path(parent).iterdir():
        suffix = path.name.removeprefix("action-")
        if path.name.startswith("action-") and len(suffix) == 48 and all(c in "0123456789abcdef" for c in suffix):
            require(not path.is_symlink(), "cgroup_symlink", "Refusing a symlink in the dedicated cgroup subtree.")
            kill_group(path)
            # Removal can fail while the kernel is reaping; fail closed on startup.
            path.rmdir()
            recovered.append(path.name)
    return recovered


def worker(config: dict) -> int:
    """Run in a fresh, single-threaded interpreter; never call this in the daemon."""
    require(os.geteuid() == 0 and config["uid"] > 0, "worker_identity", "Worker requires root then a distinct unprivileged target UID.")
    parent = config["parent"]
    prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG
    require(os.getppid() == parent, "parent_lost", "Daemon disappeared before the worker was contained.")
    cgroup = Path(config["cgroup"])
    (cgroup / "cgroup.procs").write_text(str(os.getpid()))
    body = config["grant"]
    limits = body["effects"]["limits"]
    account = pwd.getpwuid(config["uid"])
    require(account.pw_gid > 0, "worker_group", "Target primary group cannot be root.")
    outer_pidfd = os.pidfd_open(os.getpid(), 0)
    # No network interfaces are configured in this namespace. Mount propagation
    # is private before any potential namespace-local operation.
    check(LIBC.unshare(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET), "isolation namespaces")
    check(LIBC.mount(None, b"/", None, ctypes.c_ulong(16384 | (1 << 18)), None), "private mount propagation")
    child = os.fork()
    if child:
        os.close(outer_pidfd)
        status_fd = config["status_fd"]
        os.close(status_fd)

        def deadline(_signal, _frame):
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass

        signal.signal(signal.SIGALRM, deadline)
        remaining = min(limits["wall_seconds"], body["expires_ms"] / 1000 - time.time())
        signal.setitimer(signal.ITIMER_REAL, max(0.001, remaining))
        _, status = os.waitpid(child, 0)
        signal.setitimer(signal.ITIMER_REAL, 0)
        return os.waitstatus_to_exitcode(status)
    # This child is PID 1 in its PID namespace. Kernel teardown kills remaining
    # descendants when it exits, even when they double-fork or change sessions.
    try:
        prctl(1, signal.SIGKILL)
        with ExitStack() as stack:
            restrict_mounts(body['effects'])
            cwd_fd = stack.enter_context(open_path(body["action"]["cwd"], directory=True))
            cwd_stat = os.fstat(cwd_fd)
            require({"device": str(cwd_stat.st_dev), "inode": str(cwd_stat.st_ino)} == body["inputs"]["cwd_identity"], "cwd_changed", "Working directory changed before launch.")
            executable = body["action"]["argv"][0]
            exe_fd = stack.enter_context(open_path(executable))
            require(file_digest(exe_fd) == body["inputs"]["executables"][executable], "executable_changed", "Executable changed before launch.")
            os.lseek(exe_fd, 0, os.SEEK_SET)
            require(os.read(exe_fd, 4) == b"\x7fELF", "script_entrypoint", "Use a configured ELF interpreter explicitly; shebang entrypoints are unsupported.", "compatibility_block")
            for path, expected in body["inputs"]["artifacts"].items():
                with open_path(path) as fd:
                    require(file_digest(fd, 16777216) == expected, "inputs_changed", "Input changed immediately before launch.")
            os.fchdir(cwd_fd)
            null = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            os.dup2(null, 0)
            os.close(null)
            os.umask(0o077)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
            resource.setrlimit(resource.RLIMIT_CPU, (limits["cpu_seconds"], limits["cpu_seconds"]))
            resource.setrlimit(resource.RLIMIT_FSIZE, (limits["file_bytes"], limits["file_bytes"]))
            os.setgroups([])
            os.setresgid(account.pw_gid, account.pw_gid, account.pw_gid)
            os.setresuid(config["uid"], config["uid"], config["uid"])
            # Credential changes clear PDEATHSIG, so reapply and check a pidfd to
            # close the parent-death race across the PID namespace boundary.
            prctl(1, signal.SIGKILL)
            poller = select.poll()
            poller.register(outer_pidfd, select.POLLIN)
            require(not poller.poll(0), "parent_lost", "Worker supervisor disappeared during credential drop.")
            os.close(outer_pidfd)
            prctl(4, 0)  # PR_SET_DUMPABLE
            restrict_files(body["effects"], stack)
            # Close preopened directory/ruleset descriptors before exec. The
            # executable FD is needed for fexecve; every FD is close-on-exec.
            status_fd = config["status_fd"]
            os.set_inheritable(status_fd, False)
            restrict_syscalls(allow_metadata=body['effects']['metadata_mutations'] == 'workspace')
            os.write(status_fd, b"controls_ready\n")
            os.execve(exe_fd, body["action"]["argv"], body["effects"]["environment"])
    except BaseException as exc:
        code = exc.code if isinstance(exc, KechaaError) else "worker_initialization"
        # Error text is diagnostic, never claimed to be an observed denied path.
        try:
            os.write(config["status_fd"], canonical({"error": code, "errno": getattr(exc, "errno", None),
                     "message": exc.message if isinstance(exc, KechaaError) else "Operating-system initialization or executable admission failed."}) + b"\n")
        except OSError:
            pass
        os._exit(126)
    os._exit(126)
