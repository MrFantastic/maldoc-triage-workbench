"""run.py --contain -- <command...>: the launcher every tool process starts through on
Linux and macOS (on Windows, adapters/winjob.py puts each tool in a Job Object instead).

The launcher runs before any tool code, in a fresh single-threaded process, so it can
safely set things up that can't be done from the multi-threaded GUI:

  * it is the leader of the tool's own session and process group (the GUI starts it with
    start_new_session), so a timeout or Stop can signal the whole group at once
  * on Linux it registers as a child subreaper: if a descendant double-forks or calls
    setsid() to leave the group, it is re-parented to the launcher instead of init, so
    the launcher can still find and kill it. When the tool exits, or the launcher gets
    SIGTERM (timeout / Stop), every remaining descendant is killed before it exits.

  * it applies resource limits that the tool inherits: address space (MEMORY_LIMIT),
    CPU time (--cpu, set from the tool's timeout), the largest file it may write
    (FILE_LIMIT) and no core dumps. The GUI can't set these itself without affecting
    its own process.

  * with --no-net (every tool except a download you start), on Linux it moves into a new
    user + network namespace first: the tool then has no network at all, not even
    localhost. It needs no privileges where the kernel allows unprivileged user
    namespaces (Ubuntu / REMnux do, while denying them any capabilities); where it isn't
    allowed the tool runs with the VM's network, and Help -> Tool status says so.
    It also sets no_new_privs, so nothing the tool runs can gain privileges (setuid).

This is containment, not a full sandbox: code that compromises a parser still runs as
the same user, can read and write that user's files and could, for example, kill the
launcher first. The analysis VM is the security boundary.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys

CONTAIN_FAILED = 125     # the tool could not be started inside its container
MEMORY_LIMIT = 3 * 1024 ** 3
FILE_LIMIT = 1024 ** 3
DEFAULT_CPU = 600
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000


def apply_limits(mem: int = MEMORY_LIMIT, cpu: int = DEFAULT_CPU, fsize: int = FILE_LIMIT) -> list[str]:
    """Set RLIMIT_AS / CPU / FSIZE / CORE for this process and its children (never raise a hard
    limit). Returns the names of limits that couldn't be set (e.g. RLIMIT_AS on macOS)."""
    try:
        import resource
    except ImportError:
        return ["all"]
    failed = []
    for name, soft, hard_extra in (("RLIMIT_AS", mem, 0), ("RLIMIT_CPU", cpu, 5),
                                   ("RLIMIT_FSIZE", fsize, 0), ("RLIMIT_CORE", 0, 0)):
        which = getattr(resource, name, None)
        if which is None:
            failed.append(name)
            continue
        try:
            _cur, hard = resource.getrlimit(which)
            unlimited = hard == resource.RLIM_INFINITY
            new_hard = soft + hard_extra if unlimited else min(hard, soft + hard_extra)
            resource.setrlimit(which, (min(soft, new_hard), new_hard))
        except (ValueError, OSError):
            failed.append(name)
    return failed


def _set_subreaper() -> bool:
    """Linux: PR_SET_CHILD_SUBREAPER, so orphaned descendants are re-parented to us."""
    return sys.platform.startswith("linux") and _prctl(36, 1)     # 36 = PR_SET_CHILD_SUBREAPER


def _prctl(option: int, value: int) -> bool:
    try:
        import ctypes
        return ctypes.CDLL(None, use_errno=True).prctl(option, value, 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


def isolate_network() -> bool:
    """Linux: move this process (and everything it starts) into a new user + network
    namespace. The new network namespace has only a loopback interface, and it is down,
    so no connection can be made anywhere. For an ordinary user the new user namespace
    gets no uid mapping, so a program executed inside it has no capabilities (root keeps an
    identity mapping, see _map_ids). Must be called while single-threaded.
    Returns False, changing nothing, where the kernel doesn't allow it."""
    if not sys.platform.startswith("linux"):
        return False
    flags = CLONE_NEWUSER | CLONE_NEWNET
    uid = os.geteuid()
    try:
        if hasattr(os, "unshare"):                 # Python 3.12+
            os.unshare(flags)
        else:
            import ctypes
            if ctypes.CDLL(None, use_errno=True).unshare(flags) != 0:
                return False
    except (OSError, AttributeError):
        return False
    _map_ids(uid)
    return True


def _map_ids(uid: int) -> None:
    """Root only: map every uid/gid into the new user namespace unchanged, so root keeps its
    access to files other users own. An ordinary user needs no mapping (the kernel checks
    the real ids, so its own files stay readable; ids just show as 'nobody' inside), and
    Ubuntu / REMnux would refuse one anyway, with an audit message each time."""
    if uid != 0:
        return
    for path in ("/proc/self/uid_map", "/proc/self/gid_map"):
        try:
            with open(path, "w") as fh:
                fh.write("0 0 4294967295")
        except OSError:
            return


def descendants(root: int) -> list[int]:
    """Every live descendant of root, from /proc (Linux). Empty elsewhere."""
    children: dict[int, list[int]] = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return []
    for name in entries:
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", "rb") as fh:
                fields = fh.read().rsplit(b")", 1)[1].split()   # the command name may contain ')'
            children.setdefault(int(fields[1]), []).append(int(name))
        except (OSError, IndexError, ValueError):
            continue
    out, stack = [], [root]
    while stack:
        for child in children.get(stack.pop(), []):
            out.append(child)
            stack.append(child)
    return out


def _reap() -> None:
    """Collect exited children (as a subreaper, orphans' exit statuses come to us)."""
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def sweep() -> int:
    """Kill every remaining descendant (repeat: one may have forked meanwhile). Returns how many."""
    killed = 0
    me = os.getpid()
    for _ in range(50):
        targets = descendants(me)
        if not targets:
            break
        for pid in targets:
            try:
                os.kill(pid, signal.SIGKILL)
                killed += 1
            except OSError:
                pass
        _reap()
    _reap()
    return killed


def contain_main(argv: list[str]) -> int:
    """argv: [--no-net] [--cpu S] [--mem BYTES] [--fsize BYTES] -- command args..."""
    limits = {"cpu": DEFAULT_CPU, "mem": MEMORY_LIMIT, "fsize": FILE_LIMIT}
    no_net = False
    while argv and argv[0] != "--":
        if argv[0] == "--no-net":
            no_net, argv = True, argv[1:]
            continue
        if argv[0].lstrip("-") not in limits or len(argv) < 2:
            break
        try:
            limits[argv[0].lstrip("-")] = int(argv[1])
        except ValueError:
            sys.stderr.write(f"run.py --contain: bad value for {argv[0]}\n")
            return 2
        argv = argv[2:]
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        sys.stderr.write("run.py --contain: no command\n")
        return 2
    _set_subreaper()
    if no_net:
        isolate_network()        # best effort: see the module docstring
    if sys.platform.startswith("linux"):
        _prctl(38, 1)            # 38 = PR_SET_NO_NEW_PRIVS
    apply_limits(limits["mem"], limits["cpu"], limits["fsize"])

    def on_signal(signum, _frame):
        sweep()
        os._exit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, on_signal)
    try:
        child = subprocess.Popen(argv)      # inherits stdin/stdout/stderr and the environment
    except OSError as exc:
        sys.stderr.write(f"Could not start: {exc}\n")
        return 127
    rc = child.wait()
    sweep()                                  # a tool that leaves processes behind gets them killed
    return rc if rc >= 0 else 128 - rc
