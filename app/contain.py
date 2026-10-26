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

This is cleanup and fault containment, not a security sandbox: code that compromises a
parser runs as the same user and could, for example, kill the launcher first. The
analysis VM is the security boundary.
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
    if not sys.platform.startswith("linux"):
        return False
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(36, 1, 0, 0, 0) == 0          # 36 = PR_SET_CHILD_SUBREAPER
    except (OSError, AttributeError):
        return False


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
    """argv: [--cpu S] [--mem BYTES] [--fsize BYTES] -- command args..."""
    limits = {"cpu": DEFAULT_CPU, "mem": MEMORY_LIMIT, "fsize": FILE_LIMIT}
    while argv and argv[0] != "--" and argv[0].lstrip("-") in limits and len(argv) > 1:
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
