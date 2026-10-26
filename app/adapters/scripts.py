"""Locate and run the command-line tools (Didier Stevens' scripts, oletools
CLIs, peepdf) with a hard timeout and an output cap.

Every tool runs as a separate process so a hostile sample that hangs or
crashes a parser can be killed without taking the app with it. In a frozen
(PyInstaller) build the app re-launches its own executable in a helper mode
(--run-script / --run-module / --run-callable / --worker), so the same
isolation and timeouts apply without a Python installation.

Processes are tagged with the GUI's session generation so that closing a
sample (or pressing Stop) kills everything still running for it, including anything
the tool started: on Linux/macOS every tool starts through run.py --contain in its own
session (app/contain.py), on Windows in its own Job Object (winjob.py).
"""
from __future__ import annotations

import contextlib
import io
import os
import re
import runpy
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

from ..contain import CONTAIN_FAILED

APP_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VENDOR_DIR = os.path.join(getattr(sys, "_MEIPASS", APP_ROOT), "vendor")

MAX_OUTPUT = 64 * 1024 * 1024     # never buffer more than 64 MB of tool output
DEFAULT_TIMEOUT = 180

RUN_PY = os.path.join(APP_ROOT, "run.py")
# Prepended to PYTHONPATH for every tool: makes JavaScript engines (STPyV8 / PyV8) unimportable,
# so no tool can evaluate a sample's JavaScript even when an engine is installed.
NOJS_DIR = os.path.join(getattr(sys, "_MEIPASS", APP_ROOT), "app", "adapters", "nojs")
_INPROC_LOCK = threading.Lock()

# ---------------------------------------------------------------- process tracking
_tls = threading.local()
_ACTIVE: dict[subprocess.Popen, int] = {}
_JOBS: dict[subprocess.Popen, int] = {}   # Windows: Job Object handle per process (guarded by _ACTIVE_LOCK)
_STOPPED: set[int] = set()          # pids killed on purpose (Stop / sample closed)
_ACTIVE_LOCK = threading.Lock()
PERSISTENT = -1                     # generation for jobs that outlive a sample (tool download, help)


def set_job_generation(generation: int) -> None:
    """Called by the GUI job runner in the worker thread before running a job."""
    _tls.generation = generation


def current_job_generation() -> int:
    """Session generation of the job running on this thread (PERSISTENT outside a job)."""
    return getattr(_tls, "generation", PERSISTENT)


def kill_generation(predicate) -> int:
    """Kill every running tool process whose generation matches predicate(gen)."""
    killed = 0
    with _ACTIVE_LOCK:
        targets = [p for p, g in _ACTIVE.items() if g != PERSISTENT and predicate(g)]
        for p in targets:
            _STOPPED.add(p.pid)
    for p in targets:      # in the background: on POSIX the escalation can take up to ~2 s
        threading.Thread(target=_kill_tree, args=(p,), daemon=True).start()
        killed += 1
    return killed


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill a tool process and everything it started."""
    if os.name == "nt":
        with _ACTIVE_LOCK:              # never terminate a job handle that's being closed
            job = _JOBS.get(proc, 0)
            if job:
                from . import winjob
                winjob.terminate(job)
        with contextlib.suppress(OSError):
            proc.kill()
        return
    # the launcher (run.py --contain) leads the group: SIGTERM makes it kill every descendant
    with contextlib.suppress(OSError):
        os.killpg(proc.pid, signal.SIGTERM)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and proc.poll() is None:
        time.sleep(0.05)
    with contextlib.suppress(OSError):
        os.killpg(proc.pid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        proc.kill()


def active_count() -> int:
    """Number of tool processes running now."""
    with _ACTIVE_LOCK:
        return len(_ACTIVE)


# script name -> (vendor sub-folder, extra PATH names)
KNOWN = {
    "pdf-parser.py": ("", ["pdf-parser.py", "pdf-parser"]),
    "oledump.py": ("oledump", ["oledump.py", "oledump"]),
    "zipdump.py": ("", ["zipdump.py", "zipdump"]),
    "rtfdump.py": ("", ["rtfdump.py", "rtfdump"]),
}


@dataclass
class RunResult:
    """The outcome of running an external tool."""
    command: str        # display form, e.g. 'oledump.py -s 3 -v "x.doc"'
    stdout: bytes
    stderr: str
    returncode: int
    timed_out: bool = False
    truncated: bool = False
    stopped: bool = False

    @property
    def text(self) -> str:
        out = self.stdout.decode("utf-8", "replace")
        if self.stderr.strip():
            out += ("\n" if out else "") + self.stderr
        if self.timed_out:
            out += "\n[stopped: timeout]"
        if self.truncated:
            out += f"\n[output truncated at {MAX_OUTPUT // (1024 * 1024)} MB]"
        return out


# Where REMnux puts Didier Stevens' tools, in case the GUI was started with a reduced PATH
SYSTEM_TOOL_DIRS = ("/usr/local/bin", "/usr/bin", "/opt/remnux-didier")


def vendor_enabled() -> bool:
    """The REMnux edition uses only the VM's installed tools, never a vendor/ copy."""
    from .. import edition
    return not edition.is_remnux()


def system_candidates(names) -> list[str]:
    """Paths where an installed copy of a tool may be: PATH, then the usual system folders.

    On Windows shutil.which only matches PATHEXT extensions, and .py is not one, so
    each PATH folder is also checked for the exact file name."""
    found = [w for w in (shutil.which(n) for n in names) if w]
    if os.name == "nt":
        path_dirs = [d for d in os.environ.get("PATH", "").split(os.pathsep) if d]
        return found + [os.path.join(d, n) for d in path_dirs for n in names]
    return found + [os.path.join(d, n) for d in SYSTEM_TOOL_DIRS for n in names]


def locate(script: str) -> str | None:
    """$MTW_<NAME>, then (standard edition) the vendor folder, then PATH and the usual system folders."""
    env = os.environ.get("MTW_" + script.split(".")[0].replace("-", "_").upper())
    sub, names = KNOWN.get(script, ("", [script]))
    candidates = [env or ""]
    if vendor_enabled():
        candidates += [os.path.join(VENDOR_DIR, sub, script), os.path.join(VENDOR_DIR, script)]
    candidates += system_candidates(names)
    for c in candidates:
        if c and os.path.isfile(c):
            return os.path.realpath(c)
    return None


def _script_dirs() -> list[str]:
    """Where pip puts console scripts (often not on PATH on Windows)."""
    import sysconfig
    dirs = []
    for scheme in (None, f"{os.name}_user", "nt_user", "posix_user"):
        try:
            d = sysconfig.get_path("scripts") if scheme is None else sysconfig.get_path("scripts", scheme)
        except KeyError:
            continue
        if d and d not in dirs:
            dirs.append(d)
    exe_dir = os.path.dirname(sys.executable)
    for d in (exe_dir, os.path.join(exe_dir, "Scripts")):
        if d not in dirs:
            dirs.append(d)
    return [d for d in dirs if os.path.isdir(d)]


def locate_cli(*names: str) -> str | None:
    """Find a console script on PATH or in Python's Scripts folder(s)."""
    for n in names:
        found = shutil.which(n)
        if found:
            return found
    exts = ("", ".exe", ".cmd", ".bat") if os.name == "nt" else ("",)
    for d in _script_dirs():
        for n in names:
            for ext in exts:
                p = os.path.join(d, n + ext)
                if os.path.isfile(p):
                    return p
    return None


def python_exe() -> str | None:
    """The interpreter for helper processes: this Python, or None when frozen."""
    if not getattr(sys, "frozen", False):
        return sys.executable
    return None


_PYTHON_NAME = re.compile(r"python(3(\.\d+)?)?", re.I)


def shebang_python(path: str | None) -> str | None:
    """The Python interpreter named on a script's #! line, if it is an absolute path
    to an existing python / python3 / python3.N; else None (and always None on Windows).

    REMnux installs each tool in its own environment and points the #! line of the
    tool (or of its launcher) at that environment's interpreter, e.g.
    #!/opt/didier-stevens/bin/python3. A '#!/usr/bin/env python3' line returns None."""
    if not path or os.name == "nt":
        return None
    try:
        with open(path, "rb") as fh:
            first = fh.readline(512).decode("utf-8", "replace").strip()
    except OSError:
        return None
    if not first.startswith("#!"):
        return None
    parts = first[2:].split()
    interp = parts[0] if parts else ""
    if (os.path.isabs(interp) and _PYTHON_NAME.fullmatch(os.path.basename(interp))
            and os.path.isfile(interp) and os.access(interp, os.X_OK)):
        return interp
    return None


def _in_vendor(path: str) -> bool:
    try:
        vendor = os.path.realpath(VENDOR_DIR)
        return os.path.commonpath([os.path.realpath(path), vendor]) == vendor
    except ValueError:          # different drives (Windows)
        return False


def script_python(script_path: str) -> str | None:
    """The interpreter a .py tool runs with (None: re-launch this app with --run-script).

    Our own vendored copies run with this app's Python. An installed copy (e.g. REMnux's
    Didier Stevens tools) runs with the interpreter its #! line names, so it gets the
    libraries its environment provides (REMnux's /opt/didier-stevens has yara-python,
    pyzipper, pefile, ...); without one, it runs with this app's Python."""
    if not _in_vendor(script_path):
        own = shebang_python(script_path)
        if own:
            return own
    return python_exe()


def self_command(mode: str, *args: str) -> list[str]:
    """Command that re-launches this app in a helper mode (works frozen or not)."""
    if getattr(sys, "frozen", False):
        return [sys.executable, mode, *args]
    return [sys.executable, RUN_PY, mode, *args]


def quote(a: str) -> str:
    """Quote one argument for a displayed command line."""
    from ..core.safety import quote_arg
    return quote_arg(a)


_quote = quote  # backwards-compatible alias


def run_script(script_path: str, args: list[str], timeout: int = DEFAULT_TIMEOUT,
               display_name: str | None = None, cwd: str | None = None, network: bool = False) -> RunResult:
    """Run a .py tool (or any executable) with args; capture stdout as bytes."""
    display = (display_name or os.path.basename(script_path)) + " " + " ".join(_quote(a) for a in args)
    is_py = script_path.lower().endswith(".py")
    if is_py:
        py = script_python(script_path)
        cmd = [py, script_path] + args if py else self_command("--run-script", script_path, *args)
    else:
        cmd = [script_path] + args
    return run_cmd(cmd, display, timeout, cwd=cwd, network=network)


def run_module(module: str, args: list[str], display_name: str, timeout: int = DEFAULT_TIMEOUT,
               cli_names: tuple[str, ...] = ()) -> RunResult:
    """Run an installed Python tool: its console script if present, else `python -m module`."""
    display = display_name + " " + " ".join(_quote(a) for a in args)
    py = python_exe()
    if py is None:      # frozen: run the bundled module inside our own executable
        return run_cmd(self_command("--run-module", module, *args), display, timeout)
    exe = locate_cli(*cli_names) if cli_names else None
    if exe:
        return run_cmd([exe] + args, display, timeout)
    return run_cmd([py, "-m", module] + args, display, timeout)


def error_summary(text: str, tail: int = 800) -> str:
    """A tool's failure output, led by the line that says what went wrong (for a Python
    traceback that's the last line, e.g. 'ModuleNotFoundError: ...'), then the tail."""
    lines = [ln.rstrip() for ln in (text or "").strip().splitlines() if ln.strip()]
    if not lines:
        return ""
    head = lines[-1].strip()
    if "Traceback (most recent call last)" in text:
        for ln in reversed(lines):
            if re.match(r"^[A-Za-z_][\w.]*(Error|Exception|Warning|Exit|Interrupt)\b", ln.strip()):
                head = ln.strip()
                break
    body = "\n".join(lines)[-tail:]
    return head if body == head else f"{head}\n\n{body}"


# What a tool may see of the app's environment: what a Python tool needs to start, find its
# files and print text (plus MTW_* settings). Everything else stays with the app: tokens and
# credentials, proxy settings, PYTHONPATH / PYTHONSTARTUP / PYTHONHOME, LD_PRELOAD, DISPLAY, ...
ENV_KEEP = frozenset({
    "PATH", "HOME", "USER", "LOGNAME", "USERNAME", "LANG", "LANGUAGE", "TZ", "TERM",
    "TMPDIR", "TMP", "TEMP", "LD_LIBRARY_PATH",
    # Windows: Python and its libraries need these to start and find their folders
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE", "APPDATA",
    "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "COMMONPROGRAMFILES",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS",
})
ENV_KEEP_PREFIXES = ("LC_", "MTW_", "_PYI", "_MEIPASS")     # locale, app settings, frozen builds


def tool_env() -> dict[str, str]:
    """Environment for tool processes: an allowlist of the app's variables (ENV_KEEP), UTF-8
    output, and only the JavaScript-engine blockers on PYTHONPATH."""
    env = {k: v for k, v in os.environ.items()
           if k.upper() in ENV_KEEP or k.upper().startswith(ENV_KEEP_PREFIXES)}
    env.update(PYTHONIOENCODING="utf-8", PYTHONUTF8="1", PYTHONPATH=NOJS_DIR)
    return env


def run_cmd(cmd: list[str], display: str, timeout: int = DEFAULT_TIMEOUT, cwd: str | None = None,
            input_bytes: bytes | None = None, max_output: int | None = None,
            limits: dict | None = None, network: bool = False) -> RunResult:
    """Run a command with a time limit and an output cap; Stop or opening another file kills it.

    limits overrides the per-tool resource limits ({"mem", "cpu", "fsize"}; tests use small ones):
    memory 3 GB, CPU time 2 x timeout + 30 s, files written at most 1 GB, no core dumps.
    Linux/macOS apply them in the launcher; Windows applies memory and CPU time in the Job Object.
    Unless network=True (a download the user started), Linux runs the tool with no network
    where that works on this system (contain.isolate_network; see tools_have_network())."""
    return _run_contained(cmd, display, timeout, cwd, input_bytes, max_output, limits,
                          no_net=not network and _isolation_works())


def _run_contained(cmd, display, timeout, cwd, input_bytes, max_output, limits, no_net: bool) -> RunResult:
    env = tool_env()
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # no console flashes on Windows
    windows = os.name == "nt"
    if windows:
        from . import winjob
        flags |= winjob.CREATE_SUSPENDED   # resumed only once it's inside its Job Object
    lim = {"mem": 3 * 1024 ** 3, "cpu": 2 * int(timeout) + 30, "fsize": 1024 ** 3}
    lim.update(limits or {})
    launch = cmd if windows else self_command("--contain", *(["--no-net"] if no_net else []),
                                              "--mem", str(lim["mem"]), "--cpu", str(lim["cpu"]),
                                              "--fsize", str(lim["fsize"]), "--", *cmd)
    limit = max_output or MAX_OUTPUT
    try:
        proc = subprocess.Popen(launch, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                                env=env, cwd=cwd, creationflags=flags, start_new_session=not windows)
    except OSError as exc:
        return RunResult(display, b"", f"Could not start: {exc}", 127)
    job = 0
    if windows:
        try:
            job = winjob.contain(int(proc._handle), lim["mem"], lim["cpu"])
        except OSError as exc:            # fail closed: the process was killed before it ran
            proc.wait()
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                if pipe is not None:
                    pipe.close()
            return RunResult(display, b"", f"Not run: the tool could not be started inside its Windows "
                             f"Job Object ({exc}).", CONTAIN_FAILED)
    with _ACTIVE_LOCK:
        _ACTIVE[proc] = current_job_generation()
        if job:
            _JOBS[proc] = job
    chunks: list[bytes] = []
    total = 0
    truncated = False

    def _reader():
        nonlocal total, truncated
        assert proc.stdout is not None
        while True:
            block = proc.stdout.read(65536)
            if not block:
                break
            room = limit - total
            if room > 0:
                chunks.append(block[:room])
                total += min(len(block), room)
            if len(block) > room:
                truncated = True

    err_chunks: list[bytes] = []

    def _err_reader():
        assert proc.stderr is not None
        for block in iter(lambda: proc.stderr.read(65536), b""):
            if sum(map(len, err_chunks)) < 1_000_000:
                err_chunks.append(block)

    readers = [threading.Thread(target=_reader, daemon=True),
               threading.Thread(target=_err_reader, daemon=True)]
    for t in readers:
        t.start()
    if input_bytes is not None and proc.stdin is not None:
        try:
            proc.stdin.write(input_bytes)
        except OSError:
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        timed_out = True
        proc.wait()
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE.pop(proc, None)
            job = _JOBS.pop(proc, 0)
            if job:                       # KILL_ON_JOB_CLOSE: anything the tool left running dies now
                winjob.close(job)
            stopped = proc.pid in _STOPPED
            _STOPPED.discard(proc.pid)
    for t in readers:
        t.join(5)
    for pipe in (proc.stdout, proc.stderr):
        if pipe is not None:
            pipe.close()
    err_text = b"".join(err_chunks).decode("utf-8", "replace")[-20000:]
    if stopped:
        err_text = (err_text + "\n" if err_text else "") + "Stopped by user."
    return RunResult(display, b"".join(chunks), err_text,
                     proc.returncode if proc.returncode is not None else -1, timed_out, truncated, stopped)


_net_lock = threading.Lock()
_net_state: list[bool] = []
_NET_PROBE = ("import os, sys\nopen(sys.argv[1], 'rb').close()\n"   # can still read the app's own files
              "print(os.readlink('/proc/self/ns/net'))")


def _isolation_works() -> bool:
    """Linux: True if a tool started with --no-net really gets its own network namespace and
    can still read this app's files. Checked once, for real, with a throwaway process."""
    if not sys.platform.startswith("linux") or getattr(sys, "frozen", False):
        return False
    with _net_lock:
        if not _net_state:
            r = _run_contained([sys.executable, "-I", "-c", _NET_PROBE, RUN_PY], "network check", 30,
                               None, None, None, None, no_net=True)
            theirs = r.stdout.decode("utf-8", "replace").strip()
            try:
                mine = os.readlink("/proc/self/ns/net")
            except OSError:
                mine = ""
            _net_state.append(r.returncode == 0 and theirs.startswith("net:") and theirs != mine)
        return _net_state[0]


def tools_have_network() -> bool | None:
    """Whether the tools the app starts can reach a network: False on Linux when each runs in
    its own empty network namespace, True on Linux when this system doesn't allow that, None on
    Windows / macOS (the app doesn't restrict the network there)."""
    if not sys.platform.startswith("linux") or getattr(sys, "frozen", False):
        return None
    return not _isolation_works()


def _run_inprocess(script_path: str, args: list[str], display: str) -> RunResult:
    """Run a script in this process. Only for tests and single-threaded helper
    processes: it swaps the process-wide stdout and argv."""
    out = io.BytesIO()
    text = io.TextIOWrapper(out, encoding="utf-8", errors="replace", write_through=True)
    err = io.StringIO()
    code = 0
    with _INPROC_LOCK:
        saved = sys.argv
        sys.argv = [script_path] + args
        try:
            with contextlib.redirect_stdout(text), contextlib.redirect_stderr(err):
                try:
                    runpy.run_path(script_path, run_name="__main__")
                except SystemExit as e:
                    code = int(e.code) if isinstance(e.code, int) else 0
                except Exception as e:
                    err.write(f"{type(e).__name__}: {e}")
                    code = 1
        finally:
            sys.argv = saved
            text.flush()
    return RunResult(display, out.getvalue(), err.getvalue(), code)


def magic_type(data: bytes) -> str:
    """Short human label for extracted content."""
    head = data[:16]
    if head.startswith(b"MZ"):
        return "Windows executable (PE)"
    if head.startswith(b"\x7fELF"):
        return "ELF executable"
    if head.startswith(bytes.fromhex("D0CF11E0A1B11AE1")):
        return "OLE2 (Office 97-2003 / MSI)"
    if head.startswith(b"PK\x03\x04"):
        return "Zip / OOXML"
    if head.startswith(b"%PDF"):
        return "PDF"
    if head.startswith(b"{\\rt"):
        return "RTF"
    if head.startswith(bytes.fromhex("4C0000000114020000000000C000000000000046")[:8]):
        return "Windows shortcut (LNK)"
    if head.startswith(b"\x89PNG"):
        return "PNG image"
    if head.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if head.startswith(b"GIF8"):
        return "GIF image"
    if head.startswith(b"\x01\x00\x09\x00") or head.startswith(b"\xd7\xcd\xc6\x9a"):
        return "Windows metafile"
    if head.startswith(b"Rar!"):
        return "RAR archive"
    if head.startswith(b"7z\xbc\xaf"):
        return "7-Zip archive"
    low = data[:512].lower()
    if b"<script" in low or b"<html" in low or b"<hta:" in low:
        return "HTML / HTA / script"
    if low.startswith(b"<?xml") or low.startswith(b"<"):
        return "XML"
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data[:1024])
    if data and printable / min(len(data), 1024) > 0.95:
        return "Text"
    return "Binary data"


DANGEROUS_TYPES = ("Windows executable (PE)", "ELF executable", "Windows shortcut (LNK)",
                   "HTML / HTA / script", "OLE2 (Office 97-2003 / MSI)", "Zip / OOXML", "RTF")
DANGEROUS_EXT = (".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
                 ".jse", ".wsf", ".hta", ".lnk", ".jar", ".msi", ".cpl", ".pif", ".reg", ".iso",
                 ".img", ".chm", ".docm", ".xlsm", ".xlam", ".pptm")
