"""Which Python environment provides the libraries the worker tasks import:
oletools, msoffcrypto-tool, jsbeautifier and yara-python.

REMnux installs each tool in its own environment (/opt/oletools,
/opt/msoffcrypto-tool, /opt/peepdf-3, ...) behind a launcher on PATH, and no other
Python can import from those. So in the REMnux edition a worker task that needs
one of these libraries runs under that environment's own interpreter (the one
named on the launcher's #! line) and uses REMnux's copy. If REMnux's copy is
missing or doesn't work, the app's own copy (from the installer) is used instead and
Tool status says why. The standard edition always uses its own copies.

Only the interpreter is borrowed: it runs this app's worker code (run.py --worker),
contained and time-limited like every other tool process.
"""
from __future__ import annotations

import importlib
import json
import os
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass

from .. import edition
from . import scripts

MIN_PYTHON = (3, 10)          # what the app's worker code needs


@dataclass(frozen=True)
class Library:
    """A library some worker tasks need, and where REMnux keeps its copy."""
    key: str
    modules: tuple[str, ...]     # must all import
    dist: str                    # distribution whose version is shown
    launchers: tuple[str, ...]   # REMnux launchers whose #! interpreter has it
    defaults: tuple[str, ...]    # REMnux's usual interpreter paths, if no launcher is found


LIBRARIES = {
    "oletools": Library("oletools", ("oletools.olevba", "oletools.oleid", "oletools.mraptor"), "oletools",
                        ("olevba", "mraptor"), ("/opt/oletools/bin/python3",)),
    "msoffcrypto": Library("msoffcrypto", ("msoffcrypto",), "msoffcrypto-tool",
                           ("msoffcrypto-tool", "olevba"),
                           ("/opt/msoffcrypto-tool/bin/python3", "/opt/oletools/bin/python3")),
    "jsbeautifier": Library("jsbeautifier", ("jsbeautifier",), "jsbeautifier",
                            ("peepdf",), ("/opt/peepdf-3/bin/python3",)),
    # REMnux gives Didier Stevens' tools a Python with yara-python
    "yara": Library("yara", ("yara",), "yara-python",
                    ("oledump.py", "pdf-parser.py", "pdfid.py"), ("/opt/didier-stevens/bin/python3",)),
}

# worker task -> the library it needs
TASK_LIBRARY = {
    "office.run": "oletools",
    "macro.analyse": "oletools",
    "macro.is_encrypted": "msoffcrypto",
    "macro.decrypt": "msoffcrypto",
    "js.beautify": "jsbeautifier",
    "yara.scan": "yara",
}


@dataclass(frozen=True)
class Provider:
    """Where one library comes from."""
    library: str
    available: bool = False
    version: str = ""
    python: str = ""     # interpreter for the tasks that need it; "" = this app's own worker
    source: str = ""     # e.g. "REMnux (/opt/oletools)" or "this app's Python (/path/.venv)"
    note: str = ""       # why REMnux's copy wasn't used, when it wasn't

    @property
    def external(self) -> bool:
        return bool(self.python)


_PROBE = r"""
import importlib, json, sys
import importlib.metadata as md
for m in sys.argv[1].split(","):
    importlib.import_module(m)
try:
    v = md.version(sys.argv[2])
except Exception:
    v = ""
print(json.dumps({"python": list(sys.version_info[:3]), "version": v}))
"""

_cache: dict[str, Provider] = {}
_lock = threading.Lock()


def provider(key: str) -> Provider:
    """Where the library `key` ("oletools", "msoffcrypto", "jsbeautifier") comes from. Cached."""
    with _lock:
        if key not in _cache:
            _cache[key] = _resolve(LIBRARIES[key])
        return _cache[key]


def clear() -> None:
    """Forget what was found, so it's looked up again."""
    with _lock:
        _cache.clear()


def worker_command(task: str) -> list[str]:
    """The command that runs a worker task: under REMnux's environment when the task needs
    a library REMnux provides (REMnux edition), else this app's own worker."""
    key = TASK_LIBRARY.get(task)
    if key:
        p = provider(key)
        if p.external:
            return [p.python, scripts.RUN_PY, "--worker"]
    return scripts.self_command("--worker")


def _use_remnux() -> bool:
    return (edition.is_remnux() and os.name != "nt" and not getattr(sys, "frozen", False)
            and os.path.isfile(scripts.RUN_PY) and not os.environ.get("MTW_IN_WORKER"))


def env_dir(interp: str) -> str:
    """/opt/oletools for /opt/oletools/bin/python3."""
    parent = os.path.dirname(interp)
    return os.path.dirname(parent) if os.path.basename(parent) == "bin" else parent


def _candidates(lib: Library) -> list[str]:
    found = [os.environ.get(f"MTW_{lib.key.upper()}_PYTHON", "")]
    for name in lib.launchers:
        for p in [shutil.which(name)] + [os.path.join(d, name) for d in scripts.SYSTEM_TOOL_DIRS]:
            if p and os.path.isfile(p):
                found.append(scripts.shebang_python(p) or "")
                break
    found += list(lib.defaults)
    own = os.path.abspath(sys.executable)
    out: list[str] = []
    for c in found:
        if c and os.path.abspath(c) != own and c not in out and os.path.isfile(c):
            out.append(c)
    return out


def _probe(interp: str, lib: Library) -> tuple[bool, str]:
    """(True, version) if interp can import the library and is new enough; else (False, why)."""
    try:
        r = subprocess.run([interp, "-I", "-c", _PROBE, ",".join(lib.modules), lib.dist],
                           capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"could not run it ({exc})"
    if r.returncode != 0:
        lines = (r.stderr or "").strip().splitlines()
        return False, (lines[-1][:200] if lines else f"exit code {r.returncode}")
    try:
        info = json.loads(r.stdout.strip().splitlines()[-1])
        pyver = tuple(int(x) for x in info["python"])
    except (ValueError, KeyError, IndexError, TypeError):
        return False, "unreadable reply"
    if pyver < MIN_PYTHON:
        need = ".".join(map(str, MIN_PYTHON))
        return False, f"Python {'.'.join(map(str, pyver))} is older than {need}"
    return True, str(info.get("version") or "")[:40]


def _local(lib: Library, note: str = "") -> Provider:
    """The copy this app's own Python can import, if any."""
    top = lib.modules[0].split(".")[0]
    try:
        importlib.import_module(top)
    except Exception:
        return Provider(lib.key, note=note)
    from .versions import dist_version
    return Provider(lib.key, True, dist_version(lib.dist) or "installed (version unknown)", "",
                    f"this app's Python ({sys.prefix})", note)


def _resolve(lib: Library) -> Provider:
    if not _use_remnux():
        return _local(lib)
    tried = []
    for interp in _candidates(lib):
        ok, info = _probe(interp, lib)
        if ok:
            return Provider(lib.key, True, info or "installed (version unknown)", interp,
                            f"REMnux ({env_dir(interp)})")
        tried.append(f"{interp}: {info}")
    note = ("REMnux's copy didn't work: " + "; ".join(tried)) if tried else "REMnux's copy wasn't found"
    return _local(lib, note)
