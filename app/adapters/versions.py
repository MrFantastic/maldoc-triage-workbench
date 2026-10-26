"""Versions of the tools the app runs, for Tool status, the report and finding notes.

Didier Stevens' scripts carry `__version__` (and `__date__`) near the top, read
here from the file without running it. Installed packages come from their
metadata. Results are cached; call clear() after tools are re-downloaded.
"""
from __future__ import annotations

import re
import subprocess
import sys
import threading

from . import scripts

_VERSION_RE = re.compile(r"""^__version__\s*=\s*['"]([^'"]+)['"]""", re.M)
_DATE_RE = re.compile(r"""^__date__\s*=\s*['"]([^'"]+)['"]""", re.M)
_PEEPDF_RE = re.compile(r"""^\s*VERSION\s*=\s*['"]([^'"]+)['"]""", re.M)


_cache: dict[str, str] = {}
_lock = threading.Lock()


def script_version(path: str | None) -> str:
    """'0.2.10 (2024/08/31)' from a script's __version__ / __date__, or ''."""
    if not path:
        return ""
    try:
        with open(path, "rb") as fh:
            head = fh.read(200_000).decode("utf-8", "replace")
    except OSError:
        return ""
    v = _VERSION_RE.search(head)
    d = _DATE_RE.search(head)
    if not v:
        return ""
    return v.group(1) + (f" ({d.group(1)})" if d else "")


def dist_version(*names: str) -> str:
    """Version of the first installed distribution among names, or ""."""
    from importlib.metadata import PackageNotFoundError, version
    for n in names:
        try:
            return version(n)
        except PackageNotFoundError:
            continue
        except Exception:
            continue
    return ""


def launcher_dist_version(script: str | None, *names: str) -> str:
    """Version of a package installed in a console script's own environment.

    REMnux installs tools such as peepdf and XLMMacroDeobfuscator in separate
    environments (/opt/<tool>/bin/python3) with a launcher on PATH, so their
    metadata isn't visible to this Python. Ask the launcher's interpreter instead
    (only the interpreter named on the launcher's #! line is run, never the tool)."""
    interp = scripts.shebang_python(script)
    if not interp:
        return ""
    code = ("import importlib.metadata as m, sys\n"
            "for n in sys.argv[1:]:\n"
            "    try:\n        print(m.version(n)); break\n"
            "    except Exception:\n        pass\n")
    try:
        r = subprocess.run([interp, "-I", "-c", code, *names], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return ""
    out = r.stdout.strip().splitlines()
    return out[0][:40] if r.returncode == 0 and out else ""


def _peepdf_version() -> str:
    v = dist_version("peepdf-3", "peepdf")
    if v:
        return v
    from .peepdf_adapter import locate
    path = locate()
    v = launcher_dist_version(path, "peepdf-3", "peepdf")
    if v:
        return v
    if path and path.lower().endswith(".py"):
        try:
            with open(path, "rb") as fh:
                m = _PEEPDF_RE.search(fh.read(200_000).decode("utf-8", "replace"))
            return m.group(1) if m else ""
        except OSError:
            return ""
    return ""


def _library_version(key: str) -> str:
    from . import toolenv
    p = toolenv.provider(key)
    return p.version if p.available else ""


def _detect() -> dict[str, str]:
    from .pdfid_adapter import locate_pdfid
    out = {
        "pdfid": script_version(locate_pdfid()),
        "pdf-parser": script_version(scripts.locate("pdf-parser.py")),
        "oledump": script_version(scripts.locate("oledump.py")),
        "zipdump": script_version(scripts.locate("zipdump.py")),
        "rtfdump": script_version(scripts.locate("rtfdump.py")),
        "oletools": _library_version("oletools"),
        "peepdf": _peepdf_version(),
        "XLMMacroDeobfuscator": dist_version("XLMMacroDeobfuscator") or launcher_dist_version(
            scripts.locate_cli("xlmdeobfuscator"), "XLMMacroDeobfuscator"),
        "msoffcrypto-tool": _library_version("msoffcrypto"),
        "jsbeautifier": _library_version("jsbeautifier"),
        "pikepdf": dist_version("pikepdf"),
        "pypdf": dist_version("pypdf"),
        "Python": sys.version.split()[0],
    }
    return out


def all_versions() -> dict[str, str]:
    """Versions of every known tool, detected once and cached."""
    with _lock:
        if not _cache:
            _cache.update(_detect())
        return dict(_cache)


def version_of(tool: str) -> str:
    """Version of one tool, or "" if unknown."""
    return all_versions().get(tool, "")


def clear() -> None:
    """Forget the cached versions, so they're detected again."""
    from . import toolenv
    with _lock:
        _cache.clear()
    toolenv.clear()
