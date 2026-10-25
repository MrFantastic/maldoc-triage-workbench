"""oledump.py (Didier Stevens) + olemap/oledir (oletools) adapter.

oledump handles OLE2 files directly and OOXML files by opening the OLE
containers inside the zip (vbaProject.bin etc.), using A1/A2… stream indices.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .. import edition
from ..core import outputcheck
from ..core.models import Finding, Severity, ToolResult
from . import scripts, versions

# "  8: M    1388 'Macros/VBA/ThisDocument'"   or   " A3: m     938 'VBA/Module1'"
_STREAM_RE = re.compile(r"^\s*([A-Za-z]?\d+):\s+([MmOE!.]?)\s*(\d+)\s+'(.*)'\s*$")
_CONTAINER_RE = re.compile(r"^([A-Za-z]):\s+(\S.*)$")
# oledump's normal message for an OOXML file without an OLE part (e.g. a .docx with no macros)
_NO_OLE_RE = re.compile(r"(?i)^warning:.*no ole file")


@dataclass
class Stream:
    """One stream from oledump's listing."""
    index: str
    indicator: str          # M = macro with code, m = macro attributes only, O = OLE10Native, ! = issue
    size: int
    name: str
    container: str = ""     # OOXML part holding this OLE file

    @property
    def meaning(self) -> str:
        return {"M": "VBA macro (code)", "m": "VBA module, attributes only",
                "O": "Embedded OLE object (Ole10Native)", "E": "Error parsing stream",
                "!": "Unusual: check with -i"}.get(self.indicator, "")


@dataclass
class StreamList:
    """oledump's stream listing, with OOXML container letters and any unrecognized lines."""
    streams: list[Stream] = field(default_factory=list)
    containers: dict[str, str] = field(default_factory=dict)
    unrecognized: list[str] = field(default_factory=list)   # output lines in no known shape


def locate() -> str | None:
    """Path of oledump.py, or None."""
    return scripts.locate("oledump.py")


def list_plugins(oledump_path: str | None) -> list[str]:
    """oledump plugin files next to oledump.py."""
    if not oledump_path:
        return []
    folder = os.path.dirname(oledump_path)
    out = []
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return []
    for n in names:
        if not (n.startswith("plugin_") and n.endswith(".py")):
            continue
        p = os.path.join(folder, n)
        try:
            with open(p, "rb") as fh:
                body = fh.read()
        except OSError:
            continue
        if b"AddPlugin" in body and b"PDFiD" not in body:
            out.append(p)
    return out


def parse_listing(text: str) -> StreamList:
    """Parse oledump's stream listing; lines in no known shape go to unrecognized."""
    out = StreamList()
    current = ""
    for line in text.splitlines():
        m = _STREAM_RE.match(line)
        if m:
            idx, ind, size, name = m.groups()
            container = out.containers.get(idx[0], "") if idx[0].isalpha() else ""
            out.streams.append(Stream(idx, ind.strip(), int(size), name, container))
            continue
        c = _CONTAINER_RE.match(line.strip())
        if c and len(c.group(1)) == 1:
            current = c.group(1)
            out.containers[current] = c.group(2).strip()
            continue
        if line.strip() and not _NO_OLE_RE.match(line.strip()):
            outputcheck.keep(out.unrecognized, line)
    return out


def findings_from(sl: StreamList) -> list[Finding]:
    """Findings for macro streams, embedded OLE10Native objects and unrecognized output."""
    out: list[Finding] = []
    if sl.unrecognized:
        out.append(outputcheck.note("oledump", sl.unrecognized, versions.version_of("oledump")))
    macro = [s for s in sl.streams if s.indicator == "M"]
    native = [s for s in sl.streams if s.indicator == "O"]
    if macro:
        out.append(Finding("oledump", Severity.MEDIUM, f"{len(macro)} stream(s) with VBA code",
                           ", ".join(s.name for s in macro[:10]), ref={"tab": "streams", "kb": "ole:macro_streams"}))
    if native:
        out.append(Finding("oledump", Severity.HIGH, f"{len(native)} embedded OLE10Native object(s)",
                           "Ole10Native streams carry embedded files (often a dropped payload). "
                           + ", ".join(s.name for s in native[:10]), ref={"tab": "streams", "kb": "ole:native"}))
    for s in sl.streams:
        low = s.name.lower()
        if "objectpool" in low and s.indicator != "O":
            out.append(Finding("oledump", Severity.MEDIUM, "ObjectPool storage present",
                               "Embedded OLE objects. Check the Objects & links tab.",
                               ref={"tab": "streams", "kb": "ole:objectpool"}))
            break
    return out


def run_list(path: str, timeout: int = 120) -> ToolResult:
    """Run oledump.py and parse its stream list (a failure if none of the output is recognized)."""
    tool = locate()
    if not tool:
        return ToolResult("oledump", False, "oledump.py", error=f"oledump.py not found ({edition.hint('tools')}).")
    r = scripts.run_script(tool, [path], timeout, "oledump.py")
    sl = parse_listing(r.stdout.decode("utf-8", "replace"))
    if sl.streams:
        ok, error = True, ""
    elif sl.unrecognized and r.returncode == 0 and not (r.timed_out or r.stopped):
        # output, but none of it was a stream listing: don't report "no streams"
        ok, error = False, outputcheck.failure("oledump", sl.unrecognized, versions.version_of("oledump"),
                                               "no stream listing")
    else:
        ok = r.returncode == 0 and not (r.timed_out or r.stopped)
        error = "" if ok else (scripts.error_summary(r.text) or f"exit code {r.returncode}")
    return ToolResult("oledump", ok, r.command, raw_output=r.text, data=sl, error=error,
                      findings=findings_from(sl) if ok else [])


def dump_stream(path: str, index: str, mode: str = "raw", plugin: str | None = None,
                plugin_options: str = "", decoder: str = "") -> scripts.RunResult:
    """mode: raw (-d) | vba (-v) | info (-i) | hexdump (-x) | strings (-S) | plugin (-p)"""
    tool = locate()
    if not tool:
        return scripts.RunResult("oledump.py", b"", "oledump.py not found", 127)
    args = ["-s", index] if index else []
    if mode == "raw":
        args.append("-d")
    elif mode == "vba":
        args.append("-v")
    elif mode == "info":
        args.append("-i")
    elif mode == "hexdump":
        args.append("-x")
    elif mode == "strings":
        args.append("-S")
    elif mode == "plugin" and plugin:
        args += ["-p", plugin]
        if plugin_options:
            args += ["--pluginoptions", plugin_options]
    if decoder:
        args += ["-D", decoder]
    return scripts.run_script(tool, args + [path], 120, "oledump.py")


def run_raw(path: str, args: list[str]) -> scripts.RunResult:
    """Run oledump.py with extra arguments (stream selection, plugins, dumps)."""
    tool = locate()
    if not tool:
        return scripts.RunResult("oledump.py", b"", "oledump.py not found", 127)
    return scripts.run_script(tool, args + [path], 180, "oledump.py")


def run_olemap(path: str) -> scripts.RunResult:
    """Run oletools' olemap (the OLE file's sector map)."""
    return scripts.run_module("oletools.olemap", [path], "olemap", cli_names=("olemap",))


def run_oledir(path: str) -> scripts.RunResult:
    """Run oletools' oledir (the OLE directory entries)."""
    return scripts.run_module("oletools.oledir", [path], "oledir", cli_names=("oledir",))
