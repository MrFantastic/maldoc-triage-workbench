"""Embedded objects and links: oleobj, rtfobj (oletools), msodde, rtfdump.py.

Extraction always goes to a fresh folder under the output directory and every
extracted file is renamed with a .bin suffix so nothing can be opened by a
double-click.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field

from .. import edition
from ..core import outputcheck
from ..core.models import Finding, Severity, ToolResult
from ..core.safety import defang, sanitize_filename
from . import scripts


@dataclass
class Extracted:
    """A file extracted from an embedded object, saved with a .bin suffix."""
    path: str
    original_name: str
    size: int
    sha256: str
    kind: str

    @property
    def dangerous(self) -> bool:
        return (self.kind in scripts.DANGEROUS_TYPES
                or self.original_name.lower().endswith(scripts.DANGEROUS_EXT))


@dataclass
class ObjectsData:
    """What oleobj or rtfobj extracted, and any DDE links."""
    tool: str
    files: list[Extracted] = field(default_factory=list)
    dde: list[str] = field(default_factory=list)
    out_dir: str = ""


def _fresh_dir(base: str, label: str) -> str:
    n = 1
    while True:
        d = os.path.join(base, f"{label}_{n}" if n > 1 else label)
        if not os.path.exists(d):
            os.makedirs(d)
            return d
        n += 1


def _collect(out_dir: str) -> list[Extracted]:
    files = []
    for root, _dirs, names in os.walk(out_dir):
        for name in sorted(names):
            p = os.path.join(root, name)
            safe = p if p.lower().endswith(".bin") else p + ".bin"
            if safe != p:
                os.replace(p, safe)        # rename first: never leave an openable extension behind
            h, size, head = hashlib.sha256(), 0, b""
            with open(safe, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    if not head:
                        head = chunk[:4096]
                    h.update(chunk)
                    size += len(chunk)
            files.append(Extracted(safe, name, size, h.hexdigest(), scripts.magic_type(head)))
    return files


def extract(path: str, sha256: str, family: str, output_base: str) -> ToolResult:
    """oleobj for OLE/OOXML, rtfobj for RTF."""
    label = sanitize_filename(f"{sha256[:12]}_objects")
    out_dir = _fresh_dir(output_base, label)
    if family == "RTF":
        r = scripts.run_module("oletools.rtfobj", ["-s", "all", "-d", out_dir, path], "rtfobj",
                               cli_names=("rtfobj",))
        tool = "rtfobj"
    else:
        r = scripts.run_module("oletools.oleobj", ["-d", out_dir, path], "oleobj", cli_names=("oleobj",))
        tool = "oleobj"
    files = _collect(out_dir)
    if not files:
        try:
            os.rmdir(out_dir)
        except OSError:
            pass
    data = ObjectsData(tool, files, out_dir=out_dir if files else "")
    findings = []
    for f in files:
        sev = Severity.HIGH if f.dangerous else Severity.MEDIUM
        findings.append(Finding(tool, sev, f"Embedded {f.kind}: {f.original_name}",
                                f"{f.size:,} bytes, SHA256 {f.sha256}. Saved as {f.path}",
                                ref={"tab": "objects", "kb": "obj:embedded"}))
    text = r.text
    # oleobj also reports external relationships it finds
    for m in re.finditer(r"(?i)external (?:link|relationship)[^\n]*?((?:https?|ftp|file)://\S+|\\\\\S+)", text):
        findings.append(Finding(tool, Severity.HIGH, f"External link: {defang(m.group(1))[:80]}",
                                "Reported by oleobj.", ref={"tab": "objects", "kb": "obj:external"}))
    ok = r.returncode in (0, 1, 2) or bool(files)    # oletools return non-zero when objects are found
    return ToolResult(tool, ok, r.command, raw_output=defang(text), data=data, findings=findings,
                      error="" if ok else text[-500:])


def msodde(path: str) -> ToolResult:
    """Run msodde; each DDE/DDEAUTO field it reports becomes a High finding."""
    r = scripts.run_module("oletools.msodde", [path], "msodde", cli_names=("msodde",))
    text = r.text
    links: list[str] = []
    if "DDE Links:" in text:
        tail = text.split("DDE Links:", 1)[1]
        links = [ln.strip() for ln in tail.splitlines() if ln.strip()]
    findings = [Finding("msodde", Severity.HIGH, f"DDE field: {defang(link)[:90]}",
                        "DDE/DDEAUTO fields can launch commands when the document opens.",
                        ref={"tab": "objects", "kb": "office:dde"}) for link in links[:10]]
    ok = r.returncode == 0 or bool(links)
    error = ""
    if ok and "DDE Links:" not in text and not (r.timed_out or r.stopped):
        # msodde always prints this header before its results; without it we read nothing
        from . import versions
        ok = False
        error = outputcheck.failure("msodde", [ln for ln in text.splitlines() if ln.strip()][-5:],
                                    versions.version_of("oletools"), "no 'DDE Links:' section")
    elif not ok:
        error = ("stopped: timeout" if r.timed_out else "stopped by user" if r.stopped else
                 (r.stderr.strip().splitlines() or [f"exit code {r.returncode}"])[-1][:300])
    return ToolResult("msodde", ok, r.command, raw_output=defang(text),
                      data=links, findings=findings, error=error)


def rtfdump(path: str, objects_only: bool = False) -> scripts.RunResult:
    """Run rtfdump.py on the file (only the objects when objects_only), if it's installed."""
    tool = scripts.locate("rtfdump.py")
    if not tool:
        return scripts.RunResult("rtfdump.py", b"", f"rtfdump.py not found (optional; {edition.hint('tools')})", 127)
    args = ["-f", "O"] if objects_only else []
    return scripts.run_script(tool, args + [path], 120, "rtfdump.py")
