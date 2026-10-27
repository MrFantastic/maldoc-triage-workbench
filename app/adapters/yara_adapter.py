"""YARA scanning with the analyst's own rules (nothing is bundled).

Two kinds of pass, all contained and time-limited like every other tool:

  * In a worker process, with yara-python: the whole file, and for ZIP-based Office
    files each part, decompressed within the same budgets as the Parts view. On REMnux
    the worker runs under REMnux's own Python that has YARA (toolenv.py).
  * Inside the formats, with Didier Stevens' tools' own -y option, which do the
    decoding: oledump (each OLE stream, and all VBA code together), pdf-parser (each
    object's decoded stream) and rtfdump (each RTF object).

Rules are a file, or a folder whose *.yar / *.yara files (in any sub-folder) are all
used together. Each match is a Medium finding. Matched text is defanged when shown.
"""
from __future__ import annotations

import os
import re
import tempfile
import zipfile
from dataclasses import dataclass, field

from ..core.models import Finding, Severity, ToolResult
from ..core.safety import command_line
from . import scripts

RULE_EXTS = (".yar", ".yara")
EXTERNALS = {"streamname": "", "VBA": False}     # the external variables oledump and rtfdump define
MAX_STRINGS = 10                                 # matched strings kept per rule and place
MATCH_TIMEOUT = 60                               # seconds per yara-python match


@dataclass
class YaraMatch:
    rule: str
    where: str                 # "whole file", "part word/document.xml", "stream A3 'VBA/Module1'", "object 12"
    found_by: str              # "yara", "oledump", "pdf-parser", "rtfdump"
    namespace: str = ""
    tags: list[str] = field(default_factory=list)
    meta: dict[str, str] = field(default_factory=dict)
    strings: list[str] = field(default_factory=list)   # "0x1a2b $a: 'preview'"
    decoder: str = ""


@dataclass
class YaraData:
    rules: str = ""
    rule_files: int = 0
    matches: list[YaraMatch] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)      # a pass that couldn't run, and why
    error: str = ""                                      # the rules don't compile (nothing ran)
    commands: list[str] = field(default_factory=list)


def rule_files(rules: str) -> list[str]:
    """The rule files a setting names: the file itself, or every *.yar / *.yara under a folder."""
    if not rules:
        return []
    if os.path.isfile(rules):
        return [os.path.abspath(rules)]
    found = []
    if os.path.isdir(rules):
        for root, dirs, files in os.walk(rules):
            dirs.sort()
            found += [os.path.join(root, f) for f in sorted(files) if f.lower().endswith(RULE_EXTS)]
    return [os.path.abspath(f) for f in found]


# ------------------------------------------------------------------ worker side (yara-python)


def _preview(data: bytes, limit: int = 60) -> str:
    text = repr(bytes(data[:limit]))[2:-1]
    return text + ("…" if len(data) > limit else "")


def _strings(match) -> list[str]:
    out = []
    for s in getattr(match, "strings", []) or []:
        if hasattr(s, "instances"):                       # yara-python 4.3+
            for inst in s.instances:
                out.append(f"{inst.offset:#x} {s.identifier}: '{_preview(inst.matched_data)}'")
        else:                                             # older: (offset, identifier, data)
            off, ident, data = s
            out.append(f"{off:#x} {ident}: '{_preview(data)}'")
        if len(out) >= MAX_STRINGS:
            break
    return out[:MAX_STRINGS]


def _found(m, where: str) -> YaraMatch:
    meta = {str(k): str(v)[:200] for k, v in (getattr(m, "meta", {}) or {}).items()}
    return YaraMatch(m.rule, where, "yara", getattr(m, "namespace", "") or "", list(getattr(m, "tags", []) or []),
                     meta, _strings(m))


def scan(path: str, files: list[str], zip_parts: bool) -> YaraData:
    """Worker task yara.scan: compile the rules, scan the whole file and (zip_parts) each ZIP part."""
    data = YaraData(rules=", ".join(files[:3]) + (" …" if len(files) > 3 else ""), rule_files=len(files))
    try:
        import yara  # type: ignore
    except ImportError as exc:
        data.error = f"YARA isn't installed for this Python ({exc})"
        return data
    try:
        rules = yara.compile(filepaths={f: f for f in files}, externals=EXTERNALS)
    except Exception as exc:        # yara.SyntaxError / yara.Error: name the file and line
        data.error = f"the rules don't compile: {exc}"
        return data
    try:
        for m in rules.match(filepath=path, timeout=MATCH_TIMEOUT):
            data.matches.append(_found(m, "whole file"))
    except Exception as exc:
        data.notes.append(f"whole-file scan failed: {exc}")
    if zip_parts:
        _scan_parts(path, rules, data)
    return data


def _scan_parts(path: str, rules, data: YaraData) -> None:
    from .container_adapter import MAX_PART_READ, MAX_PARTS, TOTAL_READ_BUDGET, ZipRejected, open_checked
    try:
        zf = open_checked(path)
    except (ZipRejected, zipfile.BadZipFile, OSError) as exc:
        data.notes.append(f"ZIP parts not scanned: {exc}")
        return
    budget, skipped = TOTAL_READ_BUDGET, 0
    with zf:
        for info in zf.infolist()[:MAX_PARTS]:
            if info.is_dir():
                continue
            if info.flag_bits & 0x1 or info.file_size > MAX_PART_READ or info.file_size > budget:
                skipped += 1
                continue
            budget -= info.file_size
            try:
                part = zf.read(info)
                for m in rules.match(data=part, timeout=MATCH_TIMEOUT,
                                     externals=dict(EXTERNALS, streamname=info.filename)):
                    data.matches.append(_found(m, f"part {info.filename}"))
            except Exception as exc:
                data.notes.append(f"part {info.filename}: {exc}")
    if skipped:
        data.notes.append(f"{skipped} encrypted or over-budget part(s) not scanned")


# ------------------------------------------------------------------ Didier Stevens' tools (-y)

_YARA_LINE = re.compile(r"^\s*YARA rule(?: \(stream decoder: (?P<dec>.*?)\))?: (?P<rule>\S+)(?: \((?P<ns>.*)\))?\s*$")
_OLE_STREAM = re.compile(r"^\s*(?P<id>[A-Z]?\d+):.*?'(?P<name>.*)'\s*$")
_PDF_OBJ = re.compile(r"^obj (\d+) (\d+)")
_RTF_ITEM = re.compile(r"^\s*(\d+)\s+Level\s+\d+")


def parse_tool_output(tool: str, text: str) -> list[YaraMatch]:
    """The YARA matches in oledump / pdf-parser / rtfdump -y output, with where each hit."""
    out: list[YaraMatch] = []
    where, pending = "", []
    for line in text.splitlines():
        m = _YARA_LINE.match(line)
        if m:
            hit = YaraMatch(m.group("rule"), where, tool, m.group("ns") or "", decoder=m.group("dec") or "")
            (pending if tool == "pdf-parser" else out).append(hit)
            continue
        if tool == "oledump":
            if line.startswith("All VBA source code"):
                where = "all VBA code"
            elif s := _OLE_STREAM.match(line):
                where = f"stream {s.group('id')} '{s.group('name')}'"
        elif tool == "pdf-parser" and (o := _PDF_OBJ.match(line)):
            for hit in pending:                          # pdf-parser prints the rule, then the object
                hit.where = f"object {o.group(1)}"
            out += pending
            pending = []
        elif tool == "rtfdump" and (r := _RTF_ITEM.match(line)):
            where = f"object {r.group(1)}"
    for hit in pending:
        hit.where = "PDF"
    return out + pending


def _tool_pass(tool: str, script: str, path: str, rules_arg: str, data: YaraData, shown_rules: str = "") -> None:
    located = scripts.locate(script)
    if not located:
        data.notes.append(f"{tool} not found, so {_INSIDE[tool]} weren't scanned")
        return
    r = scripts.run_script(located, ["-y", rules_arg, path], 300, script)
    # the @file list is temporary: show the rules folder instead, so the command can be rerun
    data.commands.append(r.command.replace(scripts.quote(rules_arg), scripts.quote(shown_rules)) +
                         "   # its .yar / .yara files" if shown_rules else r.command)
    text = r.stdout.decode("utf-8", "replace")
    data.matches += parse_tool_output(tool, text)
    lowered = (text + r.stderr).lower()
    if "requires the yara python module" in lowered:
        data.notes.append(f"{tool}: YARA isn't installed for the Python it runs with")
    elif r.timed_out:
        data.notes.append(f"{tool}: stopped after its time limit, so {_INSIDE[tool]} weren't all scanned")
    elif "traceback (most recent call last)" in lowered or r.returncode not in (0, 1):
        why = (scripts.error_summary(r.text).splitlines() or [f"exit code {r.returncode}"])[0][:300]
        data.notes.append(f"{tool} couldn't scan {_INSIDE[tool]}: {why}")


_INSIDE = {"oledump": "OLE streams and VBA code", "pdf-parser": "PDF streams", "rtfdump": "RTF objects"}
_TOOLS = {"PDF": [("pdf-parser", "pdf-parser.py")], "OLE": [("oledump", "oledump.py")],
          "OOXML": [("oledump", "oledump.py")], "RTF": [("rtfdump", "rtfdump.py")]}


def run(path: str, family: str, files: list[str]) -> ToolResult:
    """Scan with every pass that applies. family: the Family's name ("PDF", "OLE", "OOXML", "RTF", "ZIP", ...)."""
    from . import isolated
    if not files:
        return ToolResult("yara", False, "yara", error="no YARA rule files (*.yar, *.yara) found")
    data: YaraData = isolated.yara_scan(path, files, family in ("OOXML", "ZIP"))
    if len(files) <= 3:
        data.commands.insert(0, command_line(["yara", "-s", *files, path]))
    else:
        folder = os.path.commonpath(files)
        data.commands.insert(0, command_line(["yara", "-s", os.path.join(folder, "*.yar"), path])
                             + f"   # {len(files)} rule files under {folder}")
    if data.error:
        return ToolResult("yara", False, data.commands[0], error=data.error, data=data)
    rules_arg, listing, shown = files[0], "", ""
    if len(files) > 1:                       # Didier's tools take a list of rule files as @file
        shown = os.path.commonpath(files)
        fd, listing = tempfile.mkstemp(prefix="mtw-yara-", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(files) + "\n")
        rules_arg = "@" + listing
    try:
        for tool, script in _TOOLS.get(family, []):
            _tool_pass(tool, script, path, rules_arg, data, shown)
    finally:
        if listing:
            os.unlink(listing)
    return ToolResult("yara", True, "\n".join(data.commands), raw_output=render(data), data=data,
                      findings=findings_from(data))


def render(d: YaraData) -> str:
    lines = [f"Rules: {d.rule_files} file(s)"]
    for m in d.matches:
        lines.append(f"{m.rule:<40} {m.where}  [{m.found_by}{' / ' + m.decoder if m.decoder else ''}]")
        lines += [f"    {s}" for s in m.strings]
    lines += [f"note: {n}" for n in d.notes]
    return "\n".join(lines)


def findings_from(d: YaraData) -> list[Finding]:
    """One Medium finding per rule that matched, listing everywhere it matched."""
    by_rule: dict[str, list[YaraMatch]] = {}
    for m in d.matches:
        by_rule.setdefault(m.rule, []).append(m)
    out = []
    for rule, hits in by_rule.items():
        places = list(dict.fromkeys(f"{h.where} ({h.found_by}{', ' + h.decoder if h.decoder else ''})"
                                    for h in hits))
        meta = hits[0].meta
        about = meta.get("description") or meta.get("desc") or ""
        detail = (f"{about}\n" if about else "") + "Matched in: " + "; ".join(places[:10]) + (
            f" and {len(places) - 10} more" if len(places) > 10 else "")
        out.append(Finding("yara", Severity.MEDIUM, f"YARA rule {rule} matched", detail,
                           ref={"kb": "yara:match", "tab": "yara"}))
    return out
