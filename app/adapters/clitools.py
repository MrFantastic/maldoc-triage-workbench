"""Registry of every command-line tool the app wraps, plus a parser that turns
each tool's own -h output into a list of options.

Building the options form from the installed tool's help means the GUI always
offers exactly the flags that version supports. CURATED adds friendlier
labels, grouping and plain-English explanations for the flags analysts use
most; anything not curated still appears under "Other options".
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass

from .. import edition
from . import scripts


@dataclass
class ToolDef:
    """A command-line tool the command builder can drive: how to find it, run it and show its manual."""
    name: str
    kind: str                       # "script" (vendored .py) | "module" (pip package) | "peepdf"
    target: str                     # script filename or python module
    cli_names: tuple[str, ...] = ()
    takes_sample: bool = True
    man_flag: str | None = None     # Didier Stevens' tools: --man prints the full manual
    blurb: str = ""
    exclude: tuple[str, ...] = ()   # flags never offered (interactive, self-update, ...)


TOOLS: dict[str, ToolDef] = {t.name: t for t in [
    ToolDef("pdfid", "script", "pdfid.py", man_flag=None,
            blurb="Scans a PDF for keywords that indicate active content (JavaScript, auto-actions, embedded files)."),
    ToolDef("pdf-parser", "script", "pdf-parser.py", man_flag=None,
            blurb="Parses a PDF into its objects: search, select, follow references, decode streams."),
    ToolDef("oledump", "script", "oledump.py", man_flag="--man",
            blurb="Lists and dumps the streams of OLE files (doc/xls/ppt/msg and vbaProject.bin inside OOXML)."),
    ToolDef("zipdump", "script", "zipdump.py", man_flag="--man",
            blurb="Lists and dumps the files inside a zip / OOXML package."),
    ToolDef("rtfdump", "script", "rtfdump.py", man_flag="--man",
            blurb="Shows the nested group structure of RTF files and extracts embedded objects."),
    ToolDef("olevba", "module", "oletools.olevba", ("olevba",),
            blurb="Extracts and analyzes VBA and XLM macros: keywords, IOCs, decoding, deobfuscation."),
    ToolDef("mraptor", "module", "oletools.mraptor", ("mraptor",),
            blurb="Flags macros that run automatically and write files or execute commands."),
    ToolDef("oleid", "module", "oletools.oleid", ("oleid",),
            blurb="Summarizes risk indicators of an Office file."),
    ToolDef("oleobj", "module", "oletools.oleobj", ("oleobj",),
            blurb="Extracts embedded OLE objects and reports external relationships."),
    ToolDef("rtfobj", "module", "oletools.rtfobj", ("rtfobj",),
            blurb="Lists and extracts OLE objects embedded in RTF files."),
    ToolDef("msodde", "module", "oletools.msodde", ("msodde",),
            blurb="Finds DDE / DDEAUTO links in Office documents."),
    ToolDef("olemeta", "module", "oletools.olemeta", ("olemeta",), blurb="Shows OLE document metadata."),
    ToolDef("oletimes", "module", "oletools.oletimes", ("oletimes",), blurb="Shows OLE stream timestamps."),
    ToolDef("olemap", "module", "oletools.olemap", ("olemap",), blurb="Maps the sectors of an OLE file."),
    ToolDef("oledir", "module", "oletools.oledir", ("oledir",),
            blurb="Lists OLE directory entries, including orphans."),
    ToolDef("peepdf", "peepdf", "peepdf", ("peepdf",),
            blurb="PDF analysis: versions, suspicious elements, known CVEs. (Console commands are in the Console tab.)",
            exclude=("-i", "--interactive", "-u", "--update", "-s", "--load-script", "-C", "--command")),
]}


@dataclass
class CliOption:
    """One option parsed from a tool's -h output, with its curated label, group and explanation."""
    short: str = ""
    long: str = ""
    metavar: str = ""
    help: str = ""
    label: str = ""
    group: str = "Other options"
    explain: str = ""

    @property
    def flag(self) -> str:
        return self.long or self.short

    @property
    def takes_value(self) -> bool:
        return bool(self.metavar)

    @property
    def wants_path(self) -> bool:
        m = (self.metavar + " " + self.flag).upper()
        return any(k in m for k in ("FILE", "DIR", "OUTPUT", "YARA", "RULES", "PATH", "DUMP", "LOG"))

    @property
    def choices(self) -> list[str]:
        m = re.fullmatch(r"\{([^}]+)\}", self.metavar.strip())
        return m.group(1).split(",") if m else []


# ------------------------------------------------------------------ help parsing
_OPT_LINE = re.compile(r"^\s{1,8}(-[-\w].*)$")
_FORM = re.compile(r"^(--?[\w][\w-]*)(?:[ =](.+))?$")


def parse_help(text: str) -> list[CliOption]:
    """Parse optparse / argparse help into options (skips -h/--help/--version)."""
    opts: list[CliOption] = []
    cur: CliOption | None = None
    in_opts = False
    for raw in text.splitlines():
        line = raw.rstrip()
        low = line.strip().lower()
        if low in ("options:", "optional arguments:") or low.endswith(" options:"):
            in_opts = True
            continue
        m = _OPT_LINE.match(line)
        if m and (in_opts or line.startswith("  -")):
            in_opts = True
            spec_and_help = m.group(1)
            parts = re.split(r"\s{2,}", spec_and_help, maxsplit=1)
            spec = parts[0]
            help_text = parts[1].strip() if len(parts) > 1 else ""
            cur = CliOption(help=help_text)
            for form in [f.strip() for f in spec.split(", ")]:
                fm = _FORM.match(form)
                if not fm:
                    continue
                name, meta = fm.group(1), (fm.group(2) or "").strip()
                if name.startswith("--"):
                    cur.long = name
                else:
                    cur.short = name
                if meta and not cur.metavar:
                    cur.metavar = meta
            if cur.flag in ("-h", "--help", "--version"):
                cur = None
                continue
            opts.append(cur)
            continue
        if cur is not None and line.startswith(" " * 8) and line.strip() and not line.strip().startswith("-"):
            cur.help = (cur.help + " " + line.strip()).strip()
            continue
        if not line.strip():
            cur = None
    # de-duplicate (some tools print a flag twice)
    seen, out = set(), []
    for o in opts:
        if o.flag not in seen:
            seen.add(o.flag)
            out.append(o)
    return out


# ------------------------------------------------------------------ curated labels
# flag -> (label, group, explanation). Matched against short or long form.
COMMON, SELECT, OUTPUT, DECODE, ADV = "Common", "What to select", "Output", "Decoding & filters", "Advanced"

CURATED: dict[str, dict[str, tuple[str, str, str]]] = {
    "pdf-parser": {
        "-a": ("Statistics", COMMON,
               "Count objects by type and list which objects contain suspicious keywords. A good first look."),
        "-s": ("Search keyword", COMMON,
               "List objects whose dictionary contains this text, e.g. /JavaScript, /AA, /URI. Doesn't search inside "
               "streams."),
        "-o": ("Select object(s)", SELECT,
               "Show only these object ids (comma-separated). Combine with -f and -d to extract a stream."),
        "-r": ("Objects referencing", SELECT,
               "List objects that point to this object id: walks the reference chain backwards (who triggers this?)."),
        "-t": ("Select by /Type", SELECT, "Only objects of this type, e.g. /Action, /Annot, /Page, /EmbeddedFile."),
        "-e": ("Element types", SELECT,
               "Which elements to show: c=comments, x=xref, t=trailer, s=startxref, i=indirect objects."),
        "-f": ("Apply filters", DECODE,
               "Decompress / decode streams (FlateDecode, ASCIIHex, ASCII85, LZW, RunLength). Needed to read "
               "JavaScript."),
        "-w": ("Raw output", OUTPUT, "Show raw data instead of pdf-parser's formatted view."),
        "-d": ("Dump stream to file", OUTPUT,
               "Write the (filtered) stream of the selected object to a file. Use with -o and -f."),
        "-c": ("Show content", OUTPUT, "Show the content of objects without streams."),
        "-x": ("Extract malformed data", OUTPUT,
               "Write data that pdf-parser couldn't parse to a file. Useful for hidden content."),
        "-H": ("Hash streams", OUTPUT, "Show MD5/SHA256 of the stream of each selected object."),
        "-O": ("Parse object streams", DECODE,
               "Look inside /ObjStm compressed object streams too. Recommended for modern PDFs."),
        "-y": ("YARA rules", ADV, "Scan streams with YARA rules (a file or folder)."),
        "--yarastrings": ("Show YARA string matches", ADV, "Print which strings matched."),
        "--searchstream": ("Search inside streams", COMMON,
                           "Search decoded stream content (use with -f), e.g. eval, unescape, exportDataObject."),
        "--unfiltered": ("Search unfiltered streams", ADV, "Search raw (still compressed) stream bytes."),
        "--casesensitive": ("Case sensitive search", ADV, ""),
        "--regex": ("Search is a regex", ADV, ""),
        "--overridingfilters": ("Override filters", DECODE,
                                "Force a filter chain, e.g. 'FlateDecode' when /Filter is missing or lying."),
        "-k": ("Extract value of key", SELECT, "Print the value of this key from every object, e.g. /JS or /URI."),
        "-g": ("Generate Python program", ADV, "Generate a Python script that rebuilds the PDF."),
        "-v": ("Verbose", ADV, "Show malformed PDF elements."),
        "-n": ("No canonicalize", ADV, "Don't normalize names (shows obfuscation like /J#61vaScript as-is)."),
        "--decoders": ("Decoders", ADV, "Extra decoder plugins to apply."),
        "-D": ("Debug", ADV, ""),
    },
    "pdfid": {
        "-a": ("All names", COMMON, "List every /Name in the file, not just the suspicious set."),
        "-e": ("Extra data", COMMON, "Dates, entropy inside/outside streams, data after %%EOF."),
        "-f": ("Force", COMMON, "Scan even without a %PDF header."),
        "-n": ("Hide zero counts", OUTPUT, ""),
        "-d": ("Disarm", ADV, "Write a copy with /JavaScript, /OpenAction etc. renamed so they don't work."),
        "-p": ("Plugins", ADV, "Run plugins (comma-separated), e.g. plugin_triage.py."),
        "-m": ("Minimum score", ADV, "Only report plugin scores at or above this."),
        "-c": ("CSV output", OUTPUT, ""),
        "-s": ("Scan directory", ADV, "Treat the argument as a folder and scan every file."),
        "-o": ("Log to file", OUTPUT, ""),
        "-l": ("Literal filenames", ADV, ""),
    },
    "oledump": {
        "-s": ("Select stream", COMMON, "Stream index from the listing (e.g. 8, A3), or 'a' for all."),
        "-v": ("Decompress VBA", COMMON, "Show the macro source of a stream marked M. Use with -s."),
        "-d": ("Dump raw bytes", OUTPUT, "Output the selected stream's raw bytes."),
        "-x": ("Hex dump", OUTPUT, ""),
        "-a": ("ASCII dump", OUTPUT, "Hex + ASCII side by side."),
        "-A": ("ASCII dump (dedup)", OUTPUT, ""),
        "-S": ("Strings", OUTPUT, "Extract printable strings from the stream."),
        "-T": ("Head & tail", OUTPUT, "Show only the start and end of the output."),
        "-i": ("Stream info", OUTPUT, "Extra details: size, hashes, entropy."),
        "-p": ("Plugin", COMMON,
               "Run a plugin on the stream(s), e.g. plugin_vba_summary.py, plugin_biff.py (XLM), plugin_msg.py."),
        "--pluginoptions": ("Plugin options", COMMON,
                            "Options for the plugin, e.g. -x for plugin_biff to show only XLM."),
        "-e": ("Extract embedded file", OUTPUT, "Extract the file inside an Ole10Native stream (marked O)."),
        "-y": ("YARA rules", ADV, ""),
        "--yarastrings": ("Show YARA string matches", ADV, ""),
        "-D": ("Decoders", ADV, "Decoder plugins for XOR / Base64 etc."),
        "-M": ("Metadata", COMMON, "Show the document's metadata."),
        "-c": ("Calculate", ADV, "Extra calculated data (entropy, hashes) per stream."),
        "-j": ("JSON output", OUTPUT, ""),
        "-q": ("Quiet", OUTPUT, "Only plugin output."),
        "--vbadecompresscorrupt": ("Decompress corrupt VBA", ADV, "Try harder on damaged or stomped VBA streams."),
        "--storages": ("Include storages", ADV, ""),
    },
    "olevba": {
        "-a": ("Analysis only", COMMON, "Only the keyword table (AutoExec, Suspicious, IOCs), no source."),
        "-c": ("Code only", COMMON, "Only the macro source."),
        "-t": ("Triage mode", OUTPUT, "One-line summary per file."),
        "-d": ("Detailed mode", OUTPUT, ""),
        "-j": ("JSON output", OUTPUT, ""),
        "--decode": ("Show decoded strings", DECODE, "Decode Hex / Base64 / Dridex / StrReverse strings."),
        "--attr": ("Show attribute lines", ADV, ""),
        "--reveal": ("Reveal", DECODE, "Print the source with obfuscated strings replaced by their decoded values."),
        "--deobf": ("Deobfuscate expressions", DECODE, "Evaluate VBA string expressions (slow)."),
        "--show-pcode": ("Show p-code", ADV, "Disassemble the compiled p-code (needed to see stomped macros)."),
        "--no-pcode": ("Skip p-code", ADV, ""),
        "--no-xlm": ("Skip XLM", ADV, ""),
        "--relaxed": ("Relaxed", ADV, "Don't stop on parsing errors."),
        "-p": ("Password", COMMON, "Password for an encrypted document."),
        "--password": ("Password", COMMON, "Password for an encrypted document."),
        "-z": ("Zip password", ADV, "If the sample is inside a password-protected zip."),
    },
    "peepdf": {
        "-f": ("Force", COMMON, "Ignore parsing errors."),
        "-l": ("Loose mode", COMMON, "Parse objects not found in the xref table (malformed files)."),
        "-j": ("JSON output", OUTPUT, ""),
        "-x": ("XML output", OUTPUT, ""),
        "-g": ("No colors", OUTPUT, ""),
        "-c": ("Check on VirusTotal", ADV,
               "Looks up the hash on VirusTotal. Needs network access; sends the hash only."),
        "-m": ("Manual analysis", ADV, "Don't automatically analyze the document."),
    },
    "rtfobj": {"-s": ("Select object", COMMON, "Object index to save, or 'all'."),
               "-d": ("Output folder", OUTPUT, "Where extracted objects are written.")},
    "oleobj": {"-d": ("Output folder", OUTPUT, "Where extracted objects are written.")},
    "zipdump": {"-s": ("Select file", COMMON, "Index of the file in the zip."),
                "-d": ("Dump", OUTPUT, ""), "-x": ("Hex dump", OUTPUT, ""), "-a": ("ASCII dump", OUTPUT, ""),
                "-e": ("Extended info", COMMON, "Hashes, magic, compression details for each file."),
                "-y": ("YARA rules", ADV, "")},
    "rtfdump": {"-s": ("Select group", COMMON, "Group index from the listing."),
                "-H": ("Hex-decode", DECODE, "Decode the hex content of the selected group (embedded objects)."),
                "-f": ("Filter", SELECT, "Only show groups of this kind, e.g. O for objects."),
                "-d": ("Dump", OUTPUT, ""), "-x": ("Hex dump", OUTPUT, ""), "-a": ("ASCII dump", OUTPUT, ""),
                "-E": ("Extract", OUTPUT, "")},
    "msodde": {"-a": ("All fields", COMMON, "Show all fields, not only DDE."),
               "-d": ("DDE only", COMMON, ""), "-f": ("Filter mode", ADV, "")},
}


def curate(tool: str, opts: list[CliOption]) -> list[CliOption]:
    """Apply the curated labels and groups to a tool's options and drop the ones the GUI never offers."""
    table = CURATED.get(tool, {})
    excl = set(TOOLS[tool].exclude) if tool in TOOLS else set()
    out = []
    for o in opts:
        if o.short in excl or o.long in excl:
            continue
        if o.long == "--man" or (o.short == "-m" and "manual" in o.help.lower() and tool != "peepdf"):
            continue
        c = table.get(o.short) or table.get(o.long)
        if c:
            o.label, o.group, o.explain = c
        else:
            o.label = o.help.split(".")[0][:60] or o.flag
        out.append(o)
    order = {COMMON: 0, SELECT: 1, DECODE: 2, OUTPUT: 3, ADV: 4, "Other options": 5}
    out.sort(key=lambda o: order.get(o.group, 9))
    return out


# ------------------------------------------------------------------ running
def available(tool: str) -> str | None:
    """Path or command of the installed tool, or None if it can't be found."""
    t = TOOLS[tool]
    if t.kind == "script":
        return scripts.locate(t.target)
    if t.kind == "peepdf":
        from .peepdf_adapter import locate
        return locate()
    exe = scripts.locate_cli(*t.cli_names)
    if exe:
        return exe
    try:
        import importlib.util
        return t.target if importlib.util.find_spec(t.target.split(".")[0]) else None
    except (ImportError, ValueError):
        return None


def run(tool: str, args: list[str], timeout: int = 300) -> scripts.RunResult:
    """Run a tool with args (peepdf console commands that run code are refused)."""
    t = TOOLS[tool]
    if t.kind == "script":
        path = scripts.locate(t.target)
        if not path:
            return scripts.RunResult(t.target, b"", f"{t.target} not found ({edition.hint('tools')}).", 127)
        return scripts.run_script(path, args, timeout, t.target)
    if t.kind == "peepdf":
        from .peepdf_adapter import locate, refused
        why = _peepdf_refusal(args, refused)
        if why:
            return scripts.RunResult("peepdf " + " ".join(scripts.quote(a) for a in args), b"", why, 126)
        path = locate()
        if not path:
            return scripts.RunResult("peepdf", b"", f"peepdf not found ({edition.hint('peepdf')}).", 127)
        return scripts.run_script(path, args, timeout, "peepdf")
    return scripts.run_module(t.target, args, t.name, timeout, cli_names=t.cli_names)


def _peepdf_refusal(args: list[str], refused) -> str:
    """Apply the console blocklist to commands passed with -C/--command or a -s script file."""
    if any(a in ("-i", "--interactive") for a in args):
        return "Interactive mode (-i) needs a terminal. Use the Console tab, which runs commands with -s."
    commands: list[str] = []
    for i, a in enumerate(args):
        val = None
        for flag in ("-C", "--command", "-s", "--load-script"):
            if a == flag and i + 1 < len(args):
                val = args[i + 1]
            elif a.startswith(flag + "=") and flag.startswith("--"):
                val = a.split("=", 1)[1]
            if val is not None:
                if flag in ("-s", "--load-script"):
                    try:
                        with open(val, encoding="utf-8", errors="replace") as fh:
                            commands += fh.read(1_000_000).splitlines()
                    except OSError as exc:
                        return f"Could not read the script file: {exc}"
                else:
                    commands += val.split(";")
                break
    return refused([c for c in commands if c.strip()])


_help_cache: dict[str, tuple[list[CliOption], str]] = {}
_help_lock = threading.Lock()


def load_help(tool: str) -> tuple[list[CliOption], str]:
    """Return (curated options, raw help text). Cached per tool."""
    with _help_lock:
        if tool in _help_cache:
            return _help_cache[tool]
    r = run(tool, ["-h"], timeout=60)
    text = r.stdout.decode("utf-8", "replace") + ("\n" + r.stderr if r.stderr.strip() else "")
    opts = curate(tool, parse_help(text))
    with _help_lock:
        _help_cache[tool] = (opts, text)
    return opts, text


def manual(tool: str) -> str:
    """The tool's full manual (--man) when it has one, else its -h text."""
    t = TOOLS[tool]
    if t.man_flag:
        r = run(tool, [t.man_flag], timeout=60)
        text = r.stdout.decode("utf-8", "replace")
        if r.returncode == 0 and len(text) > 200:
            return text
    return load_help(tool)[1]


def args_to_values(opts: list[CliOption], args: list[str]) -> tuple[dict[str, str | bool], list[str]]:
    """Map an argument list onto known options: {flag: True | value}, plus leftovers."""
    by_name = {}
    for o in opts:
        if o.short:
            by_name[o.short] = o
        if o.long:
            by_name[o.long] = o
    values: dict[str, str | bool] = {}
    extra: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        name, eq, inline = a.partition("=")
        o = by_name.get(name)
        if o is None:
            extra.append(a)
        elif o.takes_value:
            if eq:
                values[o.flag] = inline
            elif i + 1 < len(args):
                values[o.flag] = args[i + 1]
                i += 1
        else:
            values[o.flag] = True
        i += 1
    return values, extra


def values_to_args(opts: list[CliOption], values: dict[str, str | bool]) -> list[str]:
    """Turn the command builder's form values into an argument list."""
    out: list[str] = []
    for o in opts:
        v = values.get(o.flag)
        if v is None or v is False or v == "":
            continue
        use = o.short or o.long
        if o.takes_value:
            out += [use, str(v)]
        else:
            out.append(use)
    return out
