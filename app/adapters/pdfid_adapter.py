"""Adapter around Didier Stevens' pdfid.py (vendored, unmodified).

Two paths are used together:
  * structured: pdfid.PDFiD() returns an XML document we parse into a table
  * CLI parity: pdfid's own Main() is run in-process with the same flags the
    analyst picked, and its stdout is captured verbatim (needed for plugins,
    CSV output and anything we don't model).
If pdfid can't be imported (e.g. a non-Python wrapper on PATH), the CLI is
run as a subprocess instead and the structured table is derived from it.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
import shutil
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from types import ModuleType
from xml.dom import minidom

from .. import edition
from ..core import outputcheck
from ..core.models import Finding, Severity, ToolResult
from ..core.safety import command_line, quote_arg, safe_output_path

APP_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VENDOR_DIR = os.path.join(getattr(sys, "_MEIPASS", APP_ROOT), "vendor")

# pdfid keeps module-level state and we redirect process-wide stdout, so runs are serialised.
_PDFID_LOCK = threading.Lock()

# Keyword severities, based on what each one enables in a malicious PDF.
KEYWORD_SEVERITY = {
    "/JS": Severity.HIGH, "/JavaScript": Severity.HIGH, "/OpenAction": Severity.HIGH,
    "/AA": Severity.HIGH, "/Launch": Severity.HIGH, "/EmbeddedFile": Severity.HIGH,
    "/JBIG2Decode": Severity.HIGH, "/RichMedia": Severity.HIGH, "/XFA": Severity.HIGH,
    "/AcroForm": Severity.MEDIUM, "/ObjStm": Severity.LOW, "/Encrypt": Severity.MEDIUM,
    "/URI": Severity.MEDIUM, "/SubmitForm": Severity.MEDIUM, "/GoToR": Severity.MEDIUM,
    "/GoToE": Severity.MEDIUM, "/Colors > 2^24": Severity.MEDIUM,
}

KEYWORD_EXPLANATION = {
    "/JS": "JavaScript code is present.",
    "/JavaScript": "JavaScript action or name tree is present.",
    "/OpenAction": "An action runs automatically when the document opens.",
    "/AA": "Additional actions trigger automatically on page or field events.",
    "/Launch": "The document can launch external programs or files.",
    "/EmbeddedFile": "The PDF carries an embedded file (possible dropped payload).",
    "/JBIG2Decode": "JBIG2 filter, historically used by several exploits.",
    "/RichMedia": "Embedded Flash / rich media.",
    "/XFA": "XML Forms Architecture; can carry scripts and has an exploit history.",
    "/AcroForm": "Interactive form; often paired with JavaScript.",
    "/ObjStm": "Object streams (normal in PDF 1.5+ from Word, Chrome, Acrobat). Only notable "
                "combined with other indicators, since they can hide objects from simple parsers.",
    "/Encrypt": "Encrypted content; analysis may be incomplete.",
    "/URI": "Contains links (check the URLs).",
    "/SubmitForm": "Form data can be submitted to a remote server.",
    "/GoToR": "Jumps to a remote document.",
    "/GoToE": "Jumps to an embedded document.",
    "/Colors > 2^24": "Abnormally large /Colors value, associated with an Acrobat overflow exploit.",
}

STRUCTURAL = {"obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref", "/Page"}


@dataclass
class PdfidOptions:
    """pdfid options chosen in the pdfid tab."""
    all_names: bool = False      # -a
    extra: bool = True           # -e  (dates, entropy, data after %%EOF)
    force: bool = False          # -f
    nozero: bool = False         # -n
    plugins: list[str] = field(default_factory=list)   # -p  (full paths)
    minimum_score: float = 0.0   # -m
    csv: bool = False            # -c

    def cli_args(self) -> list[str]:
        args: list[str] = []
        if self.all_names:
            args.append("-a")
        if self.extra:
            args.append("-e")
        if self.force:
            args.append("-f")
        if self.nozero:
            args.append("-n")
        if self.plugins:
            args += ["-p", ",".join(self.plugins)]
            if self.minimum_score:
                args += ["-m", str(self.minimum_score)]
        if self.csv:
            args.append("-c")
        return args


@dataclass
class KeywordRow:
    """One pdfid keyword count, with its rating and explanation."""
    name: str
    count: int
    hex_count: int
    severity: Severity
    explanation: str


@dataclass
class PdfidData:
    """pdfid's results: header, keyword counts, extra data, dates and plugin output."""
    header: str = ""
    is_pdf: bool = False
    keywords: list[KeywordRow] = field(default_factory=list)
    extra: dict[str, str] = field(default_factory=dict)   # entropy, EOF data, etc.
    dates: list[tuple[str, str]] = field(default_factory=list)
    error: str = ""
    unrecognized: list[str] = field(default_factory=list)  # keywords / lines this app doesn't know
    plugin_results: list = field(default_factory=list)     # [plugin name, score, instructions]
    plugin_errors: list = field(default_factory=list)      # pdfid's "Error ... plugin: X" lines


# --------------------------------------------------------------------------- locating


def locate_pdfid() -> str | None:
    """Find pdfid.py: $MTW_PDFID, bundled vendor/, then PATH (REMnux installs it there)."""
    from . import scripts
    candidates = [os.environ.get("MTW_PDFID", "")]
    if scripts.vendor_enabled():
        candidates.append(os.path.join(VENDOR_DIR, "pdfid.py"))
    candidates += scripts.system_candidates(("pdfid.py", "pdfid"))
    for c in candidates:
        if c and os.path.isfile(c):
            return os.path.realpath(c)
    return None


def list_plugins(pdfid_path: str | None) -> list[str]:
    """pdfid plugin files next to pdfid.py."""
    if not pdfid_path:
        return []
    folder = os.path.dirname(pdfid_path)
    try:
        names = sorted(n for n in os.listdir(folder)
                       if n.startswith("plugin_") and n.endswith(".py"))
    except OSError:
        return []
    out = []
    for n in names:
        path = os.path.join(folder, n)
        try:
            with open(path, "rb") as fh:
                if b"PDFiD" in fh.read():   # skip oledump/other plugins sharing a folder (REMnux)
                    out.append(path)
        except OSError:
            pass
    return out


_PLUGIN_ARGS_DEFAULT = 2   # pdfid 0.2.x: cPlugin(oPDFiD, options.pluginoptions)


def _plugin_call_args(pdfid_path: str) -> int:
    """How many arguments this pdfid passes when it creates a plugin (read from its source)."""
    import ast
    try:
        with open(pdfid_path, "rb") as fh:
            tree = ast.parse(fh.read())
    except (OSError, SyntaxError, ValueError):
        return _PLUGIN_ARGS_DEFAULT
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "cPlugin":
            return len(node.args)
    return _PLUGIN_ARGS_DEFAULT


def plugin_status(pdfid_path: str | None, plugin_path: str) -> tuple[bool, str, str]:
    """(compatible, plugin name, reason) without running the plugin: compares the arguments its
    constructor accepts with what this pdfid passes. Didier Stevens' repository has plugins
    written for older pdfid versions; pdfid stops at the first one that fails to start."""
    import ast
    try:
        with open(plugin_path, "rb") as fh:
            tree = ast.parse(fh.read())
    except (OSError, SyntaxError, ValueError) as exc:
        return False, os.path.basename(plugin_path), f"can't be read ({exc})"
    passed = _plugin_call_args(pdfid_path) if pdfid_path else _PLUGIN_ARGS_DEFAULT
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        if not any(isinstance(b, ast.Name) and b.id == "cPluginParent" for b in cls.bases):
            continue
        name = os.path.basename(plugin_path)
        for item in cls.body:
            if isinstance(item, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "name" for t in item.targets) \
                    and isinstance(item.value, ast.Constant) and isinstance(item.value.value, str):
                name = item.value.value
        init = next((i for i in cls.body if isinstance(i, ast.FunctionDef) and i.name == "__init__"), None)
        if init is None:
            return True, name, ""
        params = init.args.args[1:]                      # minus self
        required = len(params) - len(init.args.defaults)
        ok = required <= passed and (init.args.vararg is not None or passed <= len(params))
        reason = "" if ok else (f"written for an older pdfid: it accepts {len(params)} argument(s) when "
                                f"created, but this pdfid passes {passed}, so it fails to start")
        return ok, name, reason
    return False, os.path.basename(plugin_path), "no pdfid plugin class found in it"


_module_cache: dict[str, ModuleType] = {}


def clear_cache() -> None:
    """Forget imported pdfid modules (after the tools were re-downloaded)."""
    _module_cache.clear()


def _import_pdfid(path: str) -> ModuleType | None:
    if path in _module_cache:
        return _module_cache[path]
    try:
        with open(path, "rb") as fh:
            head = fh.read(200)
        if not (path.endswith(".py") or b"python" in head.split(b"\n", 1)[0]):
            return None
        spec = importlib.util.spec_from_file_location("mtw_vendor_pdfid", path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception:
        return None
    if not hasattr(mod, "PDFiD"):
        return None
    _module_cache[path] = mod
    return mod


# --------------------------------------------------------------------------- parsing


def known_keyword(name: str) -> bool:
    """True if the app has a rating or an explanation for this pdfid keyword."""
    return name in KEYWORD_SEVERITY or name in KEYWORD_EXPLANATION or name in STRUCTURAL


def parse_pdfid_xml(xml_text: str, all_names: bool = False) -> PdfidData:
    """Turn PDFiD()'s XML into PdfidData. Tolerant of version differences: a keyword this
    app doesn't know is still listed (rated Info) and recorded in data.unrecognized,
    unless all_names (-a) was asked for, where every name in the file is listed."""
    out = PdfidData()
    doc = minidom.parseString(xml_text)
    root = doc.documentElement
    out.header = root.getAttribute("Header")
    out.is_pdf = root.getAttribute("IsPDF") == "True"
    if root.getAttribute("ErrorOccured") == "True":
        out.error = root.getAttribute("ErrorMessage")
    skip = {"Version", "Filename", "Header", "IsPDF", "ErrorOccured", "ErrorMessage"}
    for i in range(root.attributes.length):
        attr = root.attributes.item(i)
        if attr.name not in skip and attr.value != "":
            out.extra[attr.name] = attr.value
    for kw in root.getElementsByTagName("Keyword"):
        name = kw.getAttribute("Name")
        count = int(kw.getAttribute("Count") or 0)
        hexc = int(kw.getAttribute("HexcodeCount") or 0)
        out.keywords.append(_row(name, count, hexc))
        if not all_names and not known_keyword(name):
            out.unrecognized.append(f"keyword {name} (count {count})")
    for d in root.getElementsByTagName("Date"):
        out.dates.append((d.getAttribute("Value"), d.getAttribute("Name")))
    return out


_CLI_LINE = re.compile(r"^\s{1}(\S.*?)\s+(\d+)(?:\((\d+)\))?\s*$")
# pdfid's plugin output: "<name> score:        1.00" / "<name> instructions: <text>" / "Error ... plugin: <name>"
_PLUGIN_SCORE = re.compile(r"^(.+?) score:\s+(-?[\d.]+)\s*$")
_PLUGIN_INSTR = re.compile(r"^(.+?) instructions: ?(.*)$")
_PLUGIN_ERROR = re.compile(r"^(Error (?:instantiating|loading|running) plugin): (.+)$")
_CLI_KNOWN = [re.compile(p) for p in (r"^PDFiD \S+ ", r"^\s*Not a PDF document", r"^\s*D:\d", r"(?i)entropy")] + \
    [_PLUGIN_SCORE, _PLUGIN_INSTR, _PLUGIN_ERROR]


def parse_plugin_output(text: str, data: "PdfidData") -> None:
    """Collect plugin scores, instructions and errors from pdfid's printed output."""
    by_name: dict[str, list] = {}
    for line in text.splitlines():
        s = line.strip()
        m = _PLUGIN_ERROR.match(s)
        if m:
            data.plugin_errors.append(f"{m.group(1)}: {m.group(2)}")
            continue
        m = _PLUGIN_SCORE.match(s)
        if m:
            try:
                score = float(m.group(2))
            except ValueError:
                continue
            by_name[m.group(1)] = [m.group(1), score, ""]
            data.plugin_results.append(by_name[m.group(1)])
            continue
        m = _PLUGIN_INSTR.match(s)
        if m and m.group(1) in by_name:
            by_name[m.group(1)][2] = m.group(2).strip()


def parse_pdfid_text(text: str, check: bool = True) -> PdfidData:
    """Fallback parser for pdfid's plain-text output (subprocess mode). Lines in no known
    shape go to data.unrecognized (check=False when plugin output is mixed in)."""
    out = PdfidData()
    for line in text.splitlines():
        if line.startswith(" PDF Header:"):
            out.header = line.split(":", 1)[1].strip()
            out.is_pdf = True
            continue
        m = _CLI_LINE.match(line)
        if m:
            name, count, hexc = m.group(1).strip(), int(m.group(2)), int(m.group(3) or 0)
            out.keywords.append(_row(name, count, hexc))
            continue
        if check and line.strip() and not any(p.search(line) for p in _CLI_KNOWN):
            outputcheck.keep(out.unrecognized, line)
    return out


def _row(name: str, count: int, hexc: int) -> KeywordRow:
    sev = KEYWORD_SEVERITY.get(name, Severity.INFO)
    if hexc:
        sev = Severity.HIGH
    if count == 0 and hexc == 0:
        sev = Severity.INFO
    explanation = KEYWORD_EXPLANATION.get(name, "Structural element." if name in STRUCTURAL else "")
    if hexc:
        explanation = (f"{hexc} hex-obfuscated occurrence(s) (e.g. /J#61vaScript). "
                       "Obfuscated names are a strong malicious indicator. " + explanation)
    return KeywordRow(name, count, hexc, sev, explanation)


EXECUTION_NAMES = {"/JS", "/JavaScript", "/Launch"}
# Keywords that are routine on their own but dangerous next to code execution
CONTEXTUAL = {"/AA", "/OpenAction", "/AcroForm"}


def contextual_severity(name: str, present: set[str], obfuscated: bool = False) -> Severity:
    """Severity of a PDF keyword given which other keywords are present.

    /AA and /OpenAction are everywhere in benign forms and viewers (page-1 zoom,
    field formatting), so they're Medium alone and High only when the file also
    has JavaScript or /Launch. /AcroForm alone is Low."""
    if obfuscated:
        return Severity.HIGH
    has_exec = bool(present & EXECUTION_NAMES)
    if name == "/AcroForm":
        return Severity.MEDIUM if has_exec else Severity.LOW
    if name in ("/AA", "/OpenAction"):
        return Severity.HIGH if has_exec else Severity.MEDIUM
    return KEYWORD_SEVERITY.get(name, Severity.INFO)


def findings_from(data: PdfidData) -> list[Finding]:
    """Findings from pdfid's keyword counts, extra data and plugin results."""
    found: list[Finding] = []
    if not data.is_pdf:
        found.append(Finding("pdfid", Severity.MEDIUM, "pdfid: no PDF header detected",
                             "Run with Force (-f) to scan anyway.", ref={"kb": "pdf:no_header"}))
    present = {r.name for r in data.keywords if r.count or r.hex_count}
    for row in data.keywords:
        if not (row.count or row.hex_count):
            continue
        sev = contextual_severity(row.name, present, bool(row.hex_count))
        row.severity = sev
        if sev >= Severity.LOW and row.name not in STRUCTURAL:
            note = ""
            if row.name in CONTEXTUAL:
                note = (" Rated High because the file also contains JavaScript or /Launch."
                        if sev == Severity.HIGH else
                        " On its own this is common in legitimate files; see the investigation steps.")
            found.append(Finding("pdfid", sev, f"{row.name} x{row.count}", row.explanation + note,
                                 ref={"kb": f"pdf:{row.name}", "keyword": row.name, "tab": "pdfid",
                                      "count": row.count, "hex": row.hex_count}))
    try:
        after_eof = int(data.extra.get("CountCharsAfterLastEOF", "0") or 0)
    except ValueError:
        after_eof = 0
    if after_eof > 2:  # a trailing newline or two is normal
        found.append(Finding("pdfid", Severity.MEDIUM, f"{after_eof} bytes after last %%EOF",
                             "Data appended after the end of the PDF: possible hidden payload "
                             "or a polyglot file.", ref={"kb": "pdf:after_eof"}))
    if data.error:
        found.append(Finding("pdfid", Severity.LOW, "pdfid reported a parse error", data.error))
    for name, score, instructions in data.plugin_results:
        found.append(Finding("pdfid", Severity.INFO, f"pdfid {name}: score {score:.2f}",
                             (instructions or "No instructions from the plugin.")
                             + " (A plugin's own opinion; the keyword findings above carry the rating.)",
                             ref={"kb": "pdfid:plugin", "tab": "pdfid"}))
    for err in data.plugin_errors:
        found.append(Finding("pdfid", Severity.INFO, f"pdfid {err}",
                             "pdfid stops at the first plugin that fails, so plugins after it didn't run. "
                             "Usually the plugin was written for an older pdfid version. Keyword counts are "
                             "unaffected.", ref={"kb": "pdfid:plugin_error", "tab": "pdfid"}))
    if data.unrecognized:
        from . import versions
        kw = all(u.startswith("keyword ") for u in data.unrecognized)
        found.append(outputcheck.note(
            "pdfid", data.unrecognized, versions.version_of("pdfid"),
            unit="keyword(s)" if kw else "line(s) of output",
            consequence=("and this app has no rating for it yet: it's listed as Info, so check what it "
                         "means before relying on the verdict") if kw else ""))
    return found


# --------------------------------------------------------------------------- running


def _run_cli_inprocess(mod: ModuleType, pdfid_path: str, args: list[str]) -> str:
    buf = io.StringIO()
    saved_argv = sys.argv
    sys.argv = [pdfid_path] + args
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                mod.Main()
            except SystemExit:
                pass
    finally:
        sys.argv = saved_argv
    return buf.getvalue()


def _run_cli_subprocess(pdfid_path: str, args: list[str], timeout: int) -> str:
    from . import scripts
    return scripts.run_script(pdfid_path, args, timeout, "pdfid.py").text


def run(sample_path: str, opts: PdfidOptions, timeout: int = 120) -> ToolResult:
    """Run pdfid on the sample and parse its keyword counts (a failure if none are recognized)."""
    pdfid_path = locate_pdfid()
    args = opts.cli_args() + [sample_path]
    command = "pdfid.py " + command_line(args)
    if not pdfid_path:
        return ToolResult("pdfid", False, command, error=(
            f"pdfid.py not found ({edition.hint('tools')}, or set MTW_PDFID)."))

    mod = _import_pdfid(pdfid_path)
    try:
        with _PDFID_LOCK:
            if mod is not None:
                xml_doc = mod.PDFiD(sample_path, opts.all_names, opts.extra, False, opts.force)
                data = parse_pdfid_xml(xml_doc.toxml(), opts.all_names)
                raw = _run_cli_inprocess(mod, pdfid_path, args)
            else:
                raw = _run_cli_subprocess(pdfid_path, args, timeout)
                data = parse_pdfid_text(raw)
            if opts.plugins:
                parse_plugin_output(raw, data)
    except Exception as exc:
        return ToolResult("pdfid", False, command, error=f"{type(exc).__name__}: {exc}")
    if not data.keywords and (data.is_pdf or opts.force):
        from . import versions
        return ToolResult("pdfid", False, command, raw_output=raw, data=data, error=outputcheck.failure(
            "pdfid", data.unrecognized or raw.splitlines()[:5], versions.version_of("pdfid"), "no keyword counts"))

    return ToolResult("pdfid", True, command, raw_output=raw, data=data,
                      findings=findings_from(data))


def disarm(sample_path: str, out_dir: str) -> tuple[str, str]:
    """Write a disarmed copy (pdfid -d) into out_dir. The original is never touched.

    pdfid writes '<name>.disarmed.pdf' beside its input, so we run it on a temp
    copy and move the result. Returns (output_path, cli_command)."""
    pdfid_path = locate_pdfid()
    if not pdfid_path:
        raise RuntimeError("pdfid.py not found")
    mod = _import_pdfid(pdfid_path)
    command = f"pdfid.py -d {quote_arg(sample_path)}"
    with tempfile.TemporaryDirectory(prefix="mtw_disarm_") as tmp:
        work = os.path.join(tmp, "sample.pdf")
        shutil.copyfile(sample_path, work)
        with _PDFID_LOCK:
            if mod is not None:
                with contextlib.redirect_stdout(io.StringIO()):
                    mod.PDFiD(work, False, False, True, True)
            else:
                _run_cli_subprocess(pdfid_path, ["-d", "-f", work], 120)
        produced = [os.path.join(tmp, n) for n in os.listdir(tmp) if "disarmed" in n]
        if not produced:
            raise RuntimeError("pdfid did not produce a disarmed file")
        base = os.path.splitext(os.path.basename(sample_path))[0] + ".disarmed"
        dest = safe_output_path(out_dir, base, suffix=".pdf.bin")
        shutil.move(produced[0], dest)
    return dest, command
