"""Macros module adapter: olevba (VBA + XLM extraction, keyword analysis,
decoding, deobfuscation, VBA-stomping detection, p-code), XLMMacroDeobfuscator
emulation, and msoffcrypto-tool decryption.

Every oletools call is guarded so a version difference degrades one panel
instead of failing the whole run.
"""
from __future__ import annotations

import io
import os
import re
from dataclasses import dataclass, field

from ..core.models import Finding, Severity, ToolResult
from ..core.safety import command_line, defang, quote_arg, safe_output_path

# olevba analysis types, in display order
TYPE_ORDER = ["AutoExec", "Suspicious", "IOC", "Hex String", "Base64 String",
              "Dridex string", "VBA string", "Hex Encoded", "Base64 Encoded"]
TYPE_SEVERITY = {
    "AutoExec": Severity.HIGH, "Suspicious": Severity.MEDIUM, "IOC": Severity.MEDIUM,
    "Hex String": Severity.LOW, "Base64 String": Severity.LOW, "Dridex string": Severity.MEDIUM,
    "VBA string": Severity.LOW,
}
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>)\]]+", re.IGNORECASE)
VELVET = "VelvetSweatshop"  # Excel's built-in default "encryption" password


@dataclass
class Module:
    """One macro module: VBA source, or XLM formulas."""
    name: str            # vba_filename, or "xlm_macro"
    stream_path: str
    code: str
    is_xlm: bool = False

    @property
    def lines(self) -> int:
        return self.code.count("\n") + 1 if self.code else 0


@dataclass
class AnalysisRow:
    """One row of olevba's analysis table."""
    kind: str
    keyword: str
    description: str

    @property
    def severity(self) -> Severity:
        return TYPE_SEVERITY.get(self.kind, Severity.INFO)


@dataclass
class MacroData:
    """What olevba (and the VBA stomping check) found in a file."""
    container: str = ""
    has_vba: bool = False
    has_xlm: bool = False
    modules: list[Module] = field(default_factory=list)
    analysis: list[AnalysisRow] = field(default_factory=list)
    revealed: str = ""
    stomping: bool | None = None       # None = check unavailable
    pcode: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def iocs(self) -> list[str]:
        seen, out = set(), []
        for r in self.analysis:
            if r.kind == "IOC" and r.keyword not in seen:
                seen.add(r.keyword)
                out.append(r.keyword)
        return out


@dataclass
class MacroOptions:
    """olevba options chosen in the Macros tab."""
    decode: bool = True        # --decode : show decoded strings in the analysis
    deobfuscate: bool = False  # --deobf  : attempt VBA expression deobfuscation (slow)
    reveal: bool = True        # --reveal : produce source with obfuscated strings replaced
    pcode: bool = True         # --show-pcode / stomping check

    def cli_args(self) -> list[str]:
        args = []
        if self.decode:
            args.append("--decode")
        if self.deobfuscate:
            args.append("--deobf")
        if self.reveal:
            args.append("--reveal")
        if self.pcode:
            args.append("--show-pcode")
        return args


# --------------------------------------------------------------------- olevba


def _as_text(code) -> str:
    if isinstance(code, bytes):
        return code.decode("latin-1", "replace")
    return str(code or "")


def analyse(path: str, opts: MacroOptions, parser_cls=None) -> ToolResult:
    """Run olevba in-process. parser_cls is injectable for tests."""
    command = "olevba " + command_line(opts.cli_args() + [path])
    if parser_cls is None:
        try:
            from oletools.olevba import VBA_Parser as parser_cls  # type: ignore
        except ImportError as exc:
            return ToolResult("olevba", False, command, error=f"oletools not installed ({exc})")

    data = MacroData()
    parser = None
    try:
        parser = parser_cls(path)
        data.container = str(getattr(parser, "type", "") or "")
        detect = getattr(parser, "detect_vba_macros", None) or getattr(parser, "detect_macros")
        data.has_vba = bool(detect())
        detect_xlm = getattr(parser, "detect_xlm_macros", None)
        if detect_xlm is not None:
            try:
                data.has_xlm = bool(detect_xlm())
            except Exception as exc:
                data.errors.append(f"XLM detection: {exc}")
        if data.has_vba or data.has_xlm:
            for (_fname, stream_path, vba_filename, code) in parser.extract_macros():
                code = _as_text(code)
                is_xlm = "xlm" in str(vba_filename).lower() or "xlm" in str(stream_path).lower()
                data.modules.append(Module(str(vba_filename), str(stream_path), code, is_xlm))
            try:
                rows = parser.analyze_macros(show_decoded_strings=opts.decode,
                                             deobfuscate=opts.deobfuscate)
                for kind, keyword, desc in rows or []:
                    data.analysis.append(AnalysisRow(str(kind), _as_text(keyword), _as_text(desc)))
            except Exception as exc:
                data.errors.append(f"Keyword analysis: {exc}")
            if opts.reveal:
                try:
                    data.revealed = _as_text(parser.reveal())
                except Exception as exc:
                    data.errors.append(f"Reveal: {exc}")
            if opts.pcode and data.has_vba:
                stomp = getattr(parser, "detect_vba_stomping", None)
                if stomp is not None:
                    try:
                        data.stomping = bool(stomp())
                    except Exception as exc:
                        data.errors.append(f"VBA stomping check: {exc}")
                pc = getattr(parser, "extract_pcode", None)
                if pc is not None:
                    try:
                        data.pcode = _as_text(pc())
                    except Exception as exc:
                        data.errors.append(f"P-code disassembly: {exc}")
    except Exception as exc:
        return ToolResult("olevba", False, command, error=f"{type(exc).__name__}: {exc}", data=data)
    finally:
        if parser is not None:
            try:
                parser.close()
            except Exception:
                pass

    data.analysis.sort(key=lambda r: (TYPE_ORDER.index(r.kind) if r.kind in TYPE_ORDER else 99))
    return ToolResult("olevba", True, command, raw_output=render_text(data), data=data,
                      error="; ".join(data.errors), findings=findings_from(data))


def findings_from(d: MacroData) -> list[Finding]:
    """Findings for auto-run macros, suspicious keywords, IOCs, VBA stomping and encoded strings."""
    out: list[Finding] = []
    auto = [r.keyword for r in d.analysis if r.kind == "AutoExec"]
    susp = [r.keyword for r in d.analysis if r.kind == "Suspicious"]
    if auto:
        out.append(Finding("olevba", Severity.HIGH, f"AutoExec: {', '.join(auto[:4])}",
                           "Macro code runs automatically when the document is opened or closed.",
                           ref={"keyword": auto[0], "tab": "macros", "kb": "vba:autoexec"}))
    if susp:
        out.append(Finding("olevba", Severity.MEDIUM, f"{len(susp)} suspicious keyword(s)",
                           defang(", ".join(susp[:25])), ref={"tab": "macros", "kb": "vba:suspicious"}))
    for ioc in d.iocs[:15]:
        out.append(Finding("olevba", Severity.MEDIUM, f"IOC: {defang(ioc)}",
                           "Indicator extracted from macro code.", ref={"tab": "macros", "kb": "vba:ioc"}))
    if d.stomping:
        out.append(Finding("olevba", Severity.HIGH, "VBA stomping detected",
                           "The compiled p-code does not match the VBA source. The visible source "
                           "may be a decoy; the p-code is what actually runs. Check the P-code tab.",
                           ref={"tab": "macros", "kb": "vba:stomping"}))
    if any(r.kind in ("Hex String", "Base64 String", "Dridex string") for r in d.analysis):
        out.append(Finding("olevba", Severity.LOW, "Encoded strings in macro code",
                           "Hex/Base64/Dridex-encoded strings were found; see decoded values in "
                           "the analysis table.", ref={"tab": "macros", "kb": "vba:encoded"}))
    return out


def render_text(d: MacroData) -> str:
    """olevba-style plain-text report, for the raw view."""
    lines = [f"Container: {d.container or '?'}   VBA: {d.has_vba}   XLM: {d.has_xlm}", ""]
    for m in d.modules:
        lines += ["-" * 79, f"{'XLM MACRO' if m.is_xlm else 'VBA MACRO'} {m.name}",
                  f"in file: {m.stream_path}", "- " * 39, m.code, ""]
    if d.analysis:
        lines += ["+" + "-" * 12 + "+" + "-" * 22 + "+" + "-" * 42, "Type         | Keyword              | Description"]
        for r in d.analysis:
            lines.append(f"{r.kind:<13}| {defang(r.keyword)[:21]:<21}| {defang(r.description)}")
    if d.stomping is not None:
        lines += ["", f"VBA stomping: {'DETECTED' if d.stomping else 'not detected'}"]
    for e in d.errors:
        lines.append(f"ERROR: {e}")
    return "\n".join(lines)


# --------------------------------------------------------------------- XLM emulation


def xlm_deobfuscator_available() -> bool:
    """True if XLMMacroDeobfuscator is installed (as a command or a module)."""
    from . import scripts
    if scripts.locate_cli("xlmdeobfuscator"):
        return True
    try:
        import XLMMacroDeobfuscator  # type: ignore  # noqa: F401
        return True
    except ImportError:
        return False


# Text XLMMacroDeobfuscator prints in a normal run (any one is enough to say we read it)
_XLM_MARKERS = ("Deobfuscation]", "CELL:", "entry point", "XLMMacroDeobfuscator")


def emulate_xlm(path: str, password: str | None = None, timeout: int = 300) -> ToolResult:
    """Run XLMMacroDeobfuscator as a separate process so a hostile workbook that
    loops forever can be killed by the timeout."""
    args = ["--file", path, "--noninteractive", "--no-indent"]
    if password:
        args += ["--password", password]
    from . import scripts
    exe = scripts.locate_cli("xlmdeobfuscator") if scripts.python_exe() else None
    if exe:
        cmd = [exe] + args
    elif scripts.python_exe():
        cmd = [scripts.python_exe(), "-c",
               "from XLMMacroDeobfuscator.deobfuscator import main; main()"] + args
    else:   # frozen build: run the bundled package inside our own executable
        cmd = scripts.self_command("--run-callable", "XLMMacroDeobfuscator.deobfuscator:main", *args)
    shown = "xlmdeobfuscator " + command_line(args)
    r = scripts.run_cmd(cmd, shown, timeout)
    if r.timed_out:
        return ToolResult("xlmdeobfuscator", False, shown,
                          error=f"Emulation stopped after {timeout} s (possible infinite loop).")
    if r.stopped:
        return ToolResult("xlmdeobfuscator", False, shown, error="Stopped by user.")
    if r.returncode == 127:
        return ToolResult("xlmdeobfuscator", False, shown, error=r.stderr)
    out = r.stdout.decode("utf-8", "replace") + (("\n" + r.stderr) if r.stderr.strip() else "")
    urls = sorted(set(_URL_RE.findall(out)))
    findings = [Finding("xlmdeobfuscator", Severity.HIGH, f"XLM IOC: {defang(u)}",
                        "URL recovered by emulating the Excel 4.0 macros.", ref={"tab": "macros", "kb": "xlm:ioc"})
                for u in urls[:15]]
    if r.returncode == 0 and out.strip() and not any(m in out for m in _XLM_MARKERS):
        from ..core import outputcheck
        from . import versions
        findings.append(outputcheck.note(
            "xlmdeobfuscator", [ln for ln in out.splitlines() if ln.strip()][:20],
            versions.version_of("XLMMacroDeobfuscator"), tab="macros",
            consequence="so URLs and calls it recovered may be missing from the findings"))
    for exe_kw in ("EXEC(", "CALL(", "REGISTER("):
        if exe_kw in out.upper():
            findings.append(Finding("xlmdeobfuscator", Severity.HIGH, f"XLM uses {exe_kw[:-1]}",
                                    "Emulated XLM macros call out to the OS or Win32 API.",
                                    ref={"tab": "macros", "kb": "xlm:exec"}))
    return ToolResult("xlmdeobfuscator", r.returncode == 0 or bool(out.strip()), shown,
                      raw_output=out, data=urls, findings=findings,
                      error="" if out.strip() else f"exit code {r.returncode}")


# --------------------------------------------------------------------- decryption


def msoffcrypto_available() -> bool:
    """True if msoffcrypto-tool is installed."""
    try:
        import msoffcrypto  # type: ignore  # noqa: F401
        return True
    except ImportError:
        return False


def is_encrypted(path: str) -> bool:
    """True if msoffcrypto says the file is encrypted; False if it can't tell."""
    try:
        import msoffcrypto  # type: ignore
    except ImportError:
        return False
    try:
        with open(path, "rb") as fh:
            return bool(msoffcrypto.OfficeFile(fh).is_encrypted())
    except Exception:
        return False


class WrongPassword(Exception):
    """The password didn't decrypt the file."""


def decrypt(path: str, out_dir: str, password: str | None) -> tuple[str, str, str]:
    """Decrypt to a new file in out_dir. Tries Excel's default password first when
    none is given. Returns (output_path, password_used, cli_command)."""
    import msoffcrypto  # type: ignore
    candidates = [password] if password else [VELVET]
    with open(path, "rb") as fh:
        office = msoffcrypto.OfficeFile(fh)
        last_exc: Exception | None = None
        for pw in candidates:
            try:
                try:
                    office.load_key(password=pw, verify_password=True)
                except TypeError:          # older msoffcrypto without verify_password
                    office.load_key(password=pw)
                buf = io.BytesIO()
                office.decrypt(buf)
            except Exception as exc:
                last_exc = exc
                continue
            base = os.path.splitext(os.path.basename(path))[0] + ".decrypted"
            dest = safe_output_path(out_dir, base, suffix=".bin")
            with open(dest, "wb") as out:
                out.write(buf.getvalue())
            shown_pw = "VelvetSweatshop" if pw == VELVET else "********"
            cmd = f"msoffcrypto-tool -p {shown_pw} {quote_arg(path)} {quote_arg(dest)}"
            return dest, pw, cmd
    raise WrongPassword(str(last_exc) if last_exc else "wrong password")
