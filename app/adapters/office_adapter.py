"""Adapter for the Office triage dashboard: oletools' oleid + mraptor (+ olevba
for macro extraction, which mraptor needs as input).

oletools is used as a library. Its APIs are stable since 0.56, but every call
is guarded so a version difference degrades a panel instead of crashing.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..core.models import Finding, Severity, ToolResult
from ..core.safety import defang, quote_arg


@dataclass
class Indicator:
    """One oleid indicator and its rating."""
    id: str
    name: str
    value: str
    risk: Severity
    risk_text: str
    description: str


@dataclass
class MacroModule:
    """A VBA module found during Office triage."""
    filename: str
    stream_path: str
    vba_filename: str
    lines: int
    code: str          # source, shown in the module viewer


@dataclass
class OfficeTriageData:
    """oleid's indicators and mraptor's verdict for one file."""
    indicators: list[Indicator] = field(default_factory=list)
    oleid_error: str = ""
    verdict: str = ""                   # NO MACRO / MACRO OK / SUSPICIOUS / ERROR
    autoexec: bool = False
    write: bool = False
    execute: bool = False
    flags: str = ""                     # mraptor style, e.g. "AWX"
    matches: list[str] = field(default_factory=list)
    has_vba: bool = False
    has_xlm: bool = False
    modules: list[MacroModule] = field(default_factory=list)
    vba_error: str = ""


def oletools_version() -> str | None:
    """The installed oletools version, or None if oletools isn't installed."""
    try:
        import oletools  # type: ignore  # noqa: F401
    except ImportError:
        return None
    try:
        from importlib.metadata import version
        return version("oletools")
    except Exception:
        pass
    try:
        from oletools.olevba import __version__  # type: ignore
        return str(__version__)
    except Exception:
        return "installed (version unknown)"


def truthy(value) -> bool:
    """Read an oleid value ("Yes", 0, None, "N/A", ...) as true or false."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    return text not in ("", "false", "no", "none", "0", "n/a", "unknown")


def _run_oleid(path: str, data: OfficeTriageData) -> None:
    try:
        from oletools.oleid import OleID  # type: ignore
    except ImportError as exc:
        data.oleid_error = f"oletools not installed ({exc})"
        return
    try:
        try:
            oid = OleID(filename=path)
        except TypeError:          # very old signature: OleID(filename)
            oid = OleID(path)
        indicators = oid.check()
    except Exception as exc:
        data.oleid_error = f"{type(exc).__name__}: {exc}"
        return
    for ind in indicators or []:
        risk_text = str(getattr(ind, "risk", "") or "")
        value = getattr(ind, "value", "")
        risk = Severity.from_text(risk_text)
        # oleid marks some indicators 'HIGH' as a category even when absent
        if not truthy(value) and risk > Severity.INFO and isinstance(value, bool):
            risk = Severity.INFO
        data.indicators.append(Indicator(
            id=str(getattr(ind, "id", "")),
            name=str(getattr(ind, "name", "")),
            value=str(value),
            risk=risk,
            risk_text=risk_text or "info",
            description=str(getattr(ind, "description", "") or ""),
        ))


def _run_vba_and_mraptor(path: str, data: OfficeTriageData) -> None:
    try:
        with open(path, "rb") as fh:
            if fh.read(5).startswith(b"{\\rt"):   # RTF cannot contain VBA or XLM macros
                data.verdict = "NO MACRO"
                return
    except OSError:
        pass
    try:
        from oletools.olevba import VBA_Parser  # type: ignore
        from oletools.mraptor import MacroRaptor  # type: ignore
    except ImportError as exc:
        data.vba_error = f"oletools not installed ({exc})"
        data.verdict = "ERROR"
        return
    parser = None
    try:
        parser = VBA_Parser(path)
        detect = getattr(parser, "detect_vba_macros", None) or parser.detect_macros
        data.has_vba = bool(detect())
        detect_xlm = getattr(parser, "detect_xlm_macros", None)
        if detect_xlm is not None:
            try:
                data.has_xlm = bool(detect_xlm())
            except Exception:
                data.has_xlm = False
        if not (data.has_vba or data.has_xlm):
            data.verdict = "NO MACRO"
            return
        all_code = []
        for (filename, stream_path, vba_filename, code) in parser.extract_macros():
            code = code if isinstance(code, str) else code.decode("latin-1", "replace")
            all_code.append(code)
            data.modules.append(MacroModule(
                str(filename), str(stream_path), str(vba_filename),
                code.count("\n") + 1 if code else 0, code))
        raptor = MacroRaptor("\n".join(all_code))
        raptor.scan()
        data.autoexec = bool(raptor.autoexec)
        data.write = bool(raptor.write)
        data.execute = bool(raptor.execute)
        data.flags = raptor.get_flags() if hasattr(raptor, "get_flags") else (
            ("A" if data.autoexec else "-") + ("W" if data.write else "-") + ("X" if data.execute else "-"))
        data.matches = [str(m) for m in getattr(raptor, "matches", [])]
        suspicious = getattr(raptor, "suspicious", data.autoexec and (data.write or data.execute))
        data.verdict = "SUSPICIOUS" if suspicious else "MACRO OK"
    except Exception as exc:
        data.vba_error = f"{type(exc).__name__}: {exc}"
        data.verdict = "ERROR"
    finally:
        if parser is not None:
            try:
                parser.close()
            except Exception:
                pass


def findings_from(data: OfficeTriageData) -> list[Finding]:
    """Findings from mraptor's verdict and oleid's indicators."""
    out: list[Finding] = []
    if data.verdict == "SUSPICIOUS":
        out.append(Finding("mraptor", Severity.HIGH, f"mraptor: SUSPICIOUS ({data.flags})",
                           "Macros run automatically and can write files and/or execute "
                           "commands. Matched: " + defang(", ".join(data.matches[:15])),
                           ref={"kb": "office:mraptor_suspicious", "tab": "macros"}))
    elif data.verdict == "MACRO OK":
        out.append(Finding("mraptor", Severity.LOW, f"Macros present, mraptor: OK ({data.flags})",
                           "mraptor's rules did not flag these macros. Review them anyway: "
                           "mraptor is a heuristic and can be evaded.",
                           ref={"kb": "office:mraptor_ok", "tab": "macros"}))
    elif data.verdict == "ERROR" and data.vba_error:
        out.append(Finding("mraptor", Severity.LOW, "Macro scan failed", data.vba_error))
    if data.has_xlm:
        out.append(Finding("mraptor", Severity.HIGH, "Excel 4.0 (XLM) macros present",
                           "XLM macros are heavily abused and often hidden on very-hidden "
                           "sheets. See the Macros tab.", ref={"kb": "office:xlm", "tab": "macros"}))
    for ind in data.indicators:
        if ind.risk >= Severity.MEDIUM and truthy(ind.value):
            out.append(Finding("oleid", ind.risk, f"{ind.name}: {defang(ind.value)}", defang(ind.description),
                               ref={"indicator": ind.id, "kb": f"oleid:{ind.id}", "tab": "oleid"}))
    return out


def run(path: str) -> ToolResult:
    """Office triage: oleid's indicators and mraptor's verdict."""
    data = OfficeTriageData()
    _run_oleid(path, data)
    _run_vba_and_mraptor(path, data)
    q = quote_arg(path)
    command = f"oleid {q}  &&  mraptor {q}"
    ok = not (data.oleid_error and data.verdict == "ERROR")
    raw = _render_text(data)
    err = "; ".join(e for e in (data.oleid_error, data.vba_error) if e)
    return ToolResult("office-triage", ok, command, raw_output=raw, error=err, data=data,
                      findings=findings_from(data))


def _render_text(d: OfficeTriageData) -> str:
    lines = ["== oleid =="]
    if d.oleid_error:
        lines.append(f"ERROR: {d.oleid_error}")
    for i in d.indicators:
        lines.append(f"{i.name:<28} {i.value:<28} {i.risk_text}")
    lines += ["", "== mraptor =="]
    lines.append(f"Result: {d.verdict}   Flags: {d.flags or '---'}   "
                 "(A=AutoExec, W=Write, X=Execute)")
    if d.matches:
        lines.append("Matches: " + defang(", ".join(d.matches)))
    if d.has_xlm:
        lines.append("XLM/Excel 4.0 macros detected.")
    if d.vba_error:
        lines.append(f"ERROR: {d.vba_error}")
    if d.modules:
        lines += ["", "== VBA modules (olevba) =="]
        for m in d.modules:
            lines.append(f"{m.stream_path}  ({m.vba_filename}, {m.lines} lines)")
    return "\n".join(lines)
