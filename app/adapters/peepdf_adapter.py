"""peepdf adapter (CLI: -j JSON overview, -s scripted console commands) and the
JavaScript workbench helpers (pure Python, never executes JavaScript).

peepdf is GPLv3 and optional: install with "python setup_vendor.py --peepdf" or
use REMnux's copy on PATH. Install with: python setup_vendor.py --peepdf
"""
from __future__ import annotations

import json
import os
import re
import tempfile

from .. import edition
from ..core import outputcheck
from ..core.models import Finding, Severity, ToolResult
from ..core.safety import defang
from . import scripts


def locate() -> str | None:
    """The peepdf command (MTW_PEEPDF, or peepdf / peepdf.py / peepdf-3 on PATH), or None."""
    env = os.environ.get("MTW_PEEPDF")
    if env and os.path.isfile(env):
        return env
    return scripts.locate_cli("peepdf", "peepdf.py", "peepdf-3")


def _run(args: list[str], timeout: int, network: bool = False) -> scripts.RunResult:
    tool = locate()
    if not tool:
        return scripts.RunResult("peepdf", b"", f"peepdf not found ({edition.hint('peepdf')}).", 127)
    return scripts.run_script(tool, args, timeout, "peepdf", network=network)


def overview(path: str, timeout: int = 300) -> ToolResult:
    """peepdf's JSON report, parsed (a failure if it isn't peepdf's report layout)."""
    r = _run(["-f", "-l", "-j", path], timeout)
    text = r.stdout.decode("utf-8", "replace")
    data = None
    start = text.find("{")
    if start != -1:
        try:
            data = json.loads(text[start:])
        except json.JSONDecodeError:
            data = None
    ok = data is not None
    error = "" if ok else (scripts.error_summary(r.text) or "peepdf returned no JSON")
    if ok and not (next(_find_key(data, "basic"), None) or next(_find_key(data, "advanced"), None)):
        # JSON, but not peepdf's report layout: reading it would silently find nothing
        from . import versions
        ok = False
        error = outputcheck.failure("peepdf", [f"top-level keys: {', '.join(map(str, data))[:200]}"]
                                    if isinstance(data, dict) else [], versions.version_of("peepdf"),
                                    "unexpected JSON layout")
    return ToolResult("peepdf", ok, r.command, raw_output=r.text, data=data,
                      findings=findings_from(data) if ok else [], error=error)


def _walk(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, f"{path}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]")
    else:
        yield path, node


def _find_key(node, key: str):
    """Yield every value stored under `key` anywhere in the JSON."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                yield v
            yield from _find_key(v, key)
    elif isinstance(node, list):
        for v in node:
            yield from _find_key(v, key)


def _objects_text(ids) -> str:
    if isinstance(ids, list):
        flat = [str(i) for i in ids if not isinstance(i, (dict, list))]
        return ", ".join(flat[:12]) + ("…" if len(flat) > 12 else "")
    return str(ids)


def findings_from(data) -> list[Finding]:
    """One finding per suspicious element / vulnerability, rated like pdfid.

    peepdf's own metadata (peepdf_info: author, project URL, version) is ignored."""
    from .pdfid_adapter import KEYWORD_SEVERITY
    if isinstance(data, dict):
        data = {k: v for k, v in data.items() if k != "peepdf_info"}
        for k, v in list(data.items()):
            if isinstance(v, dict) and "peepdf_info" in v:
                data[k] = {kk: vv for kk, vv in v.items() if kk != "peepdf_info"}
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(sev, title, detail, kb="pdf:peepdf_element", keyword=""):
        key = (title, detail)
        if key not in seen:
            seen.add(key)
            ref = {"tab": "peepdf", "kb": kb}
            if keyword:
                ref["keyword"] = keyword
            out.append(Finding("peepdf", sev, title, detail, ref=ref))

    from .pdfid_adapter import contextual_severity
    present: set[str] = set()
    for block in _find_key(data, "suspicious_elements"):
        if isinstance(block, dict):
            for entries in block.values():
                if isinstance(entries, dict):
                    present |= {str(k) for k in entries}
                elif isinstance(entries, list):
                    present |= {str(e.get("name")) for e in entries if isinstance(e, dict)}

    for block in _find_key(data, "suspicious_elements"):
        if not isinstance(block, dict):
            continue
        for category, entries in block.items():
            items = []
            if isinstance(entries, dict):
                items = list(entries.items())
            elif isinstance(entries, list):
                for e in entries:
                    if isinstance(e, dict):
                        items.append((e.get("name", "?"), e.get("objects", e.get("value", ""))))
                    else:
                        items.append((str(e), ""))
            for name, objs in items:
                name = str(name)
                if "vuln" in category.lower() or "cve" in name.lower():
                    sev = Severity.HIGH
                else:
                    sev = contextual_severity(name, present)
                    if name not in KEYWORD_SEVERITY:
                        sev = Severity.LOW
                    if name in ("/JS", "/JavaScript", "/Launch", "/EmbeddedFile"):
                        sev = Severity.HIGH
                where = f" in objects {_objects_text(objs)}" if objs not in ("", None, []) else ""
                kb = "pdf:vuln" if sev == Severity.HIGH and ("vuln" in category.lower() or "cve" in name.lower()) \
                    else f"pdf:{name}"
                add(sev, f"{name}{where}", f"peepdf suspicious element ({category}).", kb, name)
    for key in ("vulns", "js_vulns", "vulnerabilities"):
        for block in _find_key(data, key):
            for v in (block if isinstance(block, list) else [block]):
                name = v.get("name", str(v)) if isinstance(v, dict) else str(v)
                add(Severity.HIGH, f"Known-vulnerable element: {defang(name)[:80]}",
                    "Matches an element peepdf associates with a known exploit.", "pdf:vuln")
    for block in _find_key(data, "urls"):
        for u in (block if isinstance(block, list) else [block]):
            if isinstance(u, str) and "://" in u:
                add(Severity.MEDIUM, f"URL: {defang(u)[:90]}", "URL found by peepdf in the document.",
                    "pdf:/URI", "/URI")
    if len(out) > 40:
        out = sorted(out, key=lambda f: -f.severity)[:40]
    return out


def urls_from(data) -> list[str]:
    """URLs listed in peepdf's JSON report, leaving out peepdf's own project URL."""
    if isinstance(data, dict):
        data = {k: v for k, v in data.items() if k != "peepdf_info"}
    found = []
    for block in _find_key(data, "urls"):
        for u in (block if isinstance(block, list) else [block]):
            if isinstance(u, str) and "://" in u and "digitalsleuth/peepdf" not in u:
                found.append(u)
    return found


# Console commands that would execute or emulate sample code. The JS engines are also made
# unimportable for every tool (scripts.NOJS_DIR), so these are refused up front with a reason.
BLOCKED_COMMANDS = {
    "js_eval": "executes JavaScript",
    "js_analyse": "executes JavaScript when a JS engine is installed",
    "js_vars": "shows variables from executed JavaScript",
    "sctest": "emulates shellcode",
    "shell": "runs system commands",
}


def blocked_command(command: str) -> str | None:
    """The reason a peepdf console command is refused, or None if it's allowed."""
    c = command.strip()
    if c.startswith("!"):
        return "runs system commands"
    word = c.split(None, 1)[0].lower() if c else ""
    return BLOCKED_COMMANDS.get(word)


def refused(commands: list[str]) -> str:
    """Explanation for the first refused command, or '' when all are allowed."""
    for c in commands:
        why = blocked_command(c)
        if why:
            return (f"'{c.split(None, 1)[0]}' is disabled: it {why}, and this app never runs sample code. "
                    "Use js_code / object / stream to read the script, and the JS workbench to decode it.")
    return ""


def console(path: str, commands: list[str], timeout: int = 300) -> scripts.RunResult:
    """Run peepdf console commands non-interactively (peepdf -s script)."""
    why = refused(commands)
    if why:
        return scripts.RunResult("peepdf -s <commands>   # " + " ; ".join(commands), b"", why, 126)
    with tempfile.TemporaryDirectory(prefix="mtw_peepdf_") as tmp:
        script = os.path.join(tmp, "commands.txt")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write("\n".join(c for c in commands if c.strip()) + "\nexit\n")
        # vtcheck is the one command that needs the network (it sends the file's hash to VirusTotal)
        wants_net = any(c.strip().split()[:1] == ["vtcheck"] for c in commands if c.strip())
        r = _run(["-f", "-l", "-s", script, path], timeout, network=wants_net)
        r.command = r.command.replace(script, "<commands>") + "   # " + " ; ".join(commands)
        return r


# --------------------------------------------------------------------- JS workbench

_PCT_U = re.compile(r"%u([0-9a-fA-F]{4})")
_BS_U = re.compile(r"\\u([0-9a-fA-F]{4})")
_BS_X = re.compile(r"\\x([0-9a-fA-F]{2})")
_PCT_X = re.compile(r"%([0-9a-fA-F]{2})")
_FROMCHAR = re.compile(r"fromCharCode\s*\(([\d\s,xXa-fA-F]+)\)")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>)\]]+", re.IGNORECASE)


def unescape_payload(text: str) -> bytes:
    """Decode the usual JS shellcode encodings into raw bytes.

    %uXXXX / \\uXXXX are little-endian 16-bit units (heap-spray style); \\xHH, %HH and
    String.fromCharCode(...) are single bytes. Whatever matches first in the text wins.
    """
    if _PCT_U.search(text) or _BS_U.search(text):
        out = bytearray()
        for m in re.finditer(r"%u([0-9a-fA-F]{4})|\\u([0-9a-fA-F]{4})|%([0-9a-fA-F]{2})", text):
            if m.group(1) or m.group(2):
                v = int(m.group(1) or m.group(2), 16)
                out += bytes((v & 0xFF, v >> 8))
            else:
                out.append(int(m.group(3), 16))
        return bytes(out)
    if _BS_X.search(text):
        return bytes(int(h, 16) for h in _BS_X.findall(text))
    m = _FROMCHAR.search(text)
    if m:
        vals = []
        for tok in m.group(1).split(","):
            tok = tok.strip()
            if tok:
                vals.append(int(tok, 16) if tok.lower().startswith("0x") else int(tok))
        return bytes(v & 0xFF for v in vals)
    if _PCT_X.search(text):
        return bytes(int(h, 16) for h in _PCT_X.findall(text))
    return b""


def beautify(js: str) -> tuple[str, str]:
    """Returns (code, engine)."""
    try:
        import jsbeautifier  # type: ignore
        return jsbeautifier.beautify(js), "jsbeautifier"
    except Exception:
        pass
    out, indent, in_str, quote, prev = [], 0, False, "", ""
    for ch in js:
        if in_str:
            out.append(ch)
            if ch == quote and prev != "\\":
                in_str = False
        elif ch in "\"'":
            in_str, quote = True, ch
            out.append(ch)
        elif ch == "{":
            indent += 1
            out.append("{\n" + "    " * indent)
        elif ch == "}":
            indent = max(0, indent - 1)
            out.append("\n" + "    " * indent + "}\n" + "    " * indent)
        elif ch == ";":
            out.append(";\n" + "    " * indent)
        else:
            out.append(ch)
        prev = ch
    return re.sub(r"\n\s*\n", "\n", "".join(out)), "basic formatter (install jsbeautifier for better output)"


def urls_in(text: str) -> list[str]:
    """Every distinct URL in text."""
    return sorted(set(_URL.findall(text)))
