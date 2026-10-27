"""The Help → Tool status report: each tool's version, where it was found (and, for Python
tools and libraries, which Python runs them), and its hash status."""
from __future__ import annotations

import sys

from .. import edition
from ..adapters import (macro_adapter, pdf_crypto, pdfid_adapter, peepdf_adapter, scripts, toolenv, versions,
                        yara_adapter)
from ..core import vendor_manifest, vendor_pins


def status_lines() -> list[str]:
    """One row per tool: version, then where it was found (and its hash status)."""
    vs = versions.all_versions()
    vdir = scripts.VENDOR_DIR
    p = pdfid_adapter.locate_pdfid()

    def tag(path: str | None) -> str:
        st = vendor_manifest.file_status(vdir, path)
        return f"  [{st}]" if st else ""

    def row(name: str, version: str, where: str) -> str:
        return f"{name:<21} {version or '-':<22} {where}"

    def runs_with(path: str | None) -> str:
        py = scripts.script_python(path) if path else None
        return f"  (runs with {py})" if py and py != sys.executable else ""

    def library(name: str, key: str, missing: str) -> list[str]:
        prov = toolenv.provider(key)
        out = [row(name, vs.get(name, ""), prov.source if prov.available else missing)]
        if prov.note:
            out.append(row("", " ", prov.note))
        return out

    lines = [f"{edition.label()}: " + ("uses the tools installed on this REMnux VM (vendor folder ignored)"
                                       if edition.is_remnux() else "uses its own tools in the vendor folder, "
                                       "falling back to PATH"),
             row("Tool", "Version", "Location / status"),
             row("pdfid", vs.get("pdfid", ""),
                 (p or f"NOT FOUND ({edition.hint('tools')}, or set MTW_PDFID)") + tag(p) + runs_with(p)),
             row("", " ", f"{len(pdfid_adapter.list_plugins(p))} pdfid plugin(s) available")]
    not_found = f"NOT FOUND ({edition.hint('tools')})"
    for label, script, missing in (("pdf-parser", "pdf-parser.py", not_found),
                                   ("oledump", "oledump.py", not_found),
                                   ("zipdump", "zipdump.py", "not found (optional)"),
                                   ("rtfdump", "rtfdump.py", "not found (optional)")):
        loc = scripts.locate(script)
        lines.append(row(label, vs.get(label, ""), (loc or missing) + tag(loc) + runs_with(loc)))
    lines += library("oletools", "oletools", f"NOT INSTALLED ({edition.hint('oletools')})")
    pe = peepdf_adapter.locate()
    lines.append(row("peepdf", vs.get("peepdf", ""),
                     pe or f"not installed ({edition.hint('peepdf')})"))
    lines.append(row("XLMMacroDeobfuscator", vs.get("XLMMacroDeobfuscator", ""),
                     "installed" if macro_adapter.xlm_deobfuscator_available()
                     else f"not installed ({edition.hint('xlm')})"))
    lines += library("msoffcrypto-tool", "msoffcrypto",
                     f"NOT INSTALLED (Office decryption disabled: {edition.hint('msoffcrypto')})")
    lines += library("jsbeautifier", "jsbeautifier",
                     "not installed (optional: JavaScript is shown with a basic formatter)")
    lines += library("yara-python", "yara", f"not installed (YARA scanning unavailable: {edition.hint('yara')})")
    from .yara_view import rules_setting
    rules = rules_setting()
    lines.append(row("", " ", f"YARA rules: {rules} ({len(yara_adapter.rule_files(rules))} rule files)"
                     if rules else "YARA rules: none set (File → YARA rules…)"))
    lib = pdf_crypto.available()
    lines.append(row("PDF decryption", f"{lib} {vs.get(lib, '')}".strip() if lib else "",
                     "available" if lib else f"unavailable ({edition.hint('pikepdf')})"))
    lines.append(row("Python", vs.get("Python", ""), sys.executable))
    net = scripts.tools_have_network()
    lines.append("network for tools: " + (
        "blocked (each tool runs in its own empty network namespace)" if net is False else
        "NOT blocked: this Linux doesn't allow unprivileged network namespaces; keep the VM's network "
        "host-only" if net else
        "not restricted by the app on Windows or macOS; keep the analysis VM's network host-only"))
    if scripts.vendor_enabled():
        status, problems = vendor_manifest.verify(vdir)
        pin = f"pinned DidierStevensSuite {vendor_pins.COMMIT[:12]} ({vendor_pins.COMMIT_DATE})"
        lines.append(f"vendor hashes: {status}" + (f" against the {pin}" if status == "verified" else "")
                     + "".join(f"\n    {x}" for x in problems))
    else:
        lines.append("vendor hashes: not used (REMnux maintains its own tools; update with  sudo remnux upgrade)")
    return lines
