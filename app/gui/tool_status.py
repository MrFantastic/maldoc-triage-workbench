"""The Help → Tool status report: each tool's version, where it was found, and its hash status."""
from __future__ import annotations

import sys

from .. import edition
from ..adapters import macro_adapter, office_adapter, pdf_crypto, pdfid_adapter, peepdf_adapter, scripts, versions
from ..core import vendor_manifest


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

    lines = [f"{edition.label()}: " + ("uses the tools installed on this REMnux VM (vendor folder ignored)"
                                       if edition.is_remnux() else "uses its own tools in the vendor folder, "
                                       "falling back to PATH"),
             row("Tool", "Version", "Location / status"),
             row("pdfid", vs.get("pdfid", ""),
                 (p or f"NOT FOUND ({edition.hint('tools')}, or set MTW_PDFID)") + tag(p)),
             row("", " ", f"{len(pdfid_adapter.list_plugins(p))} pdfid plugin(s) available")]
    not_found = f"NOT FOUND ({edition.hint('tools')})"
    for label, script, missing in (("pdf-parser", "pdf-parser.py", not_found),
                                   ("oledump", "oledump.py", not_found),
                                   ("zipdump", "zipdump.py", "not found (optional)"),
                                   ("rtfdump", "rtfdump.py", "not found (optional)")):
        loc = scripts.locate(script)
        lines.append(row(label, vs.get(label, ""), (loc or missing) + tag(loc)))
    ole = office_adapter.oletools_version()
    lines.append(row("oletools", vs.get("oletools", ""),
                     "installed" if ole else f"NOT INSTALLED ({edition.hint('oletools')})"))
    pe = peepdf_adapter.locate()
    lines.append(row("peepdf", vs.get("peepdf", ""),
                     pe or f"not installed ({edition.hint('peepdf')})"))
    lines.append(row("XLMMacroDeobfuscator", vs.get("XLMMacroDeobfuscator", ""),
                     "installed" if macro_adapter.xlm_deobfuscator_available()
                     else f"not installed ({edition.hint('xlm')})"))
    lines.append(row("msoffcrypto-tool", vs.get("msoffcrypto-tool", ""),
                     "installed" if macro_adapter.msoffcrypto_available()
                     else f"NOT INSTALLED (Office decryption disabled: {edition.hint('msoffcrypto')})"))
    lib = pdf_crypto.available()
    lines.append(row("PDF decryption", f"{lib} {vs.get(lib, '')}".strip() if lib else "",
                     "available" if lib else f"unavailable ({edition.hint('pikepdf')})"))
    lines.append(row("Python", vs.get("Python", ""), sys.executable))
    if scripts.vendor_enabled():
        status, problems = vendor_manifest.verify(vdir)
        lines.append(f"vendor hashes: {status}" + "".join(f"\n    {x}" for x in problems))
    else:
        lines.append("vendor hashes: not used (REMnux maintains its own tools; update with  sudo remnux upgrade)")
    return lines
