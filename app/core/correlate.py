"""Cross-tool correlation: let a deeper tool's evidence refine a keyword tool's rating.

pdfid only counts keywords, so a fillable form whose only scripts are standard
Acrobat formatting/calculation calls (AFNumber_Format, AFSimple_Calculate, ...)
rates /JS and /AA High. When pdf-parser has read every script and found only
those, the keyword findings are lowered to Medium, with the reason attached.

Conservative by design. Nothing is lowered when:
  * pdf-parser hasn't run, failed, or the PDF is encrypted;
  * any script is unknown, lives in a stream, or a /Launch exists;
  * any /JS object isn't one of the benign scripts a trigger reaches;
  * part of pdf-parser's output wasn't recognized (it may have missed something);
  * pdfid counted more /JS than pdf-parser found (something is hidden);
  * pdfid saw hex-obfuscated names.
"""
from __future__ import annotations

from .models import Severity

FORM_KEYWORDS = {"/JS", "/JavaScript", "/AA", "/OpenAction", "/AcroForm"}
_ORIG_SEV, _ORIG_DETAIL = "corr_orig_severity", "corr_orig_detail"
# pdfid's reason for rating /AA or /OpenAction High; contradicts the lowered rating, so it's dropped
_RATED_HIGH = " Rated High because the file also contains JavaScript or /Launch."


def _restore(findings) -> None:
    for f in findings:
        if _ORIG_SEV in f.ref:
            f.severity = Severity(f.ref.pop(_ORIG_SEV))
            f.detail = f.ref.pop(_ORIG_DETAIL, f.detail)


def form_scripts_only(findings, facts: dict | None) -> bool:
    """True when every script pdf-parser found is a standard Acrobat form call, so pdfid's findings can be lowered."""
    if not facts or facts.get("encrypted"):
        return False
    if not facts.get("js_triggers") or facts.get("js_unknown") or facts.get("launch") \
            or facts.get("js_unexplained", 1) or facts.get("unrecognized"):
        return False
    pdfid = [f for f in findings if f.source == "pdfid"]
    if any(f.ref.get("hex") for f in pdfid):
        return False
    pdfid_js = max((int(f.ref.get("count", 0)) for f in pdfid if f.ref.get("keyword") == "/JS"), default=0)
    return pdfid_js <= int(facts.get("js_names", facts.get("js_objects", 0)))


def apply(findings, facts: dict[str, dict]) -> int:
    """Re-apply correlation to the session's findings in place; returns how many were lowered."""
    _restore(findings)
    pdf_facts = facts.get("pdf-parser")
    if not form_scripts_only(findings, pdf_facts):
        return 0
    n = pdf_facts["js_triggers"]
    note = (f" Lowered to Medium: pdf-parser read all {n} script(s) in this PDF and every one is a "
            "standard Acrobat form formatting/calculation call (AF*).")
    lowered = 0
    for f in findings:
        if f.source in ("pdfid", "peepdf") and f.ref.get("keyword") in FORM_KEYWORDS \
                and f.severity == Severity.HIGH:
            f.ref[_ORIG_SEV] = int(f.severity)
            f.ref[_ORIG_DETAIL] = f.detail
            f.severity = Severity.MEDIUM
            f.detail = f.detail.replace(_RATED_HIGH, "") + note
            lowered += 1
    return lowered
