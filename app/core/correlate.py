"""Cross-tool correlation: let a deeper tool's evidence refine a keyword tool's rating.

pdfid only counts keywords, so a fillable form whose only scripts are standard
Acrobat formatting/calculation calls (AFNumber_Format, AFSimple_Calculate, ...)
rates /JS and /AA High. When pdf-parser has read every script and found only
those, the keyword findings are lowered to Medium, with the reason attached.

Likewise oleid rates any OOXML external relationship High; when the parts analysis
has read them all and every one is a plain hyperlink, that finding is lowered to Low.

Conservative by design. PDF findings are not lowered when:
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


def _lower(f, severity: Severity, note: str) -> None:
    f.ref[_ORIG_SEV] = int(f.severity)
    f.ref[_ORIG_DETAIL] = f.detail
    f.severity = severity
    f.detail = f.detail + note


def external_rels_are_hyperlinks(findings) -> int:
    """Lower oleid's 'External Relationships' when the parts analysis read every external
    relationship and all of them are plain hyperlinks. oleid rates any external relationship
    High; a hyperlink only opens when clicked. Nothing is lowered unless parts reported at
    least as many external relationships as oleid counted, and none of them is a remote
    template, frame, OLE object or sub-document."""
    ext = [f for f in findings if f.source == "parts" and f.ref.get("kb") in ("ooxml:external", "ooxml:template")]
    if not ext or any(f.ref.get("kb") == "ooxml:template" for f in ext):
        return 0
    lowered = 0
    for f in findings:
        if f.source != "oleid" or f.ref.get("indicator") != "ext_rels" or f.severity <= Severity.LOW:
            continue
        try:
            counted = int(str(f.title).rsplit(":", 1)[-1].strip())
        except ValueError:
            continue
        if counted <= len(ext):
            _lower(f, Severity.LOW, f" Lowered to Low: the Parts analysis read all {len(ext)} external "
                   "relationship(s) and each is an ordinary hyperlink (opens only when clicked).")
            lowered += 1
    return lowered


def apply(findings, facts: dict[str, dict]) -> int:
    """Re-apply correlation to the session's findings in place; returns how many were lowered."""
    _restore(findings)
    lowered_rels = external_rels_are_hyperlinks(findings)
    pdf_facts = facts.get("pdf-parser")
    if not form_scripts_only(findings, pdf_facts):
        return lowered_rels
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
    return lowered + lowered_rels
