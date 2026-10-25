"""pdf-parser.py (Didier Stevens) adapter.

pdf-parser's full listing format ("obj N G / Type: / Referencing: / Contains
stream / << dictionary >>") has been stable for years, so the object model is
built by parsing one full run (-O expands object streams). Streams are
decoded by pdf-parser itself (-o N -f -d file), so filter support and quirks
match the CLI exactly.
"""
from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field

from .. import edition
from ..core import outputcheck
from ..core.models import Finding, Severity, ToolResult
from ..core.safety import defang
from . import scripts, versions

_OBJ_RE = re.compile(r"^obj (\d+) (\d+)\s*$")
_REF_RE = re.compile(r"(\d+) (\d+) R")
_URI_RE = re.compile(r"/URI\s*\(([^)]*)\)")

SUSPICIOUS_NAMES = ("/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile",
                    "/RichMedia", "/XFA", "/SubmitForm", "/GoToR", "/GoToE", "/URI", "/JBIG2Decode")


@dataclass
class PdfObject:
    """One object from pdf-parser's full listing."""
    id: int
    gen: int
    type: str
    references: list[int]
    has_stream: bool
    text: str                       # pdf-parser's dictionary rendering
    in_objstm: str = ""
    referenced_by: list[int] = field(default_factory=list)

    @property
    def flags(self) -> list[str]:
        return [n for n in SUSPICIOUS_NAMES if re.search(re.escape(n) + r"(?![A-Za-z])", self.text)]


@dataclass
class ParsedPdf:
    """pdf-parser's full listing, parsed: objects, trailers, comments, URIs and triggers."""
    objects: list[PdfObject] = field(default_factory=list)
    trailers: list[str] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    uris: list[str] = field(default_factory=list)
    triggers: list = field(default_factory=list)
    encrypted: bool = False      # strings and streams are ciphertext to pdf-parser
    unrecognized: list[str] = field(default_factory=list)   # output lines in no known shape

    def by_id(self, oid: int) -> PdfObject | None:
        for o in self.objects:
            if o.id == oid:
                return o
        return None


def locate() -> str | None:
    """Path of pdf-parser.py, or None."""
    return scripts.locate("pdf-parser.py")


_XREF_ROW = re.compile(r"^(\d{10} \d{5} [nf]|\d+ \d+)$")
# a per-object header field ( Type:, Referencing:, ...), as opposed to dictionary text (2+ spaces)
_HEADER_FIELD = re.compile(r"^ [A-Z][A-Za-z /]*:(\s|$)")


def parse_full_listing(text: str) -> ParsedPdf:
    """Parse `pdf-parser -O` output. Lines in no known shape (a new header field, or
    text between objects) are collected in pdf.unrecognized (see core.outputcheck)."""
    pdf = ParsedPdf()
    cur: PdfObject | None = None
    body: list[str] = []
    mode = ""

    def flush():
        nonlocal cur, body, mode
        if mode == "obj" and cur is not None:
            cur.text = "\n".join(body).strip("\n")
            pdf.objects.append(cur)
        elif mode == "trailer":
            pdf.trailers.append("\n".join(body).strip("\n"))
        cur, body, mode = None, [], ""

    for line in text.splitlines():
        m = _OBJ_RE.match(line)
        if m:
            flush()
            mode = "obj"
            cur = PdfObject(int(m.group(1)), int(m.group(2)), "", [], False, "")
            continue
        if line.startswith("trailer"):
            flush()
            mode = "trailer"
            continue
        if line.startswith(("xref", "startxref", "PDF Comment")):
            flush()
            if line.startswith("PDF Comment"):
                pdf.comments.append(line[len("PDF Comment"):].strip())
            continue
        if mode == "obj" and cur is not None:
            s = line.strip()
            if line.startswith(" Type:"):
                cur.type = line.split(":", 1)[1].strip()
                continue
            if line.startswith(" Referencing:"):
                cur.references = [int(a) for a, _g in _REF_RE.findall(line)]
                continue
            if s == "Contains stream":
                cur.has_stream = True
                continue
            if line.startswith(" Containing /ObjStm:"):
                cur.in_objstm = line.split(":", 1)[1].strip()
                continue
            if _HEADER_FIELD.match(line):        # a header field this app doesn't know
                outputcheck.keep(pdf.unrecognized, line)
                continue
        if mode:
            body.append(line)
        elif line.strip() and not _XREF_ROW.match(line.strip()):
            outputcheck.keep(pdf.unrecognized, line)
    flush()

    by_id = {o.id: o for o in pdf.objects}
    for o in pdf.objects:
        for r in o.references:
            tgt = by_id.get(r)
            if tgt is not None and o.id not in tgt.referenced_by:
                tgt.referenced_by.append(o.id)
        pdf.uris += [u for u in _URI_RE.findall(o.text)]
    pdf.encrypted = (any("/Encrypt" in t for t in pdf.trailers)
                     or any(o.type == "/XRef" and "/Encrypt" in o.text for o in pdf.objects)
                     or any("/Filter /Standard" in o.text and "/U " in o.text for o in pdf.objects))
    uris = set(pdf.uris)
    if pdf.encrypted:   # ciphertext isn't a URL: keep only values that are readable links
        uris = {u for u in uris if _readable_link(u)}
    pdf.uris = sorted(uris)
    return pdf


def _readable_target(value: str) -> bool:
    """In an encrypted PDF, strings pdf-parser shows are ciphertext. Treat a file/link target as
    readable only if it is printable and shaped like a path, file name or URL."""
    v = value.strip()
    return len(v) >= 3 and v.isprintable() and bool(re.search(r"[./\\:]", v))


def _readable_link(value: str) -> bool:
    return value.isprintable() and ("://" in value or value.lower().startswith("mailto:"))


# --------------------------------------------------------------------- dictionary parsing


@dataclass(frozen=True)
class Ref:
    """An indirect reference (N 0 R) in a parsed dictionary."""
    id: int


class PdfStr(str):
    """A PDF string's content (literal (…) or hex <…>), already unwrapped."""


_DELIMS = set("()<>[]{}/%")


def _unescape_pdf_literal(body: str) -> str:
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            n = body[i + 1]
            out.append({"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f"}.get(n, n))
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _read_literal(text: str, i: int) -> tuple[str, int]:
    """Read a PDF literal string starting at '(' with balanced parentheses."""
    depth, j = 0, i
    while j < len(text):
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return _unescape_pdf_literal(text[i + 1:j]), j + 1
        j += 1
    return _unescape_pdf_literal(text[i + 1:]), len(text)


def _tokenize(text: str) -> list:
    """Tokenize pdf-parser's dictionary rendering.

    pdf-parser prints values containing spaces as Python reprs, e.g.
    '(AFNumber_Format\\(2, 0\\);)', and simple values bare, e.g. (cmd.exe).
    Both become PdfStr tokens."""
    import ast
    toks: list = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif text.startswith("<<", i) or text.startswith(">>", i):
            toks.append(text[i:i + 2])
            i += 2
        elif c in "[]":
            toks.append(c)
            i += 1
        elif c in "'\"":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            raw = text[i:j + 1]
            try:
                inner = ast.literal_eval(raw)
            except (ValueError, SyntaxError):
                inner = raw[1:-1]
            if isinstance(inner, bytes):
                inner = inner.decode("latin-1")
            inner = str(inner).strip()
            if inner.startswith("("):
                toks.append(PdfStr(_read_literal(inner, 0)[0]))
            elif inner.startswith("<") and not inner.startswith("<<"):
                toks.append(PdfStr(inner))
            else:
                toks.extend(_tokenize(inner) or [PdfStr(inner)])
            i = j + 1
        elif c == "(":
            val, i = _read_literal(text, i)
            toks.append(PdfStr(val))
        elif c == "<":
            j = text.find(">", i)
            j = n if j == -1 else j
            hexpart = re.sub(r"\s", "", text[i + 1:j])
            try:
                toks.append(PdfStr(bytes.fromhex(hexpart + ("0" if len(hexpart) % 2 else "")).decode("latin-1")))
            except ValueError:
                toks.append(PdfStr(text[i:j + 1]))
            i = j + 1
        elif c == "/":
            j = i + 1
            while j < n and not text[j].isspace() and text[j] not in _DELIMS:
                j += 1
            toks.append(text[i:j])
            i = j
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in _DELIMS and text[j] not in "'\"":
                j += 1
            if j == i:
                j = i + 1
            toks.append(text[i:j])
            i = j
    # fold "N G R" into references
    out: list = []
    k = 0
    while k < len(toks):
        t = toks[k]
        if (not isinstance(t, PdfStr) and isinstance(t, str) and t.isdigit() and k + 2 < len(toks)
                and isinstance(toks[k + 1], str) and not isinstance(toks[k + 1], PdfStr)
                and toks[k + 1].isdigit() and toks[k + 2] == "R"):
            out.append(Ref(int(t)))
            k += 3
            continue
        out.append(t)
        k += 1
    return out


def _parse_value(toks: list, i: int):
    t = toks[i]
    if t == "<<" and not isinstance(t, PdfStr):
        d: dict = {}
        i += 1
        while i < len(toks) and toks[i] != ">>":
            key = toks[i]
            if not isinstance(key, str) or isinstance(key, PdfStr) or not key.startswith("/"):
                i += 1
                continue
            if i + 1 >= len(toks) or toks[i + 1] == ">>":
                d[key] = None
                i += 1
                continue
            val, i = _parse_value(toks, i + 1)
            d[key] = val
        return d, i + 1
    if t == "[" and not isinstance(t, PdfStr):
        arr = []
        i += 1
        while i < len(toks) and toks[i] != "]":
            v, i = _parse_value(toks, i)
            arr.append(v)
        return arr, i + 1
    return t, i + 1


def parse_dictionary(text: str):
    """Parse pdf-parser's rendering of an object into Python values (dict/list/Ref/PdfStr/str)."""
    toks = _tokenize(text)
    for i, t in enumerate(toks):
        if t == "<<" and not isinstance(t, PdfStr):
            try:
                return _parse_value(toks, i)[0]
            except (IndexError, RecursionError):
                return None
    return None


# --------------------------------------------------------------------- triggers

AA_MEANING = {
    "page": {"/O": "when the page is opened", "/C": "when the page is closed"},
    "document": {"/WC": "before the document closes", "/WS": "before the document is saved",
                 "/DS": "after the document is saved", "/WP": "before the document prints",
                 "/DP": "after the document prints"},
    "field": {"/K": "on each keystroke in the field", "/F": "when the field value is formatted",
              "/V": "when the field value is validated", "/C": "when the field is recalculated",
              "/E": "when the mouse enters the field", "/X": "when the mouse leaves the field",
              "/D": "on mouse button down", "/U": "on mouse button up (click)",
              "/Fo": "when the field gets focus", "/Bl": "when the field loses focus",
              "/PO": "when the page containing it opens", "/PC": "when its page closes",
              "/PV": "when its page becomes visible", "/PI": "when its page is no longer visible"},
}
AA_MEANING["annotation"] = AA_MEANING["field"]

BENIGN_JS = ("AFNumber_", "AFSimple_Calculate", "AFDate_", "AFPercent_", "AFSpecial_", "AFRange_",
             "AFTime_", "AFMergeChange")
EVIL_JS = ("eval", "unescape", "fromCharCode", "util.printf", "exportDataObject", "launchURL",
           "submitForm", "getAnnots", "spray", "%u", "\\x", "Collab.", "media.newPlayer")


@dataclass
class Trigger:
    """One event and the action it runs, e.g. page opened -> JavaScript in obj 5."""
    source: int
    source_kind: str
    event: str          # e.g. "/AA /C", "/OpenAction", "/A"
    when: str
    action_obj: int | None
    action_type: str    # /JavaScript, /Launch, /URI, ...
    target: str         # URL, file, inline JS preview, or "JavaScript in obj N"
    payload_obj: int | None
    severity: Severity
    note: str = ""


def _kind(d: dict) -> str:
    t = d.get("/Type")
    if t == "/Catalog":
        return "document"
    if t == "/Page":
        return "page"
    if "/FT" in d or "/T" in d and "/Kids" not in d and d.get("/Subtype") == "/Widget":
        return "field"
    if t == "/Annot" or "/Subtype" in d:
        return "annotation"
    return "object"


def _str(v) -> str:
    if isinstance(v, PdfStr):
        return str(v)
    if isinstance(v, str):
        return v[1:-1] if v.startswith("(") and v.endswith(")") else v
    if isinstance(v, dict):
        for k in ("/F", "/UF", "/DOS", "/Unix"):
            if k in v:
                return _str(v[k])
        return "<dictionary>"
    if isinstance(v, Ref):
        return f"obj {v.id}"
    return str(v)


UNREADABLE = "(encrypted, unreadable)"
ENCRYPTED_NOTE = ("PDF is encrypted: pdf-parser sees ciphertext, so this script can't be read here. "
                  "Use Decrypt PDF to analyze a readable copy.")


def analyze_triggers(pdf: ParsedPdf) -> list[Trigger]:
    """Trace /OpenAction, /AA and /A entries (and their /Next chains) to the action each one runs."""
    dicts = {o.id: parse_dictionary(o.text) for o in pdf.objects}
    objs = {o.id: o for o in pdf.objects}
    out: list[Trigger] = []
    reached: set[int] = set()

    def resolve(v):
        if isinstance(v, Ref):
            d = dicts.get(v.id)
            return (d if isinstance(d, dict) else None), v.id
        if isinstance(v, dict):
            return v, None
        return None, None

    def handle(src: int, kind: str, event: str, when: str, value, depth: int = 0):
        if depth > 8:
            return
        if isinstance(value, list):
            # OpenAction destination array [page /Fit] = navigation; or array of /Next actions
            if value and isinstance(value[0], Ref) and objs.get(value[0].id) and \
                    (dicts.get(value[0].id) or {}).get("/Type") == "/Page":
                out.append(Trigger(src, kind, event, when, None, "Go to page",
                                   f"page obj {value[0].id} " + " ".join(map(_str, value[1:])),
                                   None, Severity.INFO, "Page navigation / zoom: harmless."))
                return
            for item in value:
                handle(src, kind, event, when + " (chained)", item, depth + 1)
            return
        act, act_id = resolve(value)
        if act is None:
            return
        if act_id is not None:
            reached.add(act_id)
        s_type = _str(act.get("/S", act.get("/Type", "?")))
        payload, target, note, sev = None, "", "", Severity.LOW
        if s_type == "/JavaScript":
            js = act.get("/JS")
            if isinstance(js, Ref):
                payload = js.id
                target = f"JavaScript in obj {js.id} (stream)"
                reached.add(js.id)
            else:
                code = _str(js)
                target = code[:160]
                if any(b in code for b in BENIGN_JS) and not any(e in code for e in EVIL_JS):
                    note = "Standard Acrobat form formatting/calculation: usually benign."
                elif pdf.encrypted:
                    target = UNREADABLE
                    note = ENCRYPTED_NOTE
            if note == ENCRYPTED_NOTE:
                sev = Severity.MEDIUM
            elif note:
                sev = Severity.LOW
            else:
                sev = Severity.HIGH
        elif s_type == "/Launch":
            target = _str(act.get("/F", act.get("/Win", act.get("/Unix", ""))))
            sev = Severity.HIGH
            if pdf.encrypted and not _readable_target(target):
                target = UNREADABLE
        elif s_type in ("/URI",):
            target = _str(act.get("/URI", ""))
            sev = Severity.MEDIUM
            if pdf.encrypted and not _readable_link(target):
                target, note = UNREADABLE, ENCRYPTED_NOTE
        elif s_type in ("/SubmitForm", "/ImportData"):
            target = _str(act.get("/F", ""))
            sev = Severity.HIGH if s_type == "/ImportData" else Severity.MEDIUM
            if pdf.encrypted and not _readable_target(target):
                target, note = UNREADABLE, ENCRYPTED_NOTE
        elif s_type in ("/GoToR", "/GoToE"):
            target = _str(act.get("/F", ""))
            sev = Severity.MEDIUM
            if pdf.encrypted and not _readable_target(target):
                target, note = UNREADABLE, ENCRYPTED_NOTE
        elif s_type in ("/GoTo", "/Named"):
            target = _str(act.get("/D", act.get("/N", "")))
            sev = Severity.INFO
        else:
            target = s_type
        if event in ("/OpenAction",) or event.startswith("/AA") and kind in ("document", "page"):
            if sev == Severity.MEDIUM and s_type == "/URI":
                note = (note + " Opens automatically, without a click.").strip()
        out.append(Trigger(src, kind, event, when, act_id, s_type, target, payload, sev, note))
        if "/Next" in act:
            handle(src, kind, event, f"{when.split(', then')[0]}, then via /Next", act["/Next"], depth + 1)

    for oid, d in dicts.items():
        if not isinstance(d, dict):
            continue
        kind = _kind(d)
        if "/OpenAction" in d:
            handle(oid, kind, "/OpenAction", "when the document opens", d["/OpenAction"])
        if "/AA" in d:
            aa, aa_id = resolve(d["/AA"])
            if aa_id is not None:
                reached.add(aa_id)
            for key, val in (aa or {}).items():
                when = AA_MEANING.get(kind, AA_MEANING["field"]).get(key, f"on event {key}")
                handle(oid, kind, f"/AA {key}", when, val)
        if "/A" in d and kind in ("annotation", "field", "object"):
            handle(oid, kind, "/A", "when clicked / activated", d["/A"])

    # JavaScript actions nobody points to directly: usually the document-level /Names tree
    for oid, d in dicts.items():
        if isinstance(d, dict) and d.get("/S") in ("/JavaScript", "/Launch") and oid not in reached:
            when = ("when the document opens (document-level script)" if d.get("/S") == "/JavaScript"
                    else "if reached (no trigger found pointing to it; may be via /Names or a hidden path)")
            handle(oid, "document", "/Names JavaScript", when, Ref(oid))
    out.sort(key=lambda t: (-t.severity, t.source))
    return out


def js_source(pdf: ParsedPdf, oid: int, _depth: int = 0) -> tuple[str, str | int | None]:
    """Where is the JavaScript of object `oid`?

    Returns ("inline", code), ("stream", stream_obj_id) or ("none", None).
    Follows /JS references and action objects; an object that only has a stream
    (e.g. obj 7 holding OpenAction code) is returned as a stream."""
    o = pdf.by_id(oid)
    if o is None or _depth > 4:
        return "none", None
    d = parse_dictionary(o.text)
    if isinstance(d, dict):
        js = d.get("/JS")
        if isinstance(js, Ref):
            target = pdf.by_id(js.id)
            if target is not None and target.has_stream:
                return "stream", js.id
            return js_source(pdf, js.id, _depth + 1)
        if isinstance(js, str) and js.strip():
            return "inline", str(js)
        # an object pointing at an action (e.g. /OpenAction 6 0 R, /A << … >>)
        for key in ("/OpenAction", "/A"):
            val = d.get(key)
            if isinstance(val, Ref):
                kind, ref = js_source(pdf, val.id, _depth + 1)
                if kind != "none":
                    return kind, ref
            elif isinstance(val, dict) and isinstance(val.get("/JS"), str):
                return "inline", str(val["/JS"])
    if o.has_stream:
        return "stream", oid
    return "none", None


def facts(pdf: ParsedPdf) -> dict:
    """What pdf-parser established, for cross-tool correlation (core.correlate)."""
    js = [t for t in pdf.triggers if t.action_type == "/JavaScript"]
    benign = [t for t in js if t.severity <= Severity.LOW and t.note and t.note != ENCRYPTED_NOTE]
    explained = {t.action_obj if t.action_obj is not None else t.source for t in benign}
    js_objs = [o.id for o in pdf.objects if "/JS" in o.flags]
    return {
        "encrypted": pdf.encrypted,
        "js_triggers": len(js),
        "js_benign": len(benign),
        "js_unknown": len(js) - len(benign),
        # /JS objects no trigger reaches with a benign script (e.g. a /Names JavaScript entry)
        "js_unexplained": sum(1 for i in js_objs if i not in explained),
        "launch": sum(1 for t in pdf.triggers if t.action_type == "/Launch"),
        "js_objects": len(js_objs),
        # every /JS name pdf-parser saw (pdfid counts names, not objects)
        "js_names": sum(len(re.findall(r"/JS(?![A-Za-z])", o.text)) for o in pdf.objects),
        # output lines this app couldn't place: correlation won't lower anything while > 0
        "unrecognized": len(pdf.unrecognized),
    }


# non-JavaScript actions worth a finding at Medium (URIs are reported from pdf.uris)
OTHER_REPORTED = ("/SubmitForm", "/ImportData", "/GoToR", "/GoToE")
IOC_ACTIONS = ("/URI", "/Launch", "/SubmitForm", "/ImportData", "/GoToR", "/GoToE")


def iocs(pdf: ParsedPdf) -> list[str]:
    """Link and file targets worth recording as indicators: readable values only, so an
    encrypted PDF's ciphertext and the '(encrypted, unreadable)' placeholder never become IOCs."""
    out = list(pdf.uris)
    for t in pdf.triggers:
        v = (t.target or "").strip()
        if t.action_type in IOC_ACTIONS and v and v != UNREADABLE and v.isprintable():
            out.append(v)
    return sorted(set(out))


def findings_from(pdf: ParsedPdf, triggers: list[Trigger] | None = None) -> list[Finding]:
    """Findings for triggers and actions, encryption, links and unrecognized output."""
    out: list[Finding] = []
    if pdf.unrecognized:
        out.append(outputcheck.note("pdf-parser", pdf.unrecognized, versions.version_of("pdf-parser")))
    if pdf.encrypted:
        out.append(Finding("pdf-parser", Severity.MEDIUM, "Encrypted PDF: strings and streams unreadable here",
                           "pdf-parser can't decrypt, so script text, links and stream contents are ciphertext "
                           "and the trigger list may under-report. Decrypt the PDF and analyze the copy.",
                           ref={"tab": "pdf-parser", "kb": "pdf:encrypted_unreadable"}))
    for u in pdf.uris[:20]:
        out.append(Finding("pdf-parser", Severity.MEDIUM, f"URI: {defang(u)[:90]}",
                           "Link target found in a /URI action.",
                           ref={"tab": "pdf-parser", "kb": "pdf:/URI", "keyword": "/URI"}))
    for t in triggers or []:
        reportable = (t.severity >= Severity.HIGH
                      or (t.note == ENCRYPTED_NOTE and t.action_type == "/JavaScript")
                      or (t.severity >= Severity.MEDIUM and t.action_type in OTHER_REPORTED))
        if not reportable:
            continue
        if t.action_type == "/JavaScript":
            where = f"obj {t.payload_obj}" if t.payload_obj is not None else "inline"
            out.append(Finding("pdf-parser", t.severity,
                               f"JavaScript runs {t.when} (obj {t.source} {t.event} → {where})",
                               f"{t.source_kind} obj {t.source}, event {t.event}: {t.when}. "
                               + (f"Action obj {t.action_obj}. " if t.action_obj is not None else "Inline action. ")
                               + t.target[:120],
                               ref={"tab": "pdf-parser", "kb": "pdf:trigger_js", "object": t.source,
                                    "payload": t.payload_obj if t.payload_obj is not None else t.action_obj or t.source,
                                    "keyword": "/JS"}))
        elif t.action_type == "/Launch":
            out.append(Finding("pdf-parser", Severity.HIGH, f"Launch runs {t.when}: {defang(t.target)[:60]}",
                               f"{t.source_kind} obj {t.source}, event {t.event}.",
                               ref={"tab": "pdf-parser", "kb": "pdf:trigger_launch",
                                    "object": t.action_obj or t.source, "keyword": "/Launch"}))
        else:
            what = {"/SubmitForm": "Form data is submitted", "/ImportData": "Data is imported",
                    "/GoToR": "A remote document is opened", "/GoToE": "An embedded document is opened"
                    }.get(t.action_type, t.action_type)
            out.append(Finding("pdf-parser", t.severity, f"{what} {t.when}: {defang(t.target)[:60]}",
                               f"{t.source_kind} obj {t.source}, event {t.event}, action {t.action_type} → "
                               f"{defang(t.target)[:120]}" + (f" {t.note}" if t.note else ""),
                               ref={"tab": "pdf-parser", "kb": f"pdf:{t.action_type}", "keyword": t.action_type,
                                    "object": t.action_obj or t.source}))
    for o in pdf.objects:
        if "/EmbeddedFile" in o.flags:
            out.append(Finding("pdf-parser", Severity.HIGH, f"obj {o.id}: embedded file",
                               "Dump the stream to extract the file.",
                               ref={"tab": "pdf-parser", "kb": "pdf:/EmbeddedFile", "object": o.id,
                                    "keyword": "/EmbeddedFile"}))
    return out


def run_full(path: str, timeout: int = 300) -> ToolResult:
    """Run pdf-parser -O over the whole file and parse its objects and triggers."""
    tool = locate()
    if not tool:
        return ToolResult("pdf-parser", False, "pdf-parser.py",
                          error=f"pdf-parser.py not found ({edition.hint('tools')}).")
    r = scripts.run_script(tool, ["-O", path], timeout, "pdf-parser.py")
    text = r.stdout.decode("latin-1", "replace")
    pdf = parse_full_listing(text)
    pdf.triggers = analyze_triggers(pdf)
    ok = bool(pdf.objects)        # a PDF always has objects: none recognized means we read nothing
    if ok:
        error = ""
    elif r.timed_out or r.stopped or (r.returncode != 0 and not pdf.unrecognized):
        error = scripts.error_summary(r.text) or f"exit code {r.returncode}"
    else:
        error = outputcheck.failure("pdf-parser", pdf.unrecognized or text.splitlines()[:5],
                                    versions.version_of("pdf-parser"),
                                    "no objects found" if not text.strip() else "")
    return ToolResult("pdf-parser", ok, r.command, raw_output=text if len(text) < 2_000_000 else
                      text[:2_000_000] + "\n[display truncated]", data=pdf,
                      findings=findings_from(pdf, pdf.triggers) if ok else [], error=error)


def stream_bytes(path: str, oid: int, filtered: bool = True, objstm: bool = False) -> tuple[bytes, str, str]:
    """Return (stream bytes, command shown, error text) using pdf-parser -d."""
    tool = locate()
    if not tool:
        return b"", "", "pdf-parser.py not found"
    with tempfile.TemporaryDirectory(prefix="mtw_stream_") as tmp:
        dest = os.path.join(tmp, "stream.bin")
        args = ["-o", str(oid)] + (["-f"] if filtered else []) + (["-O"] if objstm else []) + ["-d", dest, path]
        r = scripts.run_script(tool, args, 120, "pdf-parser.py")
        data = b""
        if os.path.isfile(dest):
            with open(dest, "rb") as fh:
                data = fh.read()
        shown = r.command.replace(dest, "<file>")
        err = "" if data else (r.text.strip() or "pdf-parser produced no stream data")
        return data, shown, err


def run_args(path: str, args: list[str], timeout: int = 180) -> scripts.RunResult:
    """Run pdf-parser.py with extra arguments (search, object, filter, ...)."""
    tool = locate()
    if not tool:
        return scripts.RunResult("pdf-parser.py", b"", "pdf-parser.py not found", 127)
    return scripts.run_script(tool, args + [path], timeout, "pdf-parser.py")


def search_ids(text: str) -> list[int]:
    """Object ids appearing in a pdf-parser search result."""
    out = []
    for ln in text.splitlines():
        m = _OBJ_RE.match(ln)
        if m and int(m.group(1)) not in out:
            out.append(int(m.group(1)))
    return out
