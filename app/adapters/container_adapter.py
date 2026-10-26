"""OOXML part browser, external relationships, and document metadata.

zipdump.py gives CLI parity for the part list; the structured view uses
Python's zipfile so it works even if zipdump isn't installed. Metadata uses
olefile (what olemeta/oletimes are built on) and docProps/*.xml for OOXML.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import re
import zipfile
from dataclasses import dataclass, field

from ..core import safexml, zipcheck
from ..core.models import Finding, Severity, ToolResult
from ..core.safety import defang, safe_output_path
from . import scripts

MAX_PART_READ = 64 * 1024 * 1024      # largest single part we decompress
TOTAL_READ_BUDGET = 512 * 1024 * 1024  # total decompressed bytes per package (zip-bomb guard)
MAX_PARTS = 20_000
PREVIEW_BYTES = 4 * 1024 * 1024


@dataclass
class Part:
    """One entry in an OOXML (zip) package."""
    index: int
    name: str
    size: int
    compressed: int
    crc: str
    modified: str
    encrypted: bool
    sha256: str = ""
    kind: str = ""
    note: str = ""


@dataclass
class Relationship:
    """One relationship from the package's _rels files; external ones point outside the document."""
    source_part: str
    rel_id: str
    rel_type: str
    target: str
    external: bool


@dataclass
class PartsData:
    """A package's parts and relationships, and anything skipped or flagged while reading them."""
    parts: list[Part] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    error: str = ""
    skipped_budget: int = 0        # parts not inspected because the budget ran out
    unsafe_xml: list[str] = field(default_factory=list)
    suspicious_ratio: list[str] = field(default_factory=list)

    @property
    def external(self) -> list[Relationship]:
        return [r for r in self.relationships if r.external]


class ZipRejected(ValueError):
    """The archive failed the bounded structure check, so zipfile never parsed it."""


def open_checked(path: str) -> zipfile.ZipFile:
    """zipfile.ZipFile(path), but only after core.zipcheck accepts the archive's structure."""
    result = zipcheck.check(path)
    if not result:
        raise ZipRejected(f"ZIP structure rejected before parsing: {result.reason}")
    return zipfile.ZipFile(path)


def _part_note(name: str, data: bytes) -> str:
    low = name.lower()
    if data[:2] == b"MZ":
        return "PE executable inside the package!"
    if low.endswith("vbaproject.bin"):
        return "VBA project (macros)"
    if "embeddings/" in low or low.endswith(".bin") and "oleobject" in low:
        return "Embedded object"
    if low.endswith("vbadata.xml"):
        return "VBA data"
    if "activex" in low:
        return "ActiveX control"
    if low.endswith(".rels"):
        return "Relationships"
    if "customxml" in low:
        return "Custom XML (sometimes used to hide payloads)"
    return ""


def read_parts(path: str) -> ToolResult:
    """Read the parts and relationships of the package at path, within the decompression budget."""
    data = PartsData()
    try:
        zf = open_checked(path)
    except ZipRejected as exc:
        return ToolResult("parts", False, error=str(exc), data=data)
    except Exception as exc:
        return ToolResult("parts", False, error=f"Not a readable zip: {exc}", data=data)
    budget = TOTAL_READ_BUDGET
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_PARTS:
            data.error += f"{len(infos):,} entries; only the first {MAX_PARTS:,} were inspected.\n"
            data.skipped_budget += len(infos) - MAX_PARTS
            infos = infos[:MAX_PARTS]
        for i, info in enumerate(infos, 1):
            content = b""
            encrypted = bool(info.flag_bits & 0x1)
            if info.compress_size and info.file_size / max(1, info.compress_size) > 200 \
                    and info.file_size > 10 * 1024 * 1024:
                data.suspicious_ratio.append(info.filename)
            if not encrypted and info.file_size <= MAX_PART_READ and info.file_size <= budget:
                try:
                    content = zf.read(info)   # zipfile stops at the declared size and checks the CRC
                    budget -= len(content)
                except Exception as exc:
                    content = b""
                    data.error += f"{info.filename}: {exc}\n"
            elif not encrypted and info.file_size > 0:
                data.skipped_budget += 1
            ts = "%04d-%02d-%02d %02d:%02d:%02d" % info.date_time
            part = Part(i, info.filename, info.file_size, info.compress_size, f"{info.CRC:08X}", ts,
                        encrypted, hashlib.sha256(content).hexdigest() if content else "",
                        scripts.magic_type(content) if content else "", _part_note(info.filename, content))
            data.parts.append(part)
            if info.filename.lower().endswith(".rels") and content:
                try:
                    data.relationships += parse_rels(info.filename, content)
                except safexml.UnsafeXML as exc:
                    data.unsafe_xml.append(f"{info.filename}: {exc}")
    return ToolResult("parts", True, "zipdump.py " + scripts.quote(path), data=data,
                      findings=findings_from(data))


def parse_rels(part_name: str, xml: bytes) -> list[Relationship]:
    """Raises safexml.UnsafeXML for DTD/entity tricks; ignores malformed XML."""
    out = []
    try:
        root = safexml.fromstring(xml)
    except safexml.ParseError:
        return out
    for el in root:
        if not el.tag.endswith("Relationship"):
            continue
        out.append(Relationship(part_name, el.get("Id", ""), el.get("Type", "").rsplit("/", 1)[-1],
                                el.get("Target", ""), el.get("TargetMode", "").lower() == "external"))
    return out


TEMPLATE_TYPES = ("attachedTemplate", "subDocument", "frame", "oleObject")


def findings_from(d: PartsData) -> list[Finding]:
    """Findings for external relationships, unsafe XML, size limits, compression ratios and executables."""
    out: list[Finding] = []
    for r in d.external:
        risky = r.rel_type in TEMPLATE_TYPES or re.match(r"(?i)(https?|ftp|file|\\\\)", r.target or "")
        hyperlink = r.rel_type == "hyperlink"
        sev = Severity.HIGH if (risky and not hyperlink) else Severity.LOW
        what = {"attachedTemplate": "Remote template injection",
                "oleObject": "Remote OLE object", "frame": "Remote frame",
                "subDocument": "Remote sub-document"}.get(r.rel_type, f"External {r.rel_type}")
        out.append(Finding("parts", sev, f"{what}: {defang(r.target)[:80]}",
                           f"{r.source_part} ({r.rel_id}) loads content from outside the document "
                           "when opened." if sev == Severity.HIGH else
                           f"External link in {r.source_part}.",
                           ref={"tab": "parts", "kb": "ooxml:template" if sev == Severity.HIGH else "ooxml:external"}))
    for item in d.unsafe_xml:
        out.append(Finding("parts", Severity.HIGH, "XML with DTD / entity declarations",
                           f"{item}. Office never writes these; they're used to attack XML parsers. "
                           "The part was not parsed.", ref={"tab": "parts", "kb": "ooxml:unsafe_xml"}))
    if d.skipped_budget:
        out.append(Finding("parts", Severity.MEDIUM, f"{d.skipped_budget} part(s) not inspected (size limits)",
                           "The package decompresses to more than the inspection budget "
                           f"({TOTAL_READ_BUDGET // (1024 * 1024)} MB total, {MAX_PART_READ // (1024 * 1024)} MB "
                           "per part). Possible zip bomb or padding to evade scanners.",
                           ref={"tab": "parts", "kb": "ooxml:budget"}))
    if d.suspicious_ratio:
        out.append(Finding("parts", Severity.MEDIUM, "Extreme compression ratio",
                           "Parts that expand more than 200x: " + ", ".join(d.suspicious_ratio[:5]),
                           ref={"tab": "parts", "kb": "ooxml:budget"}))
    for p in d.parts:
        if p.note == "PE executable inside the package!":
            out.append(Finding("parts", Severity.HIGH, f"Executable inside package: {p.name}",
                               "A Windows executable is stored as a document part.",
                               ref={"tab": "parts", "kb": "ooxml:exe", "name": p.name}))
    return out


def read_part(path: str, name: str) -> bytes:
    """Bytes of one part; parts larger than MAX_PART_READ are refused."""
    with open_checked(path) as zf:
        info = zf.getinfo(name)
        if info.file_size > MAX_PART_READ:
            raise ValueError(f"Part is larger than {MAX_PART_READ:,} bytes")
        return zf.read(info)


def preview_part(path: str, name: str, max_bytes: int = PREVIEW_BYTES) -> tuple[bytes, int]:
    """First max_bytes of a part, plus its full size (for display)."""
    with open_checked(path) as zf:
        info = zf.getinfo(name)
        with zf.open(info) as fh:
            return fh.read(max_bytes), info.file_size


def extract_part(path: str, name: str, out_dir: str) -> tuple[str, int, str]:
    """Write one part to out_dir (.bin suffix). Returns (dest, size, sha256)."""
    data = read_part(path, name)
    dest = safe_output_path(out_dir, name.replace("/", "_"))
    with open(dest, "wb") as fh:
        fh.write(data)
    return dest, len(data), hashlib.sha256(data).hexdigest()


def run_zipdump(path: str) -> scripts.RunResult:
    """Run zipdump.py on the file when it's installed (the part list itself doesn't need it)."""
    tool = scripts.locate("zipdump.py")
    if not tool:
        return scripts.RunResult("zipdump.py", b"", "zipdump.py not found (optional). The part list "
                                 "above comes from Python's zipfile.", 127)
    return scripts.run_script(tool, [path], 120, "zipdump.py")


# --------------------------------------------------------------------- metadata


@dataclass
class MetaData:
    """Document properties and OLE stream timestamps."""
    properties: list[tuple[str, str, str]] = field(default_factory=list)   # (group, name, value)
    timestamps: list[tuple[str, str, str]] = field(default_factory=list)   # (entry, created, modified)
    error: str = ""


_OLE_FIELDS = ("codepage title subject author keywords comments template last_saved_by revision_number "
               "total_edit_time last_printed create_time last_saved_time num_pages num_words num_chars "
               "creating_application security codepage_doc category presentation_target bytes lines "
               "paragraphs slides notes hidden_slides mm_clips scale_crop heading_pairs titles_of_parts "
               "manager company links_dirty chars_with_spaces shared_doc link_base hlinks "
               "hlinks_changed version dig_sig content_type content_status language doc_version").split()


def _fmt(v) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace").rstrip("\x00")
    if isinstance(v, _dt.datetime):
        return v.isoformat(sep=" ")
    return "" if v is None else str(v)


def read_metadata(path: str, family: str) -> ToolResult:
    """Read document properties and timestamps (olefile for OLE files, docProps for OOXML)."""
    md = MetaData()
    if family == "OLE":
        try:
            import olefile  # type: ignore
        except ImportError:
            return ToolResult("metadata", False, error="olefile not installed (comes with oletools)", data=md)
        try:
            ole = olefile.OleFileIO(path)
        except Exception as exc:
            return ToolResult("metadata", False, error=f"olefile: {exc}", data=md)
        try:
            meta = ole.get_metadata()
            fields = [a for a in (list(getattr(olefile.OleMetadata, "SUMMARY_ATTRIBS", [])) +
                                  list(getattr(olefile.OleMetadata, "DOCSUM_ATTRIBS", [])))
                      if a != "thumbnail"] or _OLE_FIELDS
            for name in fields:
                v = getattr(meta, name, None)
                if v not in (None, b"", ""):
                    group = ("Summary" if name in getattr(olefile.OleMetadata, "SUMMARY_ATTRIBS", [])
                             else "Document summary")
                    md.properties.append((group, name, _fmt(v)))
            md.timestamps.append(("Root", _fmt(ole.root.getctime()), _fmt(ole.root.getmtime())))
            for entry in ole.listdir(streams=True, storages=True):
                name = "/".join(entry)
                try:
                    c, m = ole.getctime(name), ole.getmtime(name)
                except Exception:
                    c = m = None
                if c or m:
                    md.timestamps.append((name, _fmt(c), _fmt(m)))
        finally:
            ole.close()
        cmd = f"olemeta {scripts.quote(path)}  &&  oletimes {scripts.quote(path)}"
    elif family == "OOXML":
        try:
            with open_checked(path) as zf:
                for part, group in (("docProps/core.xml", "Core"), ("docProps/app.xml", "App"),
                                    ("docProps/custom.xml", "Custom")):
                    try:
                        info = zf.getinfo(part)
                    except KeyError:
                        continue
                    if info.file_size > safexml.MAX_XML_BYTES:
                        md.error += f"{part}: {info.file_size:,} bytes, too large to parse\n"
                        continue
                    try:
                        root = safexml.fromstring(zf.read(info))
                    except (safexml.ParseError, safexml.UnsafeXML) as exc:
                        md.error += f"{part}: {exc}\n"
                        continue
                    for el in root.iter():
                        if el is root or list(el):
                            if el.tag.endswith("property") and el.get("name"):
                                val = "".join(el.itertext()).strip()
                                md.properties.append((group, el.get("name", ""), val))
                            continue
                        if "docPropsVTypes" in el.tag:   # value of a custom property, handled above
                            continue
                        tag = el.tag.split("}", 1)[-1]
                        text = (el.text or "").strip()
                        if text:
                            md.properties.append((group, tag, text))
                for info in zf.infolist():
                    md.timestamps.append((info.filename, "", "%04d-%02d-%02d %02d:%02d:%02d" % info.date_time))
        except Exception as exc:
            return ToolResult("metadata", False, error=str(exc), data=md)
        cmd = "(docProps/core.xml, app.xml, custom.xml)"
    else:
        return ToolResult("metadata", False, error="Metadata view supports OLE2 and OOXML files.", data=md)
    return ToolResult("metadata", True, cmd, data=md, findings=meta_findings(md))


def meta_findings(md: MetaData) -> list[Finding]:
    """Findings for timestamp anomalies, plus an Info line naming the author and last editor."""
    out: list[Finding] = []
    props = {name.lower(): val for _g, name, val in md.properties}
    created = props.get("create_time") or props.get("created")
    modified = props.get("last_saved_time") or props.get("modified")
    if created and modified and modified < created:
        out.append(Finding("metadata", Severity.LOW, "Modified date earlier than created date",
                           f"created {created}, modified {modified}. Possible timestamp tampering or "
                           "a document built by a script.", ref={"tab": "metadata", "kb": "meta:dates"}))
    author = props.get("author") or props.get("creator")
    last = props.get("last_saved_by") or props.get("lastmodifiedby")
    if author or last:
        out.append(Finding("metadata", Severity.INFO, f"Author: {author or '—'} / last saved by: {last or '—'}",
                           "Useful for clustering phishing campaigns.", ref={"tab": "metadata", "kb": "meta:author"}))
    return out
