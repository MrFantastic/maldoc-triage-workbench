"""File-type router: identifies the file family from its bytes.

The extension is only used to *warn* about mismatches (a ".doc" that is
really RTF is a classic maldoc trick); it never decides which tools run.
"""
from __future__ import annotations

import io
import os
import re
import zipfile
from dataclasses import dataclass, field

from .models import Family, Finding, Severity

OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
ZIP_MAGIC = b"PK\x03\x04"
PDF_MAGIC = b"%PDF-"
PDF_HEADER_WINDOW = 1024  # Acrobat accepts the header anywhere in the first 1 KB

EXTENSION_FAMILY = {
    ".pdf": Family.PDF,
    ".doc": Family.OLE, ".dot": Family.OLE, ".xls": Family.OLE, ".xlt": Family.OLE,
    ".ppt": Family.OLE, ".pps": Family.OLE, ".pot": Family.OLE, ".msg": Family.OLE,
    ".pub": Family.OLE, ".vsd": Family.OLE,
    ".docx": Family.OOXML, ".docm": Family.OOXML, ".dotx": Family.OOXML, ".dotm": Family.OOXML,
    ".xlsx": Family.OOXML, ".xlsm": Family.OOXML, ".xlsb": Family.OOXML, ".xltm": Family.OOXML,
    ".xlam": Family.OOXML, ".pptx": Family.OOXML, ".pptm": Family.OOXML, ".ppsm": Family.OOXML,
    ".potm": Family.OOXML, ".ppam": Family.OOXML,
    ".rtf": Family.RTF,
    ".mht": Family.OFFICE_TEXT, ".mhtml": Family.OFFICE_TEXT, ".slk": Family.OFFICE_TEXT,
    ".xml": Family.OFFICE_TEXT,
    ".zip": Family.ZIP,
}

# OLE root stream names that identify the Office application
OLE_SUBTYPES = [
    ("WordDocument", "Word 97-2003 document"),
    ("Workbook", "Excel 97-2003 workbook"),
    ("Book", "Excel 5/95 workbook"),
    ("PowerPoint Document", "PowerPoint 97-2003 presentation"),
    ("__substg1.0_", "Outlook message (.msg)"),
    ("Quill", "Publisher document"),
    ("VisioDocument", "Visio drawing"),
    ("EncryptedPackage", "Encrypted OOXML document (password protected)"),
]


@dataclass
class RouteInfo:
    """What identification found: the file family, subtype, header position and warnings."""
    family: Family
    subtype: str = ""
    header_offset: int | None = None       # where the identifying magic was found
    pdf_version: str = ""
    has_vba_project: bool = False         # OOXML: vbaProject.bin present
    warnings: list[Finding] = field(default_factory=list)


def _identify_ole(data: bytes) -> tuple[str, bool]:
    """Best-effort OLE subtype using olefile (an oletools dependency).

    Returns (subtype, encrypted_package).
    """
    try:
        import olefile  # type: ignore
    except ImportError:
        return ("OLE2 compound file (install oletools for subtype)", False)
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as exc:  # malformed containers are common in malware
        return (f"OLE2 compound file (olefile could not parse: {exc})", False)
    try:
        names = ["/".join(e) for e in ole.listdir(streams=True, storages=True)]
    finally:
        ole.close()
    for marker, label in OLE_SUBTYPES:
        if any(n == marker or n.startswith(marker) for n in names):
            return (label, marker == "EncryptedPackage")
    return ("OLE2 compound file (unrecognised application)", False)


def _identify_zip(data: bytes) -> tuple[Family, str, bool]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except Exception as exc:
        return (Family.ZIP, f"Zip archive (could not list: {exc})", False)
    lower = [n.lower() for n in names]
    has_vba = any(n.endswith("vbaproject.bin") for n in lower)
    if "[content_types].xml" in lower:
        if any(n.startswith("word/") for n in lower):
            sub = "Word document (OOXML)"
        elif any(n.startswith("xl/") for n in lower):
            sub = "Excel workbook (OOXML)"
        elif any(n.startswith("ppt/") for n in lower):
            sub = "PowerPoint presentation (OOXML)"
        else:
            sub = "OOXML package (unrecognised application)"
        if has_vba:
            sub += ", macro-enabled (vbaProject.bin)"
        return (Family.OOXML, sub, has_vba)
    return (Family.ZIP, "Zip archive (no [Content_Types].xml)", False)


def identify(data: bytes, filename: str = "", deep: bool = True) -> RouteInfo:
    """deep=False skips parsing the OLE directory / zip listing (byte signatures only)."""
    head = data[:4096]
    info: RouteInfo

    pdf_pos = data.find(PDF_MAGIC, 0, PDF_HEADER_WINDOW)
    if data.startswith(OLE_MAGIC):
        if deep:
            sub, encrypted = _identify_ole(data)
        else:   # byte signatures only: the EncryptedPackage stream name, in UTF-16
            sub, encrypted = "OLE2 compound file", "EncryptedPackage".encode("utf-16-le") in data
        info = RouteInfo(Family.OLE, sub, header_offset=0)
        if encrypted:
            info.warnings.append(Finding(
                "router", Severity.MEDIUM, "Password-protected Office document",
                "EncryptedPackage stream found. Content must be decrypted before macro "
                "analysis. Use Macros → Decrypt.", ref={"kb": "router:encrypted_office"}))
    elif data.startswith(ZIP_MAGIC):
        if deep:
            fam, sub, has_vba = _identify_zip(data)
        elif b"[Content_Types].xml" in data:
            has_vba = b"vbaProject.bin" in data
            fam, sub = Family.OOXML, "OOXML package (signature match)" + (", macro-enabled" if has_vba else "")
        else:
            fam, sub, has_vba = Family.ZIP, "Zip archive", False
        info = RouteInfo(fam, sub, header_offset=0, has_vba_project=has_vba)
    elif head.startswith(b"{\\rt"):
        info = RouteInfo(Family.RTF, "Rich Text Format", header_offset=0)
    elif pdf_pos != -1:
        m = re.match(rb"%PDF-[0-9.]+", data[pdf_pos:pdf_pos + 16])
        ver = m.group(0).decode("latin-1") if m else data[pdf_pos:pdf_pos + 8].decode("latin-1", "replace")
        info = RouteInfo(Family.PDF, "PDF document", header_offset=pdf_pos, pdf_version=ver)
        if pdf_pos > 0:
            info.warnings.append(Finding(
                "router", Severity.MEDIUM, f"PDF header at offset {pdf_pos}, not 0",
                "Data precedes the %PDF header. Readers accept this, but it is a common "
                "polyglot / evasion technique. Inspect the leading bytes.",
                ref={"offset": 0, "kb": "router:header_offset"}))
    elif head.startswith(b"ID;P") or head.startswith(b"ID;"):
        info = RouteInfo(Family.OFFICE_TEXT, "SYLK spreadsheet (.slk)", header_offset=0)
    elif b"MIME-Version" in head[:2048] and b"multipart" in head.lower():
        info = RouteInfo(Family.OFFICE_TEXT, "MHT / MHTML web archive", header_offset=0)
    elif head.lstrip().startswith(b"<?xml") or head.lstrip().startswith(b"<"):
        if b"pkg:package" in head:
            sub = "Flat OPC (single-file Office XML)"
        elif b"schemas.microsoft.com/office/word/2003/wordml" in head:
            sub = "Word 2003 XML"
        elif b"urn:schemas-microsoft-com:office" in head:
            sub = "Office XML / HTML"
        else:
            sub = ""
        info = RouteInfo(Family.OFFICE_TEXT if sub else Family.UNKNOWN,
                         sub or "XML / markup (not recognised as Office)", header_offset=0)
    else:
        info = RouteInfo(Family.UNKNOWN, "Unrecognised format")
        late = data.find(PDF_MAGIC)
        if late != -1:
            info.warnings.append(Finding(
                "router", Severity.MEDIUM, f"%PDF marker found deep in file (offset {late})",
                "Outside the 1 KB header window, so readers will not treat this as a PDF, "
                "but it may be an embedded or carved document.", ref={"offset": late, "kb": "router:late_pdf"}))

    if info.family != Family.PDF and pdf_pos != -1:
        info.warnings.append(Finding(
            "router", Severity.HIGH, f"Polyglot: %PDF header at offset {pdf_pos} inside a {info.family.value}",
            "This file is valid as more than one format. PDF readers will also open it as a PDF.",
            ref={"offset": pdf_pos, "kb": "router:polyglot"}))

    # Extension vs. content mismatch
    ext = os.path.splitext(filename)[1].lower()
    expected = EXTENSION_FAMILY.get(ext)
    if expected is not None and expected != info.family:
        sev = Severity.HIGH if info.family in (Family.RTF, Family.OLE, Family.OOXML) else Severity.MEDIUM
        info.warnings.append(Finding(
            "router", sev, f"Extension '{ext}' does not match content ({info.family.value})",
            "The file's content type differs from its extension. Office opens by content, "
            "so this is a common way to slip RTF exploits or macro documents past filters.",
            ref={"kb": "router:mismatch"}))
    return info


def data_after_eof(data: bytes) -> tuple[int, int] | None:
    """(offset, length) of the bytes after a PDF's last %%EOF, ignoring the end-of-line
    and padding that normally follow it. None if nothing meaningful follows."""
    idx = data.rfind(b"%%EOF")
    if idx == -1:
        return None
    start = idx + 5
    rest = data[start:]
    stripped = rest.lstrip(b"\r\n\t \x00")
    if not stripped:
        return None
    start += len(rest) - len(stripped)
    return start, len(data) - start
