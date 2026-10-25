#!/usr/bin/env python3
"""Build a suite of HARMLESS PDFs that exercise the Workbench's features.

Nothing in these files does anything harmful:
  * every script is plain, readable JavaScript that only shows a message or
    writes to the JavaScript console; nothing is encoded or obfuscated
  * links point to example.com and 192.0.2.10 (both reserved for documentation)
  * /Launch and /GoToR name files that don't exist, and only fire on click
  * embedded and appended files are plain text, and a minimal .docx with one
    hyperlink to example.com

Run:  python make_test_suite.py [output folder]       (encrypted copies need pikepdf)
"""
from __future__ import annotations

import io
import os
import sys
import zipfile
import zlib

OUT = sys.argv[1] if len(sys.argv) > 1 else "MTW_test_suite"


# ---------------------------------------------------------------- PDF writer
def stream_obj(data: bytes, extra: str = "", compress: bool = True) -> bytes:
    body = zlib.compress(data) if compress else data
    filt = " /Filter /FlateDecode" if compress else ""
    return (f"<< /Length {len(body)}{filt}{extra} >>\nstream\n").encode() + body + b"\nendstream"


def pdf_string(text: str) -> bytes:
    return b"(" + text.encode("latin-1").replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)") + b")"


def page_text(lines: list[str], top: int = 760) -> bytes:
    out = ["BT", "/F1 15 Tf", f"50 {top} Td", "18 TL"]
    for i, t in enumerate(lines):
        if i == 1:
            out.append("/F1 10.5 Tf")
        out.append(pdf_string(t).decode("latin-1") + " Tj T*")
    out.append("ET")
    return "\n".join(out).encode("latin-1")


def build(objs: dict[int, bytes], root: int = 1, info: int | None = None, prefix: bytes = b"",
          appended: bytes = b"") -> bytes:
    out = bytearray(prefix + b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num in sorted(objs):
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode() + objs[num] + b"\nendobj\n"
    xref_at = len(out)
    size = max(objs) + 1
    out += f"xref\n0 {size}\n0000000000 65535 f \n".encode()
    for n in range(1, size):
        out += (f"{offsets[n]:010d} 00000 n \n" if n in offsets else "0000000000 65535 f \n").encode()
    trailer = f"/Size {size} /Root {root} 0 R" + (f" /Info {info} 0 R" if info else "")
    out += f"trailer\n<< {trailer} >>\nstartxref\n{xref_at}\n%%EOF\n".encode()
    return bytes(out + appended)


FONT = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"


def info_obj(title: str) -> bytes:
    return (b"<< /Title " + pdf_string(title) + b" /Author (Maldoc Triage Workbench test generator) "
            b"/Creator (make_test_suite.py) /CreationDate (D:20261012120000-04'00') >>")


# ---------------------------------------------------------------- payloads (all harmless)
OPEN_JS = (b"// Maldoc Triage Workbench test file. Harmless: this script only shows a message.\r\n"
           b'app.alert("MTW test file: this harmless script only shows this message.");\r\n')
PAGE_JS = 'console.println("MTW test: page opened (harmless)");'
DOC_JS = 'console.println("MTW test: document-level script (harmless)");'
ATTACHMENT = (b"MTW test attachment.\r\nA plain text file embedded in the test PDF so the Workbench "
              b"detects /EmbeddedFile. It is harmless.\r\n")


def tiny_docx() -> bytes:
    """A minimal .docx: one paragraph, one external hyperlink to example.com, test metadata."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-'
                   'officedocument.wordprocessingml.document.main+xml"/>'
                   '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-'
                   'package.core-properties+xml"/></Types>')
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                   'relationships/officeDocument" Target="word/document.xml"/>'
                   '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/'
                   'metadata/core-properties" Target="docProps/core.xml"/></Relationships>')
        z.writestr("word/document.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>'
                   '<w:p><w:r><w:t>MTW test: a harmless Word document embedded in the test PDF. </w:t></w:r>'
                   '<w:hyperlink r:id="rId10"><w:r><w:t>Test link to example.com</w:t></w:r></w:hyperlink>'
                   '</w:p></w:body></w:document>')
        z.writestr("word/_rels/document.xml.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                   'relationships/hyperlink" Target="https://example.com/mtw-docx-link" TargetMode="External"/>'
                   '</Relationships>')
        z.writestr("docProps/core.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/'
                   'core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" '
                   'xmlns:dcterms="http://purl.org/dc/terms/" '
                   'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
                   '<dc:creator>MTW test generator</dc:creator><cp:lastModifiedBy>MTW tester</cp:lastModifiedBy>'
                   '<dcterms:created xsi:type="dcterms:W3CDTF">2026-10-12T12:00:00Z</dcterms:created>'
                   '<dcterms:modified xsi:type="dcterms:W3CDTF">2026-10-12T12:30:00Z</dcterms:modified>'
                   '</cp:coreProperties>')
    return buf.getvalue()


def appended_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("mtw_appended_note.txt", "MTW test: a harmless text file in a zip appended after %%EOF.\r\n")
    return buf.getvalue()


def form_field(num: int, name: str, rect: str, scripts: dict[str, str], page: int = 3) -> bytes:
    aa = " ".join(f"/{ev} << /S /JavaScript /JS {pdf_string(js).decode('latin-1')} >>" for ev, js in scripts.items())
    return (f"<< /Type /Annot /Subtype /Widget /FT /Tx /T {pdf_string(name).decode('latin-1')} "
            f"/Rect [ {rect} ] /P {page} 0 R /F 4 /AA << {aa} >> >>").encode("latin-1")


# ---------------------------------------------------------------- 01: everything
def kitchen_sink() -> bytes:
    docx = tiny_docx()
    text = ["MTW test 01: triggers, links and embedded files (HARMLESS)", "",
            "Expected: HIGH. JavaScript runs on open, and a /Launch action exists.",
            "  - /OpenAction -> JavaScript in a compressed stream (shows a message)",
            "  - Page /AA /O -> JavaScript (console message)",
            "  - Document-level JavaScript in the /Names tree (console message)",
            "  - Form field with standard AFNumber_* scripts (benign: rated Low)",
            "  - /URI links to example.com and 192.0.2.10 (reserved test addresses)",
            "  - /SubmitForm to example.com, /GoToR to a file that doesn't exist",
            "  - /Launch on click -> a .txt file name that doesn't exist",
            "  - Document /AA /WC (on close) -> /URI",
            "  - Two embedded files: a text note and a small .docx",
            "  - A small zip appended after %%EOF",
            "", "Nothing in this file is malicious."]
    content = page_text(text) + (b"\nBT /F1 10.5 Tf 50 420 Td (Amount field:) Tj ET"
                                 b"\nBT /F1 10.5 Tf 50 380 Td (Links: example.com, 192.0.2.10, submit, "
                                 b"remote doc, launch) Tj ET")
    objs = {
        1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R /AcroForm 10 0 R /Names 12 0 R "
           b"/AA << /WC 17 0 R >> >>",
        2: b"<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 612 792 ] /Contents 4 0 R "
           b"/Resources << /Font << /F1 5 0 R >> >> /Annots [ 11 0 R 15 0 R 16 0 R 22 0 R 23 0 R 24 0 R ] "
           b"/AA << /O 8 0 R >> >>",
        4: stream_obj(content),
        5: FONT,
        6: b"<< /Type /Action /S /JavaScript /JS 7 0 R >>",
        7: stream_obj(OPEN_JS),
        8: b"<< /Type /Action /S /JavaScript /JS " + pdf_string(PAGE_JS) + b" >>",
        10: b"<< /Fields [ 11 0 R ] /DA (/Helv 0 Tf 0 g) >>",
        11: form_field(11, "Amount", "150 412 300 432", {
            "F": 'AFNumber_Format(2, 0, 0, 0, "$", true);', "K": 'AFNumber_Keystroke(2, 0, 0, 0, "$", true);'}),
        12: b"<< /JavaScript 13 0 R /EmbeddedFiles 18 0 R >>",
        13: b"<< /Names [ (MTW-doc-script) 14 0 R ] >>",
        14: b"<< /S /JavaScript /JS " + pdf_string(DOC_JS) + b" >>",
        15: b"<< /Type /Annot /Subtype /Link /Rect [ 50 340 250 355 ] /Border [ 0 0 0 ] "
            b"/A << /S /URI /URI (https://example.com/mtw-test) >> >>",
        16: b"<< /Type /Annot /Subtype /Link /Rect [ 50 320 250 335 ] /Border [ 0 0 0 ] "
            b"/A << /S /Launch /F (MTW_test_launch_target_does_not_exist.txt) >> >>",
        17: b"<< /Type /Action /S /URI /URI (https://example.com/mtw-test-on-close) >>",
        18: b"<< /Names [ (mtw_test_attachment.txt) 19 0 R (mtw_test_document.docx) 25 0 R ] >>",
        19: b"<< /Type /Filespec /F (mtw_test_attachment.txt) /UF (mtw_test_attachment.txt) /EF << /F 20 0 R >> >>",
        20: stream_obj(ATTACHMENT, f" /Type /EmbeddedFile /Params << /Size {len(ATTACHMENT)} >>"),
        21: info_obj("MTW test 01: triggers, links and embedded files"),
        22: b"<< /Type /Annot /Subtype /Link /Rect [ 50 300 250 315 ] /Border [ 0 0 0 ] "
            b"/A << /S /URI /URI (http://192.0.2.10/mtw-test) >> >>",
        23: b"<< /Type /Annot /Subtype /Link /Rect [ 50 280 250 295 ] /Border [ 0 0 0 ] "
            b"/A << /S /SubmitForm /F << /FS /URL /F (https://example.com/mtw-submit) >> /Flags 4 >> >>",
        24: b"<< /Type /Annot /Subtype /Link /Rect [ 50 260 250 275 ] /Border [ 0 0 0 ] "
            b"/A << /S /GoToR /F (MTW_test_remote_doc_does_not_exist.pdf) /D [ 0 /Fit ] >> >>",
        25: b"<< /Type /Filespec /F (mtw_test_document.docx) /UF (mtw_test_document.docx) /EF << /F 26 0 R >> >>",
        26: stream_obj(docx, f" /Type /EmbeddedFile /Subtype /application#2Fvnd.openxmlformats-officedocument."
                             f"wordprocessingml.document /Params << /Size {len(docx)} >>"),
    }
    return build(objs, info=21, appended=appended_zip())


# ---------------------------------------------------------------- 02: form scripts only
def form_only() -> bytes:
    text = ["MTW test 02: a fillable form whose only scripts are standard (HARMLESS)", "",
            "Expected: MEDIUM, not HIGH.",
            "pdfid rates /JS and /AA High by keyword alone. After pdf-parser reads every script",
            "and finds only Acrobat AF* formatting/calculation calls, those findings are lowered",
            "to Medium with the reason in their detail.",
            "", "Fields: Quantity, Unit price, Total (calculated)."]
    content = page_text(text) + (b"\nBT /F1 10.5 Tf 50 520 Td (Quantity:) Tj ET"
                                 b"\nBT /F1 10.5 Tf 50 490 Td (Unit price:) Tj ET"
                                 b"\nBT /F1 10.5 Tf 50 460 Td (Total:) Tj ET")
    objs = {
        1: b"<< /Type /Catalog /Pages 2 0 R /AcroForm 10 0 R >>",
        2: b"<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 612 792 ] /Contents 4 0 R "
           b"/Resources << /Font << /F1 5 0 R >> >> /Annots [ 11 0 R 12 0 R 13 0 R ] >>",
        4: stream_obj(content),
        5: FONT,
        10: b"<< /Fields [ 11 0 R 12 0 R 13 0 R ] /CO [ 13 0 R ] /DA (/Helv 0 Tf 0 g) >>",
        11: form_field(11, "Quantity", "150 512 300 532", {
            "F": "AFNumber_Format(0, 0, 0, 0, \"\", true);", "K": "AFNumber_Keystroke(0, 0, 0, 0, \"\", true);"}),
        12: form_field(12, "UnitPrice", "150 482 300 502", {
            "F": 'AFNumber_Format(2, 0, 0, 0, "$", true);', "K": 'AFNumber_Keystroke(2, 0, 0, 0, "$", true);'}),
        13: form_field(13, "Total", "150 452 300 472", {
            "C": 'AFSimple_Calculate("PRD", new Array ("Quantity", "UnitPrice"));',
            "F": 'AFNumber_Format(2, 0, 0, 0, "$", true);'}),
        21: info_obj("MTW test 02: form scripts only"),
    }
    return build(objs, info=21)


# ---------------------------------------------------------------- 05 / 06
def header_offset() -> bytes:
    text = ["MTW test 05: data before the PDF header, and a .doc extension (HARMLESS)", "",
            "Expected: Medium findings for 'PDF header at offset' and 'Extension does not match'.",
            "No active content."]
    objs = {1: b"<< /Type /Catalog /Pages 2 0 R >>", 2: b"<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>",
            3: b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 612 792 ] /Contents 4 0 R "
               b"/Resources << /Font << /F1 5 0 R >> >> >>",
            4: stream_obj(page_text(text)), 5: FONT, 21: info_obj("MTW test 05: header offset")}
    prefix = b"MTW-TEST: harmless text placed before the %PDF header to test header-offset detection.\n" * 2
    return build(objs, info=21, prefix=prefix)


def clean() -> bytes:
    text = ["MTW test 06: a clean PDF (HARMLESS)", "",
            "Expected: no suspicious findings. Saved with object streams (/ObjStm), as Word and",
            "Chrome do, which on its own must not raise the risk.",
            "", "Lorem ipsum dolor sit amet, consectetur adipiscing elit."]
    objs = {1: b"<< /Type /Catalog /Pages 2 0 R >>", 2: b"<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>",
            3: b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 612 792 ] /Contents 4 0 R "
               b"/Resources << /Font << /F1 5 0 R >> >> >>",
            4: stream_obj(page_text(text)), 5: FONT, 21: info_obj("MTW test 06: clean")}
    return build(objs, info=21)


# ---------------------------------------------------------------- write the suite
def main() -> int:
    os.makedirs(OUT, exist_ok=True)

    def write(name: str, data: bytes) -> str:
        path = os.path.join(OUT, name)
        with open(path, "wb") as fh:
            fh.write(data)
        print(f"  {name}  ({len(data):,} bytes)")
        return path

    p01 = write("MTW_test_01_triggers_links_embedded.pdf", kitchen_sink())
    p02 = write("MTW_test_02_form_scripts_only.pdf", form_only())
    write("MTW_test_05_header_offset_wrong_extension.doc", header_offset())
    p06 = write("MTW_test_06_clean.pdf", clean())
    try:
        import pikepdf
    except ImportError:
        print("pikepdf not installed: skipped 03/04 (encrypted) and object streams in 06.")
        return 0
    with pikepdf.open(p02) as pdf:          # 03: the form file, encrypted with an EMPTY user password
        pdf.save(os.path.join(OUT, "MTW_test_03_encrypted_form_no_password.pdf"),
                 encryption=pikepdf.Encryption(owner="mtw-owner", user="", R=4, aes=True))
    print("  MTW_test_03_encrypted_form_no_password.pdf")
    with pikepdf.open(p01) as pdf:          # 04: the kitchen sink, needs a password to open
        pdf.save(os.path.join(OUT, "MTW_test_04_encrypted_password_mtwtest.pdf"),
                 encryption=pikepdf.Encryption(owner="mtw-owner", user="mtwtest", R=4, aes=True))
    print("  MTW_test_04_encrypted_password_mtwtest.pdf   (password: mtwtest)")
    with pikepdf.open(p06, allow_overwriting_input=True) as pdf:
        pdf.save(p06, object_stream_mode=pikepdf.ObjectStreamMode.generate)
    print("  MTW_test_06_clean.pdf re-saved with object streams")
    return 0


if __name__ == "__main__":
    sys.exit(main())
