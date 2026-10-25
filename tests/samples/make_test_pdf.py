#!/usr/bin/env python3
"""Build a HARMLESS PDF that trips the Workbench's detections, for testing.

Nothing in it does anything harmful:
  * JavaScript only shows a message box / writes to the JS console
  * the "encoded payload" decodes to the text "MTW TEST"
  * the link points to example.com (a domain reserved for documentation)
  * the /Launch action targets a text file name that doesn't exist, and only
    on click (Acrobat asks before launching anything anyway)
  * the embedded file is a plain text note

Run:  python make_test_pdf.py  [output.pdf]
"""
import sys
import zlib

OUT = sys.argv[1] if len(sys.argv) > 1 else "MTW_test_sample_benign.pdf"

OPEN_JS = (
    '// MTW test file: harmless demo script\r\n'
    'var msg = "Maldoc Triage Workbench test file. This script only shows this message.";\r\n'
    'var payload = unescape("%u544d%u2057%u4554%u5453"); // decodes to the text "MTW TEST"\r\n'
    'app.alert(msg + " Decoded test string: " + payload);\r\n'
).encode("latin-1")

DOC_JS = b'console.println("MTW test: document-level script ran (harmless).");'
ATTACHMENT = (b"MTW test attachment.\r\nThis is a plain text file embedded in the test PDF "
              b"so the Workbench can detect /EmbeddedFile. It is harmless.\r\n")

PAGE_TEXT = [
    "Maldoc Triage Workbench - HARMLESS test PDF",
    "",
    "This file deliberately contains PDF features the app should flag:",
    "  - /OpenAction -> JavaScript (shows a message box only)",
    "  - Page /AA /O -> JavaScript when the page opens (console message)",
    "  - Form field /AA /F and /K -> AFNumber_Format (benign form script)",
    "  - Document-level JavaScript in the /Names tree",
    "  - Hex-obfuscated name /J#61vaScript",
    "  - /URI link to example.com (reserved test domain)",
    "  - /Launch action on click -> nonexistent text file",
    "  - /EmbeddedFile: a plain text note",
    "  - Data appended after %%EOF",
    "",
    "Nothing in this file is malicious.",
]


def stream_obj(data: bytes, extra: str = "", compress: bool = True) -> bytes:
    body = zlib.compress(data) if compress else data
    filt = " /Filter /FlateDecode" if compress else ""
    return (f"<< /Length {len(body)}{filt}{extra} >>\nstream\n").encode() + body + b"\nendstream"


def page_content() -> bytes:
    lines = ["BT", "/F1 16 Tf", "50 760 Td", "20 TL"]
    for i, t in enumerate(PAGE_TEXT):
        if i == 1:
            lines.append("/F1 11 Tf")
        esc = t.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        lines.append(f"({esc}) Tj T*")
    lines.append("ET")
    # field label and link labels
    lines += ["BT /F1 11 Tf 50 360 Td (Amount field \\(uses AFNumber_Format\\):) Tj ET",
              "BT /F1 11 Tf 50 300 Td (Test link: https://example.com/mtw-test) Tj ET",
              "BT /F1 11 Tf 50 270 Td (Launch test \\(click; target does not exist\\)) Tj ET"]
    return "\n".join(lines).encode("latin-1")


objs: dict[int, bytes] = {
    1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R /AcroForm 10 0 R /Names 12 0 R "
       b"/AA << /WC 17 0 R >> >>",
    2: b"<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>",
    3: b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 612 792 ] /Contents 4 0 R "
       b"/Resources << /Font << /F1 5 0 R >> >> /Annots [ 11 0 R 15 0 R 16 0 R ] "
       b"/AA << /O 8 0 R >> >>",
    4: stream_obj(page_content()),
    5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    # OpenAction -> JavaScript in a compressed stream (obj 7)
    6: b"<< /Type /Action /S /JavaScript /JS 7 0 R >>",
    7: stream_obj(OPEN_JS),
    # Page-open action, with a hex-obfuscated /JavaScript name (#61 = 'a')
    8: b"<< /Type /Action /S /J#61vaScript /JS (console.println\\(\"MTW test: page opened \\(harmless\\)\"\\);) >>",
    10: b"<< /Fields [ 11 0 R ] /DA (/Helv 0 Tf 0 g) >>",
    # Form field with standard (benign) Acrobat formatting scripts
    11: b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (Amount) /Rect [ 280 352 420 372 ] /P 3 0 R "
        b"/V (1234.5) /F 4 "
        b"/AA << /F << /S /JavaScript /JS (AFNumber_Format\\(2, 0, 0, 0, \"$\", true\\);) >> "
        b"/K << /S /JavaScript /JS (AFNumber_Keystroke\\(2, 0, 0, 0, \"$\", true\\);) >> >> >>",
    12: b"<< /JavaScript 13 0 R /EmbeddedFiles 18 0 R >>",
    13: b"<< /Names [ (MTW-doc-script) 14 0 R ] >>",
    14: b"<< /S /JavaScript /JS (" + DOC_JS.replace(b"(", b"\\(").replace(b")", b"\\)") + b") >>",
    # Link annotation -> /URI on click
    15: b"<< /Type /Annot /Subtype /Link /Rect [ 50 295 330 310 ] /Border [ 0 0 0 ] "
        b"/A << /S /URI /URI (https://example.com/mtw-test) >> >>",
    # Link annotation -> /Launch on click (nonexistent harmless target)
    16: b"<< /Type /Annot /Subtype /Link /Rect [ 50 265 330 280 ] /Border [ 0 0 0 ] "
        b"/A << /S /Launch /F (MTW_test_launch_target_does_not_exist.txt) >> >>",
    # Document will-close action -> URI (tests document /AA)
    17: b"<< /Type /Action /S /URI /URI (https://example.com/mtw-test-close) >>",
    # Embedded file
    18: b"<< /Names [ (mtw_test_attachment.txt) 19 0 R ] >>",
    19: b"<< /Type /Filespec /F (mtw_test_attachment.txt) /UF (mtw_test_attachment.txt) /EF << /F 20 0 R >> >>",
    20: stream_obj(ATTACHMENT, f" /Type /EmbeddedFile /Params << /Size {len(ATTACHMENT)} >>"),
    21: b"<< /Title (MTW harmless test PDF) /Author (Maldoc Triage Workbench test generator) "
        b"/Creator (make_test_pdf.py) /CreationDate (D:20261012120000-04'00') >>",
}

out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
offsets = {}
for num in sorted(objs):
    offsets[num] = len(out)
    out += f"{num} 0 obj\n".encode() + objs[num] + b"\nendobj\n"
xref_at = len(out)
size = max(objs) + 1
out += f"xref\n0 {size}\n0000000000 65535 f \n".encode()
for n in range(1, size):
    if n in offsets:
        out += f"{offsets[n]:010d} 00000 n \n".encode()
    else:
        out += b"0000000000 65535 f \n"
out += (f"trailer\n<< /Size {size} /Root 1 0 R /Info 21 0 R >>\nstartxref\n{xref_at}\n%%EOF\n").encode()
out += b"MTW-TEST: harmless data appended after the end-of-file marker so the app can detect it.\n"

with open(OUT, "wb") as fh:
    fh.write(out)
print(f"Wrote {OUT} ({len(out):,} bytes)")
