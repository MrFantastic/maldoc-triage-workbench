"""Headless tests for the Qt-free core and adapter parsing.

Run:  python -m unittest discover -s tests
"""
import io
import os
import sys
import tempfile
import textwrap
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.adapters import pdfid_adapter  # noqa: E402
from app.core.models import Family, Severity  # noqa: E402
from app.core.router import identify  # noqa: E402
from app.core.safety import defang, safe_output_path, sanitize_filename  # noqa: E402
from app.core.session import Sample, SampleTooLarge, Session  # noqa: E402

MIN_PDF = (b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n"
           b"2 0 obj\n<< /S /JavaScript /JS (app.alert(1)) >>\nendobj\ntrailer\n<<>>\n%%EOF\n")


def _ooxml(with_vba: bool) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document/>")
        if with_vba:
            zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0")
    return buf.getvalue()


class RouterTests(unittest.TestCase):
    def test_pdf(self):
        r = identify(MIN_PDF, "a.pdf")
        self.assertEqual(r.family, Family.PDF)
        self.assertEqual(r.header_offset, 0)
        self.assertEqual(r.pdf_version, "%PDF-1.7")
        self.assertEqual(r.warnings, [])

    def test_pdf_header_with_cr_line_endings(self):
        r = identify(b"%PDF-1.7\r%\xe2\xe3\xcf\xd3\r1 0 obj", "a.pdf")
        self.assertEqual(r.pdf_version, "%PDF-1.7")

    def test_pdf_with_leading_junk(self):
        r = identify(b"MZjunk" * 10 + MIN_PDF, "a.pdf")
        self.assertEqual(r.family, Family.PDF)
        self.assertEqual(r.header_offset, 60)
        self.assertTrue(any("offset 60" in w.title for w in r.warnings))

    def test_rtf_disguised_as_doc(self):
        r = identify(b"{\\rtf1\\ansi hello}", "invoice.doc")
        self.assertEqual(r.family, Family.RTF)
        self.assertTrue(any(w.severity == Severity.HIGH and "does not match" in w.title
                            for w in r.warnings))

    def test_rtf_minimal_header(self):
        self.assertEqual(identify(b"{\\rt\\object}", "x.rtf").family, Family.RTF)

    def test_ooxml(self):
        r = identify(_ooxml(False), "a.docx")
        self.assertEqual(r.family, Family.OOXML)
        self.assertFalse(r.has_vba_project)
        r = identify(_ooxml(True), "a.docm")
        self.assertTrue(r.has_vba_project)
        self.assertIn("macro-enabled", r.subtype)

    def test_plain_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", "hi")
        self.assertEqual(identify(buf.getvalue(), "a.zip").family, Family.ZIP)

    def test_ole_magic(self):
        data = bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 600
        self.assertEqual(identify(data, "a.doc").family, Family.OLE)

    def test_polyglot(self):
        data = bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 100 + MIN_PDF
        r = identify(data, "a.doc")
        self.assertEqual(r.family, Family.OLE)
        self.assertTrue(any("Polyglot" in w.title for w in r.warnings))

    def test_slk_and_mht(self):
        self.assertEqual(identify(b"ID;PWXL;N;E\r\n", "a.slk").family, Family.OFFICE_TEXT)
        mht = b"MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=x\r\n"
        self.assertEqual(identify(mht, "a.mht").family, Family.OFFICE_TEXT)

    def test_unknown(self):
        self.assertEqual(identify(b"\x00\x01\x02", "a.bin").family, Family.UNKNOWN)


class SafetyTests(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(defang("go to http://evil.example.com/a.exe now"),
                         "go to hxxp://evil[.]example[.]com/a.exe now")
        self.assertEqual(defang("https://x.y"), "hxxps://x[.]y")
        self.assertEqual(defang("c2 at 10.1.2.3"), "c2 at 10.1.2[.]3")

    def test_sanitize(self):
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("a<b>:c?.exe"), "a_b__c_.exe")
        self.assertEqual(sanitize_filename(""), "extracted")

    def test_safe_output_path_never_overwrites(self):
        with tempfile.TemporaryDirectory() as d:
            p1 = safe_output_path(d, "payload.exe")
            self.assertTrue(p1.endswith("payload.exe.bin"))
            open(p1, "w").close()
            p2 = safe_output_path(d, "payload.exe")
            self.assertNotEqual(p1, p2)


class SessionTests(unittest.TestCase):
    def test_load_and_export(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.pdf")
            with open(p, "wb") as fh:
                fh.write(MIN_PDF)
            s = Sample.load(p)
            self.assertEqual(len(s.sha256), 64)
            self.assertTrue(s.verify_unchanged())
            sess = Session(s)
            self.assertEqual(sess.risk, Severity.INFO)
            self.assertIn('"family": "PDF"', sess.export_json())
            with open(p, "ab") as fh:
                fh.write(b"x")
            self.assertFalse(s.verify_unchanged())

    def test_size_cap(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "big.bin")
            with open(p, "wb") as fh:
                fh.write(b"0" * 100)
            with self.assertRaises(SampleTooLarge):
                Sample.load(p, max_bytes=10)


FAKE_PDFID = textwrap.dedent('''
    #!/usr/bin/env python
    """Stand-in for pdfid.py with the same public surface, used only in tests."""
    import sys
    from xml.dom import minidom

    def PDFiD(file, allNames=False, extraData=False, disarm=False, force=False):
        data = open(file, "rb").read()
        if disarm:
            open(file.replace(".pdf", ".disarmed.pdf"), "wb").write(data.replace(b"/JS", b"/js"))
        doc = minidom.Document()
        root = doc.createElement("PDFiD")
        root.setAttribute("IsPDF", "True" if data.startswith(b"%PDF") else "False")
        root.setAttribute("Header", data[:8].decode())
        root.setAttribute("ErrorOccured", "False")
        root.setAttribute("ErrorMessage", "")
        if extraData:
            root.setAttribute("TotalEntropy", "4.5")
            root.setAttribute("CountCharsAfterLastEOF", "40")
        doc.appendChild(root)
        kws = doc.createElement("Keywords")
        root.appendChild(kws)
        for name in ["obj", "/JS", "/JavaScript", "/OpenAction", "/Launch"]:
            k = doc.createElement("Keyword")
            k.setAttribute("Name", name)
            k.setAttribute("Count", str(data.count(name.encode())))
            k.setAttribute("HexcodeCount", "1" if name == "/JavaScript" else "0")
            kws.appendChild(k)
        return doc

    def Main():
        print("PDFiD fake", " ".join(sys.argv[1:]))

    if __name__ == "__main__":
        Main()
''')


class PdfidAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fake = os.path.join(self.tmp.name, "pdfid.py")
        with open(self.fake, "w") as fh:
            fh.write(FAKE_PDFID)
        self.sample = os.path.join(self.tmp.name, "s.pdf")
        with open(self.sample, "wb") as fh:
            fh.write(MIN_PDF)
        os.environ["MTW_PDFID"] = self.fake
        pdfid_adapter.clear_cache()

    def tearDown(self):
        os.environ.pop("MTW_PDFID", None)
        self.tmp.cleanup()

    def test_run_structured_and_cli(self):
        res = pdfid_adapter.run(self.sample, pdfid_adapter.PdfidOptions(extra=True, nozero=True))
        self.assertTrue(res.ok, res.error)
        self.assertTrue(res.command.startswith("pdfid.py -e -n "))
        self.assertIn("PDFiD fake -e -n", res.raw_output)
        rows = {r.name: r for r in res.data.keywords}
        self.assertEqual(rows["/JS"].count, 1)
        self.assertEqual(rows["/JavaScript"].severity, Severity.HIGH)   # hex-obfuscated
        titles = [f.title for f in res.findings]
        self.assertIn("/OpenAction x1", titles)
        self.assertTrue(any("after last %%EOF" in t for t in titles))
        self.assertFalse(any(t.startswith("/Launch") for t in titles))  # zero count

    def test_disarm_writes_copy_only(self):
        out = os.path.join(self.tmp.name, "out")
        dest, cmd = pdfid_adapter.disarm(self.sample, out)
        self.assertTrue(os.path.isfile(dest))
        self.assertTrue(dest.endswith(".pdf.bin"))
        with open(self.sample, "rb") as fh:
            self.assertEqual(fh.read(), MIN_PDF)  # original untouched

    def test_text_parser(self):
        text = (" PDF Header: %PDF-1.4\n obj                   12\n /JS                    2(1)\n"
                " /Launch                0\n")
        data = pdfid_adapter.parse_pdfid_text(text)
        self.assertTrue(data.is_pdf)
        rows = {r.name: r for r in data.keywords}
        self.assertEqual((rows["/JS"].count, rows["/JS"].hex_count), (2, 1))
        self.assertEqual(rows["obj"].count, 12)

    def test_missing_pdfid(self):
        os.environ["MTW_PDFID"] = "/nonexistent/pdfid.py"
        if pdfid_adapter.locate_pdfid() is None:
            res = pdfid_adapter.run(self.sample, pdfid_adapter.PdfidOptions())
            self.assertFalse(res.ok)
            self.assertIn("not found", res.error)


class OfficeFindingsTests(unittest.TestCase):
    def test_findings_from_suspicious(self):
        from app.adapters.office_adapter import Indicator, OfficeTriageData, findings_from
        d = OfficeTriageData(verdict="SUSPICIOUS", flags="AWX", matches=["AutoOpen", "Shell"],
                             has_xlm=True)
        d.indicators.append(Indicator("ext_rels", "External Relationships", "1",
                                      Severity.HIGH, "HIGH", "http://bad.example/t.dotm"))
        d.indicators.append(Indicator("vba", "VBA Macros", "No", Severity.INFO, "none", ""))
        f = findings_from(d)
        self.assertEqual(f[0].severity, Severity.HIGH)
        self.assertTrue(any("XLM" in x.title for x in f))
        ext = [x for x in f if x.source == "oleid"]
        self.assertEqual(len(ext), 1)
        self.assertIn("hxxp://bad[.]example", ext[0].detail)

    def test_missing_oletools_degrades(self):
        from app.adapters import office_adapter
        if office_adapter.oletools_version() is None:
            res = office_adapter.run(__file__)
            self.assertIn("oletools not installed", res.error)


if __name__ == "__main__":
    unittest.main()
