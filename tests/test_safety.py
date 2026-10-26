"""Safety and correctness: process isolation, cross-tool correlation, encrypted PDFs,
safe XML and zip handling, the JS-engine block and artifact export (no Qt needed)."""
import os
import re
import sys
import tempfile
import textwrap
import threading
import time
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.adapters import clitools, container_adapter as ca, isolated, pdf_crypto  # noqa: E402
from app.adapters import pdfparser_adapter as pp, peepdf_adapter as pe, scripts  # noqa: E402
from app.core import codec, correlate, guidance, safexml, safezip, vendor_manifest  # noqa: E402
from app.core.models import Family, Finding, Severity, ToolResult  # noqa: E402
from app.core.router import data_after_eof, identify  # noqa: E402
from app.core.safety import csv_safe  # noqa: E402
from app.core.session import Sample, Session  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIN_PDF = (b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n")

FORM_ONLY = textwrap.dedent("""\
    obj 1 0
     Type: /Catalog
     Referencing: 2 0 R

      <<
        /Type /Catalog
        /AcroForm 2 0 R
      >>


    obj 11 0
     Type: /Annot
     Referencing:

      <<
        /Type /Annot
        /Subtype /Widget
        /AA
          <<
            /F
              <<
                /S /JavaScript
                /JS '(AFNumber_Format\\\\(2, 0, 0, 0, "$", true\\\\);)'
              >>
            /K
              <<
                /S /JavaScript
                /JS '(AFNumber_Keystroke\\\\(2, 0, 0, 0, "$", true\\\\);)'
              >>
          >>
      >>
""")

ENCRYPTED_LISTING = textwrap.dedent("""\
    obj 1 0
     Type: /Catalog
     Referencing: 4 0 R

      <<
        /Type /Catalog
        /OpenAction 4 0 R
      >>


    obj 4 0
     Type: /Action
     Referencing:

      <<
        /S /JavaScript
        /JS (\\x8f\\x12\\xa0\\x9b\\xc3)
      >>


    trailer
      <<
        /Root 1 0 R
        /Encrypt 9 0 R
      >>
""")


def _pdfid_finding(keyword: str, count: int, sev=Severity.HIGH, hexcount=0) -> Finding:
    return Finding("pdfid", sev, f"{keyword} x{count}", "keyword",
                   ref={"kb": f"pdf:{keyword}", "keyword": keyword, "count": count, "hex": hexcount})


# ------------------------------------------------------------------ codec
class CodecTests(unittest.TestCase):
    def test_round_trip(self):
        tr = ToolResult("pdfid", True, "cmd", "raw", data={"b": b"\x00\xff", "t": (1, 2)},
                        findings=[Finding("pdfid", Severity.HIGH, "t", "d", {"keyword": "/JS"})])
        back = codec.loads(codec.dumps(tr))
        self.assertIsInstance(back, ToolResult)
        self.assertEqual(back.findings[0].severity, Severity.HIGH)
        self.assertEqual(back.data["b"], b"\x00\xff")

    def test_unknown_types_rejected(self):
        for evil in ('{"__dc__": "os.system", "x": 1}', '{"__enum__": "Popen", "v": 1}'):
            with self.assertRaises((ValueError, KeyError, TypeError)):
                codec.loads(evil)


# ------------------------------------------------------------------ worker isolation
class WorkerTests(unittest.TestCase):
    def test_echo_and_identify(self):
        self.assertEqual(isolated.call("selftest.echo", {"a": [1, b"x"]}), {"a": [1, b"x"]})
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.pdf")
            with open(p, "wb") as fh:
                fh.write(MIN_PDF)
            route = isolated.identify(p, "x.pdf")
            self.assertEqual(route.family, Family.PDF)

    def test_timeout_kills_worker(self):
        t = time.time()
        with self.assertRaises(isolated.WorkerError) as cm:
            isolated.call("selftest.sleep", 60, timeout=2)
        self.assertLess(time.time() - t, 20)
        self.assertIn("stopped after", str(cm.exception))

    def test_unknown_task_and_remote_error(self):
        with self.assertRaises(isolated.WorkerError):
            isolated.call("no.such.task")
        res = isolated.read_parts("/nonexistent/file.docx")      # a tool failure is a normal reply
        self.assertFalse(res.ok)
        self.assertIn("Not a readable zip", res.error)

    def test_stop_by_generation(self):
        errors = []

        def run():
            scripts.set_job_generation(7)
            try:
                isolated.call("selftest.sleep", 60, timeout=120)
            except isolated.WorkerError as exc:
                errors.append(str(exc))
            finally:
                scripts.set_job_generation(scripts.PERSISTENT)

        th = threading.Thread(target=run)
        th.start()
        for _ in range(100):
            if scripts.active_count():
                break
            time.sleep(0.05)
        time.sleep(0.3)
        self.assertGreaterEqual(scripts.kill_generation(lambda g: g == 7), 1)
        th.join(20)
        self.assertTrue(errors and "stopped by user" in errors[0], errors)

    def test_output_cap_sets_truncated(self):
        r = scripts.run_cmd([sys.executable, "-c", "print('x' * 1000)"], "x", 30, max_output=10)
        self.assertTrue(r.truncated)
        self.assertEqual(len(r.stdout), 10)

    def test_sample_load_falls_back_when_worker_fails(self):
        real = isolated.identify
        isolated.identify = lambda *a: (_ for _ in ()).throw(isolated.WorkerError("crashed"))
        try:
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "x.pdf")
                with open(p, "wb") as fh:
                    fh.write(MIN_PDF)
                s = Sample.load(p)
        finally:
            isolated.identify = real
        self.assertEqual(s.family, Family.PDF)
        self.assertTrue(any(f.ref.get("kb") == "router:identify_failed" for f in s.route.warnings))

    def test_shallow_identify(self):
        ole = bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 64 + "EncryptedPackage".encode("utf-16-le")
        r = identify(ole, "a.docx", deep=False)
        self.assertEqual(r.family, Family.OLE)
        self.assertTrue(any("Password" in w.title for w in r.warnings))


# ------------------------------------------------------------------ correlation (B2)
class CorrelationTests(unittest.TestCase):
    def _facts(self, listing=FORM_ONLY):
        pdf = pp.parse_full_listing(listing)
        pdf.triggers = pp.analyze_triggers(pdf)
        return pp.facts(pdf)

    def test_form_scripts_lower_keyword_findings(self):
        facts = self._facts()
        self.assertEqual((facts["js_triggers"], facts["js_unknown"], facts["js_unexplained"]), (2, 0, 0))
        findings = [_pdfid_finding("/JS", 2), _pdfid_finding("/AA", 1), _pdfid_finding("/Launch", 1)]
        self.assertEqual(correlate.apply(findings, {"pdf-parser": facts}), 2)
        self.assertEqual([f.severity for f in findings], [Severity.MEDIUM, Severity.MEDIUM, Severity.HIGH])
        self.assertIn("pdf-parser read all", findings[0].detail)
        # re-applying is idempotent, and losing the facts restores the originals
        correlate.apply(findings, {"pdf-parser": facts})
        self.assertEqual(findings[0].detail.count("Lowered"), 1)
        correlate.apply(findings, {})
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertNotIn("Lowered", findings[0].detail)

    def test_not_lowered_when_anything_is_unexplained(self):
        facts = self._facts()
        cases = [
            ([_pdfid_finding("/JS", 3)], facts),                                    # pdfid saw more /JS
            ([_pdfid_finding("/JS", 2, hexcount=1)], facts),                        # obfuscated names
            ([_pdfid_finding("/JS", 2)], dict(facts, js_unknown=1)),
            ([_pdfid_finding("/JS", 2)], dict(facts, launch=1)),
            ([_pdfid_finding("/JS", 2)], dict(facts, encrypted=True)),
            ([_pdfid_finding("/JS", 2)], dict(facts, js_unexplained=1)),
        ]
        for findings, f in cases:
            correlate.apply(findings, {"pdf-parser": f})
            self.assertEqual(findings[0].severity, Severity.HIGH, f)

    def test_session_recorrelates(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.pdf")
            with open(p, "wb") as fh:
                fh.write(MIN_PDF)
            sess = Session(Sample.load(p, isolate=False))
        sess.replace_findings("pdfid", [_pdfid_finding("/JS", 2)])
        sess.set_facts("pdf-parser", self._facts())
        self.assertEqual(sess.risk, Severity.MEDIUM)
        sess.mark_failed("pdf-parser", "boom")
        self.assertEqual(sess.risk, Severity.HIGH)


# ------------------------------------------------------------------ encrypted PDFs (B3)
class EncryptedPdfTests(unittest.TestCase):
    def test_encrypted_listing(self):
        pdf = pp.parse_full_listing(ENCRYPTED_LISTING)
        self.assertTrue(pdf.encrypted)
        trig = pp.analyze_triggers(pdf)
        js = [t for t in trig if t.action_type == "/JavaScript"][0]
        self.assertEqual(js.severity, Severity.MEDIUM)
        self.assertEqual(js.note, pp.ENCRYPTED_NOTE)
        titles = [f.title for f in pp.findings_from(pdf, trig)]
        self.assertTrue(any(t.startswith("Encrypted PDF") for t in titles))
        self.assertTrue(pp.facts(pdf)["encrypted"])

    @unittest.skipUnless(pdf_crypto.available(), "needs pikepdf or pypdf")
    def test_decrypt_in_worker(self):
        lib = pdf_crypto.available()
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "enc.pdf")
            if lib == "pikepdf":
                import pikepdf
                with pikepdf.new() as pdf:
                    pdf.add_blank_page()
                    pdf.save(src, encryption=pikepdf.Encryption(user="", owner="o"))
            else:
                import pypdf
                w = pypdf.PdfWriter()
                w.add_blank_page(100, 100)
                w.encrypt("", "o")
                with open(src, "wb") as fh:
                    w.write(fh)
            dest, used = isolated.pdf_decrypt(src, d)
            self.assertTrue(dest.endswith(".bin"))
            with open(dest, "rb") as fh:
                self.assertNotIn(b"/Encrypt", fh.read())
            with self.assertRaises(isolated.WorkerError):
                isolated.pdf_decrypt(dest, d)          # not encrypted any more


# ------------------------------------------------------------------ containers (S4, budgets)
class ContainerSafetyTests(unittest.TestCase):
    def _zip(self, parts: dict) -> str:
        fd, path = tempfile.mkstemp(suffix=".docx")
        os.close(fd)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in parts.items():
                zf.writestr(name, data)
        self.addCleanup(os.remove, path)
        return path

    def test_safexml(self):
        self.assertEqual(safexml.fromstring(b"<a><b/></a>").tag, "a")
        for bad in (b'<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>', b"<!ENTITY a SYSTEM 'file:///etc/passwd'><x/>"):
            with self.assertRaises(safexml.UnsafeXML):
                safexml.fromstring(bad)

    def test_dtd_in_rels_is_a_finding(self):
        rels = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]>'
                b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>')
        path = self._zip({"[Content_Types].xml": "<Types/>", "word/_rels/document.xml.rels": rels})
        res = ca.read_parts(path)
        self.assertTrue(any(f.ref.get("kb") == "ooxml:unsafe_xml" for f in res.findings))

    def test_read_budget(self):
        path = self._zip({"[Content_Types].xml": "<Types/>", "word/a.bin": b"\0" * 300_000,
                          "word/b.bin": b"\0" * 300_000})
        old = ca.TOTAL_READ_BUDGET
        ca.TOTAL_READ_BUDGET = 400_000
        try:
            res = ca.read_parts(path)
        finally:
            ca.TOTAL_READ_BUDGET = old
        self.assertGreaterEqual(res.data.skipped_budget, 1)
        self.assertTrue(any(f.ref.get("kb") == "ooxml:budget" for f in res.findings))

    def test_preview_and_extract(self):
        path = self._zip({"[Content_Types].xml": "<Types/>", "word/x.xml": b"<x>" + b"A" * 100 + b"</x>"})
        data, size = ca.preview_part(path, "word/x.xml", 10)
        self.assertEqual((len(data), size), (10, 107))
        with tempfile.TemporaryDirectory() as d:
            dest, n, sha = isolated.extract_part(path, "word/x.xml", d)
            self.assertTrue(dest.endswith(".bin"))
            self.assertEqual(n, 107)


# ------------------------------------------------------------------ never run sample code
class NoCodeExecutionTests(unittest.TestCase):
    def test_peepdf_console_blocklist(self):
        for cmd in ("js_eval 5", "JS_ANALYSE object 3", "js_vars", "sctest 4", "!dir", "shell ls"):
            self.assertTrue(pe.refused(["info", cmd]), cmd)
        self.assertEqual(pe.refused(["info", "tree", "js_code 5", "object 4", "vtcheck"]), "")
        r = pe.console("x.pdf", ["js_eval 1"])
        self.assertEqual(r.returncode, 126)

    def test_builder_applies_blocklist(self):
        self.assertTrue(clitools._peepdf_refusal(["-C", "info;js_eval 1", "x.pdf"], pe.refused))
        self.assertTrue(clitools._peepdf_refusal(["-i", "x.pdf"], pe.refused))
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("info\nsctest 3\n")
        self.addCleanup(os.remove, fh.name)
        self.assertTrue(clitools._peepdf_refusal(["-s", fh.name, "x.pdf"], pe.refused))
        self.assertEqual(clitools._peepdf_refusal(["-f", "-l", "-j", "x.pdf"], pe.refused), "")

    def test_js_engines_unimportable_in_tools(self):
        env = scripts.tool_env()
        self.assertTrue(env["PYTHONPATH"].startswith(scripts.NOJS_DIR))
        r = scripts.run_cmd([sys.executable, "-c",
                             "import importlib\n"
                             "for m in ('STPyV8', 'PyV8'):\n"
                             "    try:\n        importlib.import_module(m); print('LOADED', m)\n"
                             "    except ImportError: print('blocked', m)"], "x", 30)
        self.assertEqual(r.stdout.decode().split(), ["blocked", "STPyV8", "blocked", "PyV8"])

    def test_tools_see_engine_as_not_installed(self):
        # peepdf-3 catches only ModuleNotFoundError; anything broader would crash it on startup
        r = scripts.run_cmd([sys.executable, "-c",
                             "try:\n    import STPyV8\n    print('LOADED')\n"
                             "except ModuleNotFoundError:\n    print('not installed')"], "x", 30)
        self.assertEqual(r.stdout.decode().strip(), "not installed", r.stderr)

    def test_error_summary_leads_with_exception(self):
        tb = ('Traceback (most recent call last):\n  File "C:\\x\\peepdf.py", line 37, in <module>\n'
              '    from peepdf.PDFCore import PDFParser\nImportError: boom\n')
        self.assertEqual(scripts.error_summary(tb).splitlines()[0], "ImportError: boom")


# ------------------------------------------------------------------ artifacts, manifest, misc
class ArtifactTests(unittest.TestCase):
    def test_safezip_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "a.zip")
            payload = os.urandom(5000) + b"MZ" * 1000
            safezip.write(dest, [("x.bin", payload), ("x.bin", b"dup"), ("MANIFEST.txt", b"hashes")])
            with zipfile.ZipFile(dest) as zf:
                self.assertTrue(all(i.flag_bits & 1 for i in zf.infolist()))
                self.assertEqual(zf.read("x.bin", pwd=b"infected"), payload)
                self.assertEqual(zf.read("x_2.bin", pwd=b"infected"), b"dup")
                with self.assertRaises(RuntimeError):
                    zf.read("x.bin")

    def test_vendor_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "oledump"))
            for rel in ("pdfid.py", "oledump/oledump.py"):
                with open(os.path.join(d, rel), "w") as fh:
                    fh.write("# tool\n")
            self.assertEqual(vendor_manifest.verify(d)[0], "no manifest")
            vendor_manifest.record(d, "test")           # not pinned: consistent, but UNVERIFIED
            status, problems = vendor_manifest.verify(d)
            self.assertEqual(status, "UNVERIFIED")
            self.assertTrue(problems and "pinned" in problems[-1])
            with open(os.path.join(d, "pdfid.py"), "a") as fh:
                fh.write("import os\n")
            status, problems = vendor_manifest.verify(d)
            self.assertEqual(status, "MODIFIED")
            self.assertEqual(vendor_manifest.file_status(d, os.path.join(d, "pdfid.py")), "CHANGED")
            self.assertEqual(vendor_manifest.file_status(d, "/usr/bin/pdfid.py"), "")
            _, changes = vendor_manifest.record(d, "test")
            self.assertTrue(any("pdfid.py" in c for c in changes))

    def test_after_eof_and_csv(self):
        self.assertIsNone(data_after_eof(b"%PDF..%%EOF\r\n"))
        self.assertEqual(data_after_eof(b"%PDF..%%EOF\r\nPK\x03\x04"), (13, 4))
        self.assertEqual(csv_safe("=cmd|' /c calc'!A1"), "'=cmd|' /c calc'!A1")
        self.assertEqual(csv_safe("hxxp://x"), "hxxp://x")


class GuidanceWiringTests(unittest.TestCase):
    def test_every_step_action_is_dispatched(self):
        with open(os.path.join(ROOT, "app", "gui", "main_window.py"), encoding="utf-8") as fh:
            src = fh.read()
        handled = set(re.findall(r'name == "([a-z._]+)"', src))
        for key, g in guidance.GUIDES.items():
            for step in g.steps:
                if step.action:
                    self.assertIn(step.action.partition(":")[0], handled, f"{key}: {step.action}")
        for arg in ("after_eof", "end"):
            self.assertIn(f'arg == "{arg}"', src)


if __name__ == "__main__":
    unittest.main()
