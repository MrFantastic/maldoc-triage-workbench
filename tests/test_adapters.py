"""Tool adapters: output parsers, container and metadata readers, JS helpers,
the script runner, and report generation."""
import io
import os
import sys
import tempfile
import textwrap
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.adapters import container_adapter as ca  # noqa: E402
from app.adapters import objects_adapter as oa  # noqa: E402
from app.adapters import oledump_adapter as od  # noqa: E402
from app.adapters import pdfparser_adapter as pp  # noqa: E402
from app.adapters import peepdf_adapter as pe  # noqa: E402
from app.adapters import scripts  # noqa: E402
from app.core import report  # noqa: E402
from app.core.models import Finding, Severity  # noqa: E402
from app.core.session import Sample, Session  # noqa: E402

OLEDUMP_OLE = """\
  1:       114 '\\x01CompObj'
  2:      4096 '\\x05DocumentSummaryInformation'
  3:      4096 '\\x05SummaryInformation'
  4:      7119 '1Table'
  5:       499 'Macros/PROJECT'
  6:        41 'Macros/PROJECTwm'
  7: M    9852 'Macros/VBA/ThisDocument'
  8:      2717 'Macros/VBA/_VBA_PROJECT'
  9: O     616 'ObjectPool/_1234/\\x01Ole10Native'
"""
OLEDUMP_OOXML = """\
A: word/vbaProject.bin
 A1:       421 'PROJECT'
 A2:        71 'PROJECTwm'
 A3: M    1953 'VBA/ThisDocument'
 A4:      2565 'VBA/_VBA_PROJECT'
"""

PDFPARSER_FULL = textwrap.dedent("""\
    PDF Comment '%PDF-1.7\\n'

    obj 1 0
     Type: /Catalog
     Referencing: 2 0 R, 3 0 R

      <<
        /Type /Catalog
        /Pages 2 0 R
        /OpenAction 3 0 R
      >>


    obj 2 0
     Type: /Pages
     Referencing:

      <<
        /Type /Pages
        /Count 0
      >>


    obj 3 0
     Type: /Action
     Referencing: 4 0 R

      <<
        /Type /Action
        /S /JavaScript
        /JS 4 0 R
      >>


    obj 4 0
     Type:
     Referencing:
     Contains stream

      <<
        /Length 44
        /Filter /FlateDecode
      >>


    obj 5 0
     Type: /Annot
     Referencing:

      <<
        /A << /S /URI /URI (http://evil.example.com/landing) >>
      >>


    obj 6 0
     Type: /Action
     Referencing:

      <<
        /S /Launch /F (cmd.exe)
      >>


    xref

    trailer
      <<
        /Size 7
        /Root 1 0 R
      >>

    startxref 1234

    PDF Comment '%%EOF\\n'
""")


_PKG_RELS = "http://schemas.openxmlformats.org/package/2006/relationships"
_DOC_RELS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_CORE_PROPS = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"


def _docx_with_template(target="http://evil.example.com/t.dotm") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document/>")
        zf.writestr("word/_rels/settings.xml.rels",
                    f'<?xml version="1.0"?><Relationships xmlns="{_PKG_RELS}">'
                    f'<Relationship Id="rId1" Type="{_DOC_RELS}/attachedTemplate" '
                    f'Target="{target}" TargetMode="External"/>'
                    f'<Relationship Id="rId2" Type="{_DOC_RELS}/hyperlink" '
                    'Target="https://example.org/" TargetMode="External"/></Relationships>')
        zf.writestr("docProps/core.xml",
                    f'<?xml version="1.0"?><cp:coreProperties xmlns:cp="{_CORE_PROPS}" '
                    'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
                    '<dc:creator>Mallory</dc:creator><cp:lastModifiedBy>Eve</cp:lastModifiedBy>'
                    '<dcterms:created>2026-05-02T10:00:00Z</dcterms:created>'
                    '<dcterms:modified>2026-05-01T10:00:00Z</dcterms:modified></cp:coreProperties>')
        zf.writestr("word/embeddings/oleObject1.bin", b"MZ\x90\x00payload")
    return buf.getvalue()


class OledumpParseTests(unittest.TestCase):
    def test_ole_listing(self):
        sl = od.parse_listing(OLEDUMP_OLE)
        self.assertEqual(len(sl.streams), 9)
        self.assertEqual(sl.streams[6].indicator, "M")
        self.assertEqual(sl.streams[6].name, "Macros/VBA/ThisDocument")
        self.assertEqual(sl.streams[0].name, "\\x01CompObj")
        titles = [f.title for f in od.findings_from(sl)]
        self.assertIn("1 stream(s) with VBA code", titles)
        self.assertIn("1 embedded OLE10Native object(s)", titles)

    def test_ooxml_listing(self):
        sl = od.parse_listing(OLEDUMP_OOXML)
        self.assertEqual([s.index for s in sl.streams], ["A1", "A2", "A3", "A4"])
        self.assertEqual(sl.streams[2].container, "word/vbaProject.bin")


class PdfParserParseTests(unittest.TestCase):
    def test_objects_refs_and_flags(self):
        pdf = pp.parse_full_listing(PDFPARSER_FULL)
        self.assertEqual([o.id for o in pdf.objects], [1, 2, 3, 4, 5, 6])
        o1, o3, o4 = pdf.by_id(1), pdf.by_id(3), pdf.by_id(4)
        self.assertEqual(o1.type, "/Catalog")
        self.assertEqual(o1.references, [2, 3])
        self.assertTrue(o4.has_stream)
        self.assertEqual(o4.referenced_by, [3])
        self.assertIn("/OpenAction", o1.flags)
        self.assertIn("/JavaScript", o3.flags)
        self.assertIn("/JS", o3.flags)
        self.assertEqual(pdf.uris, ["http://evil.example.com/landing"])
        self.assertEqual(len(pdf.trailers), 1)
        trig = pp.analyze_triggers(pdf)
        titles = [f.title for f in pp.findings_from(pdf, trig)]
        self.assertIn("URI: hxxp://evil[.]example[.]com/landing", titles)
        self.assertIn("JavaScript runs when the document opens (obj 1 /OpenAction → obj 4)", titles)
        self.assertTrue(any(t.startswith("Launch runs") and "cmd.exe" in t for t in titles))

    def test_search_ids(self):
        self.assertEqual(pp.search_ids(PDFPARSER_FULL), [1, 2, 3, 4, 5, 6])


class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "lure.docx")
        with open(self.path, "wb") as fh:
            fh.write(_docx_with_template())

    def tearDown(self):
        self.tmp.cleanup()

    def test_parts_and_template_injection(self):
        res = ca.read_parts(self.path)
        self.assertTrue(res.ok)
        names = [p.name for p in res.data.parts]
        self.assertIn("word/embeddings/oleObject1.bin", names)
        ext = res.data.external
        self.assertEqual(len(ext), 2)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        self.assertTrue(any("Remote template injection" in f.title for f in high))
        self.assertTrue(any("Executable inside package" in f.title for f in high))
        low = [f for f in res.findings if f.severity == Severity.LOW]
        self.assertTrue(any("hyperlink" in f.title for f in low))
        self.assertEqual(ca.read_part(self.path, "word/embeddings/oleObject1.bin")[:2], b"MZ")

    def test_ooxml_metadata(self):
        res = ca.read_metadata(self.path, "OOXML")
        self.assertTrue(res.ok, res.error)
        props = {(g, n): v for g, n, v in res.data.properties}
        self.assertEqual(props[("Core", "creator")], "Mallory")
        self.assertEqual(props[("Core", "lastModifiedBy")], "Eve")
        titles = [f.title for f in res.findings]
        self.assertIn("Modified date earlier than created date", titles)


class ObjectsTests(unittest.TestCase):
    def test_collect_renames_and_classifies(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "invoice.exe"), "wb") as fh:
                fh.write(b"MZ\x90\x00")
            with open(os.path.join(d, "note.txt"), "wb") as fh:
                fh.write(b"hello world")
            files = oa._collect(d)
            self.assertEqual(sorted(os.listdir(d)), ["invoice.exe.bin", "note.txt.bin"])
            exe = [f for f in files if f.original_name == "invoice.exe"][0]
            self.assertTrue(exe.dangerous)
            self.assertEqual(exe.kind, "Windows executable (PE)")
            txt = [f for f in files if f.original_name == "note.txt"][0]
            self.assertFalse(txt.dangerous)


class JsWorkbenchTests(unittest.TestCase):
    def test_unescape_variants(self):
        self.assertEqual(pe.unescape_payload('unescape("%u9090%u4141")'), b"\x90\x90\x41\x41")
        self.assertEqual(pe.unescape_payload(r'"\x4d\x5a"'), b"MZ")
        self.assertEqual(pe.unescape_payload("String.fromCharCode(77, 90, 0x41)"), b"MZA")
        self.assertEqual(pe.unescape_payload("%4D%5A"), b"MZ")
        self.assertEqual(pe.unescape_payload("nothing here"), b"")

    def test_beautify_fallback_or_lib(self):
        code, engine = pe.beautify("function a(){var x='{';return x;}")
        self.assertIn("\n", code)
        self.assertIn("'{'", code)
        self.assertTrue(engine)

    def test_peepdf_findings_from_json(self):
        data = {"peepdf_analysis": {
            "peepdf_info": {"author": "x", "url": "https://github.com/digitalsleuth/peepdf-3", "version": "6.0.1"},
            "advanced": [{"version_info": {
                "suspicious_elements": {"triggers": {"/Names": [45, 48, 276]},
                                        "elements": {"/AcroForm": [48, 276], "/JS": [3]},
                                        "js_vulns": [{"name": "CVE-2009-0927", "objects": [3]}]},
                "urls": ["http://evil.example.com/x"]}}]}}
        f = pe.findings_from(data)
        titles = [x.title for x in f]
        self.assertIn("/Names in objects 45, 48, 276", titles)
        self.assertIn("/AcroForm in objects 48, 276", titles)
        self.assertEqual(len([t for t in titles if t.startswith("/AcroForm")]), 1)   # grouped
        sev = {x.title: x.severity for x in f}
        self.assertEqual(sev["/Names in objects 45, 48, 276"], Severity.LOW)
        self.assertEqual(sev["/AcroForm in objects 48, 276"], Severity.MEDIUM)
        self.assertEqual(sev["/JS in objects 3"], Severity.HIGH)
        self.assertTrue(any("CVE-2009-0927" in t for t in titles))
        self.assertTrue(any("hxxp://evil[.]example" in t for t in titles))
        self.assertFalse(any("digitalsleuth" in t for t in titles))       # peepdf's own URL ignored
        self.assertEqual(pe.urls_from(data), ["http://evil.example.com/x"])


class ScriptRunnerTests(unittest.TestCase):
    def test_run_script_and_timeout(self):
        with tempfile.TemporaryDirectory() as d:
            ok = os.path.join(d, "ok.py")
            with open(ok, "w") as fh:
                fh.write("import sys\nsys.stdout.write('args=' + ' '.join(sys.argv[1:]))\n"
                         "sys.stderr.write('warn')\n")
            r = scripts.run_script(ok, ["-a", "x y"], 30)
            self.assertEqual(r.stdout, b"args=-a x y")
            self.assertIn("warn", r.text)
            self.assertEqual(r.returncode, 0)
            slow = os.path.join(d, "slow.py")
            with open(slow, "w") as fh:
                fh.write("import time\ntime.sleep(30)\n")
            r = scripts.run_script(slow, [], 1)
            self.assertTrue(r.timed_out)
            self.assertIn("timeout", r.text)

    def test_inprocess_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.py")
            with open(p, "w") as fh:
                fh.write("import sys\nprint('hi', sys.argv[1])\nsys.exit(3)\n")
            r = scripts._run_inprocess(p, ["there"], "t.py there")
            self.assertEqual(r.stdout.decode().strip(), "hi there")
            self.assertEqual(r.returncode, 3)

    def test_magic(self):
        self.assertEqual(scripts.magic_type(b"MZ\x00"), "Windows executable (PE)")
        self.assertEqual(scripts.magic_type(b"%PDF-1.4"), "PDF")
        self.assertEqual(scripts.magic_type(b"<html><script>"), "HTML / HTA / script")
        self.assertEqual(scripts.magic_type(b"plain text here"), "Text")

    def test_locate_env_override(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "oledump.py")
            open(p, "w").close()
            os.environ["MTW_OLEDUMP"] = p
            try:
                self.assertEqual(scripts.locate("oledump.py"), os.path.realpath(p))
            finally:
                del os.environ["MTW_OLEDUMP"]


class ReportTests(unittest.TestCase):
    def test_report_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.docm")
            with open(p, "wb") as fh:
                fh.write(_docx_with_template())
            sess = Session(Sample.load(p))
            sess.replace_findings("olevba", [Finding("olevba", Severity.HIGH, "AutoExec: <AutoOpen>", "d")])
            sess.set_iocs("olevba", ["http://evil.example.com/a.exe", "http://evil.example.com/a.exe"])
            sess.set_iocs("parts", ["http://evil.example.com/a.exe", "\\\\10.1.2.3\\share"])
            sess.commands.append("olevba x.docm")
            sess.notes = "Reported by finance <script>"
            self.assertEqual(len(sess.all_iocs), 2)
            html_text = report.html_report(sess, "Alex")
            self.assertIn("HIGH RISK", html_text)
            self.assertIn("hxxp://evil[.]example[.]com/a.exe", html_text)
            self.assertNotIn("http://evil.example.com", html_text)
            self.assertIn("&lt;AutoOpen&gt;", html_text)          # escaped
            self.assertNotIn("<script>", html_text)
            summary = report.phishing_summary(sess)
            self.assertIn("Verdict: HIGH RISK", summary)
            self.assertIn(sess.sample.sha256, summary)
            csv_text = report.ioc_csv(sess)
            self.assertIn("10.1.2[.]3", csv_text)
            self.assertIn('"iocs_defanged"', sess.export_json())


if __name__ == "__main__":
    unittest.main()


TRIGGER_LISTING = textwrap.dedent("""\
    obj 1 0
     Type: /Catalog
     Referencing: 2 0 R, 9 0 R, 20 0 R

      <<
        /Type /Catalog
        /Pages 2 0 R
        /OpenAction [ 3 0 R /Fit ]
        /AA
          <<
            /WC 9 0 R
          >>
        /Names 20 0 R
      >>


    obj 3 0
     Type: /Page
     Referencing: 4 0 R

      <<
        /Type /Page
        /AA << /O 4 0 R >>
      >>


    obj 4 0
     Type: /Action
     Referencing: 5 0 R

      <<
        /Type /Action
        /S /JavaScript
        /JS 5 0 R
        /Next 6 0 R
      >>


    obj 5 0
     Type:
     Referencing:
     Contains stream

      <<
        /Length 40
        /Filter /FlateDecode
      >>


    obj 6 0
     Type: /Action
     Referencing:

      <<
        /S /Launch
        /F (cmd.exe)
      >>


    obj 7 0
     Type: /Annot
     Referencing: 8 0 R

      <<
        /Type /Annot
        /Subtype /Widget
        /FT /Tx
        /T (Total)
        /AA << /C << /S /JavaScript /JS (AFSimple_Calculate\\("SUM", new Array \\("a"\\)\\);) >> /F 8 0 R >>
      >>


    obj 8 0
     Type:
     Referencing:

      <<
        /S /JavaScript
        /JS (AFNumber_Format\\(2, 0, 0, 0, "", true\\);)
      >>


    obj 9 0
     Type:
     Referencing:

      <<
        /S /URI
        /URI (http://evil.example.com/bye)
      >>


    obj 10 0
     Type:
     Referencing: 11 0 R

      <<
        /S /JavaScript
        /JS 11 0 R
      >>


    obj 11 0
     Type:
     Referencing:
     Contains stream

      <<
        /Length 10
      >>
""")


class TriggerTests(unittest.TestCase):
    def setUp(self):
        self.pdf = pp.parse_full_listing(TRIGGER_LISTING)
        self.trig = pp.analyze_triggers(self.pdf)

    def by(self, src, event):
        return [t for t in self.trig if t.source == src and t.event == event]

    def test_dictionary_parser(self):
        d = pp.parse_dictionary(self.pdf.by_id(7).text)
        self.assertEqual(d["/FT"], "/Tx")
        self.assertIsInstance(d["/AA"]["/F"], pp.Ref)
        self.assertEqual(d["/AA"]["/C"]["/S"], "/JavaScript")
        self.assertEqual(pp.parse_dictionary(self.pdf.by_id(1).text)["/OpenAction"][0], pp.Ref(3))

    def test_openaction_page_navigation_is_benign(self):
        t = self.by(1, "/OpenAction")[0]
        self.assertEqual(t.action_type, "Go to page")
        self.assertEqual(t.severity, Severity.INFO)

    def test_page_open_js_and_next_launch(self):
        js = self.by(3, "/AA /O")
        types = [t.action_type for t in js]
        self.assertEqual(types[:1] + sorted(types[1:]), ["/JavaScript", "/Launch"][:len(types)] or types)
        j = [t for t in js if t.action_type == "/JavaScript"][0]
        self.assertEqual(j.payload_obj, 5)
        self.assertEqual(j.when, "when the page is opened")
        self.assertEqual(j.severity, Severity.HIGH)
        launch = [t for t in js if t.action_type == "/Launch"][0]
        self.assertEqual(launch.target, "cmd.exe")
        self.assertIn("then via /Next", launch.when)
        self.assertTrue(launch.when.startswith("when the page is opened"))

    def test_field_formatting_scripts_are_benign(self):
        calc = self.by(7, "/AA /C")[0]
        self.assertEqual(calc.when, "when the field is recalculated")
        self.assertEqual(calc.severity, Severity.LOW)
        self.assertIn("usually benign", calc.note)
        fmt = self.by(7, "/AA /F")[0]
        self.assertEqual(fmt.action_obj, 8)
        self.assertEqual(fmt.severity, Severity.LOW)

    def test_document_close_uri(self):
        t = self.by(1, "/AA /WC")[0]
        self.assertEqual(t.when, "before the document closes")
        self.assertEqual(t.target, "http://evil.example.com/bye")

    def test_unreferenced_js_is_reported(self):
        t = [t for t in self.trig if t.source == 10][0]
        self.assertEqual(t.payload_obj, 11)
        self.assertIn("document-level", t.when)
        self.assertTrue(t.when.startswith("when the document opens"))

    def test_findings_point_at_payload(self):
        f = pp.findings_from(self.pdf, self.trig)
        js = [x for x in f if x.ref.get("kb") == "pdf:trigger_js"]
        self.assertTrue(any(x.ref["payload"] == 5 for x in js))
        self.assertFalse(any(x.ref.get("object") == 7 for x in js))   # benign AF* scripts not flagged
        self.assertTrue(any(x.ref.get("kb") == "pdf:trigger_launch" for x in f))


class GuidanceTests(unittest.TestCase):
    def test_every_emitted_key_has_guidance(self):
        import glob
        import re
        from app.core import guidance
        keys = set()
        for path in glob.glob(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                           "app", "**", "*.py"), recursive=True):
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
            for m in re.finditer(r'"kb": "([a-z_]+:[^"{}]+)"', src):
                keys.add(m.group(1))
        missing = [k for k in keys if k not in guidance.GUIDES]
        self.assertEqual(missing, [])

    def test_placeholders_filled(self):
        from app.core import guidance
        f = Finding("pdf-parser", Severity.HIGH, "x", "", ref={"kb": "pdf:trigger_js", "payload": 5})
        steps = guidance.steps_for(f)
        self.assertEqual(steps[0].action, "pdf.object:5")
        self.assertIn("-o 5", steps[0].cli)
        g = Finding("pdfid", Severity.MEDIUM, "/AA x3", "", ref={"kb": "pdf:/AA", "keyword": "/AA"})
        self.assertIn("pdf.search:/AA", [s.action for s in guidance.steps_for(g)])
        # unfilled placeholder -> manual step, no broken action
        h = Finding("pdf-parser", Severity.HIGH, "x", "", ref={"kb": "pdf:trigger_js"})
        self.assertEqual(guidance.steps_for(h)[0].action, "")

    def test_contextual_pdf_severity(self):
        from app.adapters.pdfid_adapter import contextual_severity
        self.assertEqual(contextual_severity("/AA", {"/AA", "/AcroForm"}), Severity.MEDIUM)
        self.assertEqual(contextual_severity("/AA", {"/AA", "/JS"}), Severity.HIGH)
        self.assertEqual(contextual_severity("/AcroForm", {"/AcroForm"}), Severity.LOW)
        self.assertEqual(contextual_severity("/OpenAction", {"/OpenAction"}), Severity.MEDIUM)
        self.assertEqual(contextual_severity("/AA", {"/AA"}, obfuscated=True), Severity.HIGH)


OPTPARSE_HELP = """\
Usage: pdf-parser.py [options] pdf-file|zip-file|url
pdf-parser, use it to parse a PDF document

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -m, --man             Print manual
  -s SEARCH, --search=SEARCH
                        string to search in indirect objects (except streams)
  -f, --filter          pass stream object through filters (FlateDecode,
                        ASCIIHexDecode, ASCII85Decode, LZWDecode and
                        RunLengthDecode only)
  -o OBJECT, --object=OBJECT
                        id(s) of indirect object(s) to select, use comma (,)
                        to separate ids (version independent)
  -d DUMP, --dump=DUMP  filename to dump stream content to
  --searchstream=SEARCHSTREAM
                        string to search in streams
  -O, --objstm          parse stream of /ObjStm objects
"""

ARGPARSE_HELP = """\
usage: oleobj [-h] [-r] [-d OUTPUT_DIR] [--log LOGLEVEL] FILE [FILE ...]

positional arguments:
  FILE                  File(s) to analyze

options:
  -h, --help            show this help message and exit
  -r                    find files recursively in subdirectories.
  -d OUTPUT_DIR         use specified directory to output files.
  --log LOGLEVEL        logging level debug/info/warning/error/critical
                        (default=warning)
  -m {all,dde}, --mode {all,dde}
                        which fields
"""


class HelpParserTests(unittest.TestCase):
    def test_optparse(self):
        from app.adapters import clitools as ct
        opts = ct.parse_help(OPTPARSE_HELP)
        flags = [o.flag for o in opts]
        self.assertEqual(flags, ["--man", "--search", "--filter", "--object", "--dump", "--searchstream", "--objstm"])
        s = opts[1]
        self.assertEqual((s.short, s.long, s.metavar), ("-s", "--search", "SEARCH"))
        self.assertIn("except streams", s.help)
        self.assertIn("RunLengthDecode", opts[2].help)          # continuation lines joined
        self.assertFalse(opts[2].takes_value)
        self.assertTrue(opts[4].wants_path)                      # DUMP -> file picker
        self.assertEqual(opts[4].help, "filename to dump stream content to")
        cur = ct.curate("pdf-parser", opts)
        self.assertNotIn("--man", [o.flag for o in cur])         # manual flag removed from the form
        self.assertEqual(cur[0].group, "Common")
        self.assertTrue(any(o.label == "Search keyword" for o in cur))

    def test_argparse_and_choices(self):
        from app.adapters import clitools as ct
        opts = ct.parse_help(ARGPARSE_HELP)
        by = {o.flag: o for o in opts}
        self.assertNotIn("FILE", by)                              # positional ignored
        self.assertEqual(by["-d"].metavar, "OUTPUT_DIR")
        self.assertTrue(by["-d"].wants_path)
        self.assertIn("(default=warning)", by["--log"].help)
        self.assertEqual(by["--mode"].choices, ["all", "dde"])

    def test_args_roundtrip(self):
        from app.adapters import clitools as ct
        opts = ct.curate("pdf-parser", ct.parse_help(OPTPARSE_HELP))
        values, extra = ct.args_to_values(opts, ["-s", "/AA", "-f", "--searchstream=eval", "-K", "x"])
        self.assertEqual(values["--search"], "/AA")
        self.assertIs(values["--filter"], True)
        self.assertEqual(values["--searchstream"], "eval")
        self.assertEqual(extra, ["-K", "x"])
        args = ct.values_to_args(opts, values)
        self.assertEqual(args[:2], ["-s", "/AA"])
        self.assertIn("-f", args)
        self.assertIn("--searchstream", args)

    def test_registry_complete(self):
        from app.adapters import clitools as ct
        for name in ("pdfid", "pdf-parser", "oledump", "olevba", "peepdf", "oleobj", "rtfobj", "msodde"):
            self.assertIn(name, ct.TOOLS)


# What the real pdf-parser printed for the generated test PDF: values that contain
# spaces come out as Python reprs ('(…)' with doubled backslashes), simple ones bare.
REPR_LISTING = textwrap.dedent(r"""
    obj 3 0
     Type: /Page
     Referencing: 8 0 R

      <<
        /Type /Page
        /AA
          <<
            /O 8 0 R
          >>
      >>


    obj 8 0
     Type: /Action
     Referencing:

      <<
        /Type /Action
        /S /JavaScript
        /JS '(console.println\\("MTW test: page opened \\(harmless\\)"\\);)'
      >>


    obj 11 0
     Type: /Annot
     Referencing:

      <<
        /Type /Annot
        /Subtype /Widget
        /FT /Tx
        /T (Amount)
        /AA
          <<
            /F
              <<
                /S /JavaScript
                /JS '(AFNumber_Format\\(2, 0, 0, 0, "$", true\\);)'
              >>
            /K
              <<
                /S /JavaScript
                /JS '(AFNumber_Keystroke\\(2, 0, 0, 0, "$", true\\);)'
              >>
          >>
      >>


    obj 16 0
     Type: /Annot
     Referencing:

      <<
        /Type /Annot
        /Subtype /Link
        /A
          <<
            /S /Launch
            /F (MTW_test_launch_target_does_not_exist.txt)
          >>
      >>
""")


class ReprFormatTests(unittest.TestCase):
    def test_repr_strings_are_unwrapped(self):
        pdf = pp.parse_full_listing(REPR_LISTING)
        d = pp.parse_dictionary(pdf.by_id(11).text)
        self.assertEqual(d["/AA"]["/F"]["/JS"], 'AFNumber_Format(2, 0, 0, 0, "$", true);')
        self.assertEqual(pp.parse_dictionary(pdf.by_id(8).text)["/JS"],
                         'console.println("MTW test: page opened (harmless)");')

    def test_form_scripts_benign_in_real_format(self):
        pdf = pp.parse_full_listing(REPR_LISTING)
        trig = pp.analyze_triggers(pdf)
        field = [t for t in trig if t.source == 11]
        self.assertEqual(len(field), 2)
        self.assertTrue(all(t.severity == Severity.LOW and "benign" in t.note for t in field))
        page = [t for t in trig if t.source == 3][0]
        self.assertEqual(page.severity, Severity.HIGH)
        self.assertIn("console.println", page.target)
        launch = [t for t in trig if t.action_type == "/Launch"][0]
        self.assertEqual(launch.target, "MTW_test_launch_target_does_not_exist.txt")
        titles = [f.title for f in pp.findings_from(pdf, trig)]
        self.assertFalse(any("field" in t and "formatted" in t for t in titles))

    def test_tokenizer_edge_cases(self):
        toks = pp._tokenize("<< /A (nested (parens) ok) /B <414243> /C [ 1 0 R 2 0 R ] /D 12 /E \"(dq)\" >>")
        d = pp._parse_value(toks, 0)[0]
        self.assertEqual(d["/A"], "nested (parens) ok")
        self.assertEqual(d["/B"], "ABC")
        self.assertEqual(d["/C"], [pp.Ref(1), pp.Ref(2)])
        self.assertEqual(d["/D"], "12")
        self.assertEqual(d["/E"], "dq")


class IncompleteAnalysisTests(unittest.TestCase):
    """A scan where the tools never ran must never be reported as clean."""

    def _session(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.pdf")
        with open(p, "wb") as fh:
            fh.write(b"%PDF-1.7\n%%EOF\n")
        return Session(Sample.load(p))

    def test_no_tools_ran_is_incomplete_not_clean(self):
        sess = self._session()
        sess.mark_failed("pdfid", "pdfid.py not found. Run setup_vendor.py.")
        sess.mark_failed("pdf-parser", "pdf-parser.py not found")
        self.assertTrue(sess.incomplete)
        title, action = report.verdict(sess)
        self.assertEqual(title, "INCOMPLETE: ANALYSIS DID NOT RUN")
        self.assertIn("NOT been checked", action)
        html_text = report.html_report(sess)
        self.assertNotIn("NO INDICATORS FOUND", html_text)
        self.assertIn("Tools FAILED", html_text)
        self.assertIn("INCOMPLETE", report.phishing_summary(sess))
        self.assertTrue(sess.export_dict()["analysis_incomplete"])

    def test_partial_failure_warns(self):
        sess = self._session()
        sess.replace_findings("pdfid", [])
        sess.mark_failed("pdf-parser", "timeout")
        self.assertFalse(sess.incomplete)
        title, action = report.verdict(sess)
        self.assertIn("(INCOMPLETE)", title)
        self.assertIn("some tools failed", action)

    def test_success_clears_failure(self):
        sess = self._session()
        sess.mark_failed("pdfid", "not found")
        sess.replace_findings("pdfid", [])
        self.assertEqual(sess.tool_errors, {})
        self.assertEqual(report.verdict(sess)[0], "NO INDICATORS FOUND")


class JsSourceTests(unittest.TestCase):
    def test_inline_js_from_real_format(self):
        pdf = pp.parse_full_listing(REPR_LISTING)
        self.assertEqual(pp.js_source(pdf, 8), ("inline", 'console.println("MTW test: page opened (harmless)");'))

    def test_stream_js_and_following_references(self):
        pdf = pp.parse_full_listing(TRIGGER_LISTING)
        self.assertEqual(pp.js_source(pdf, 4), ("stream", 5))     # action -> /JS 5 0 R (stream)
        self.assertEqual(pp.js_source(pdf, 5), ("stream", 5))     # the stream itself
        self.assertEqual(pp.js_source(pdf, 10), ("stream", 11))
        self.assertEqual(pp.js_source(pdf, 2), ("none", None))     # /Pages has no JS

    def test_investigate_step_carries_object(self):
        from app.core import guidance
        f = Finding("pdf-parser", Severity.HIGH, "x", "", ref={"kb": "pdf:trigger_js", "payload": 8})
        actions = [s.action for s in guidance.steps_for(f)]
        self.assertIn("pdf.js:8", actions)
        self.assertNotIn("js.workbench", actions)
