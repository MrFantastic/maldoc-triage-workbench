"""Tool versions, and noticing tool output this app doesn't recognize (all of it: the
tool failed; part of it: an Info note that qualifies the verdict). Also pdfid plugins."""
import json
import os
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.adapters import macro_adapter, objects_adapter, oledump_adapter as od  # noqa: E402
from app.adapters import pdfid_adapter as pa, pdfparser_adapter as pp, peepdf_adapter as pe  # noqa: E402
from app.adapters import scripts, versions  # noqa: E402
from app.core import correlate, outputcheck, report  # noqa: E402
from app.core.models import Finding, Severity  # noqa: E402
from app.core.session import Sample, Session  # noqa: E402
from test_adapters import REPR_LISTING, TRIGGER_LISTING  # noqa: E402
from test_core import FAKE_PDFID  # noqa: E402

MIN_PDF = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"


def _script(body: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as fh:
        fh.write(textwrap.dedent(body))
    return path


def _session(findings=()) -> Session:
    fd, path = tempfile.mkstemp(suffix=".pdf")
    with os.fdopen(fd, "wb") as fh:
        fh.write(MIN_PDF)
    s = Session(Sample.load(path, isolate=False))
    os.remove(path)
    s.findings.extend(findings)
    return s


class _EnvTool:
    """Point scripts.locate(<name>) at a fake script for the duration of a test."""
    def __init__(self, env: str, body: str):
        self.env, self.path = env, _script(body)

    def __enter__(self):
        self.old = os.environ.get(self.env)
        os.environ[self.env] = self.path
        versions.clear()
        return self.path

    def __exit__(self, *exc):
        if self.old is None:
            os.environ.pop(self.env, None)
        else:
            os.environ[self.env] = self.old
        os.remove(self.path)
        versions.clear()


class VersionTests(unittest.TestCase):
    def test_script_version(self):
        p = _script('#!/usr/bin/env python\n__description__ = "x"\n__version__ = \'0.7.10\'\n'
                    '__date__ = "2024/08/31"\n')
        self.addCleanup(os.remove, p)
        self.assertEqual(versions.script_version(p), "0.7.10 (2024/08/31)")
        self.assertEqual(versions.script_version(None), "")

    def test_versions_reach_report(self):
        with _EnvTool("MTW_PDF_PARSER", "__version__ = '9.9.9'\n"):
            self.assertEqual(versions.version_of("pdf-parser"), "9.9.9")
            s = _session()
            s.tool_versions = versions.all_versions()
        s.tools_run.add("pdf-parser")
        self.assertIn("pdf-parser 9.9.9", report.phishing_summary(s))
        self.assertIn("pdf-parser 9.9.9", report.html_report(s))
        self.assertEqual(s.export_dict()["tool_versions"]["pdf-parser"], "9.9.9")


class PdfParserOutputTests(unittest.TestCase):
    def test_known_output_has_nothing_unrecognized(self):
        for listing in (TRIGGER_LISTING, REPR_LISTING):
            self.assertEqual(pp.parse_full_listing(listing).unrecognized, [])

    def test_partial_output_is_noted_even_with_findings(self):
        listing = REPR_LISTING + "\nobj 99 0\n Type: /Page\n Signature: abc\n\n  <<\n  >>\n"
        pdf = pp.parse_full_listing(listing)
        pdf.triggers = pp.analyze_triggers(pdf)
        found = pp.findings_from(pdf, pdf.triggers)
        notes = [f for f in found if f.ref.get("kb") == outputcheck.KB]
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0].severity, Severity.INFO)
        self.assertTrue(any(f.severity == Severity.HIGH for f in found))   # real findings still there
        self.assertEqual(pp.facts(pdf)["unrecognized"], 1)

    def test_nothing_recognized_is_a_failure(self):
        with _EnvTool("MTW_PDF_PARSER", "print('Totally new output format v2')\nprint('object 1: catalog')\n"):
            res = pp.run_full("x.pdf")
        self.assertFalse(res.ok)
        self.assertIn("output not recognized", res.error)
        self.assertEqual(res.findings, [])

    def test_partial_output_blocks_correlation(self):
        facts = {"encrypted": False, "js_triggers": 2, "js_unknown": 0, "js_unexplained": 0, "launch": 0,
                 "js_names": 2, "unrecognized": 1}
        f = Finding("pdfid", Severity.HIGH, "/JS x2", "", ref={"keyword": "/JS", "count": 2, "hex": 0})
        correlate.apply([f], {"pdf-parser": facts})
        self.assertEqual(f.severity, Severity.HIGH)
        correlate.apply([f], {"pdf-parser": dict(facts, unrecognized=0)})
        self.assertEqual(f.severity, Severity.MEDIUM)


class PdfidOutputTests(unittest.TestCase):
    XML = ('<PDFiD IsPDF="True" Header="%PDF-1.7"><Keywords>'
           '<Keyword Name="obj" Count="3" HexcodeCount="0"/>'
           '<Keyword Name="/JS" Count="1" HexcodeCount="0"/>'
           '<Keyword Name="/NewThing" Count="2" HexcodeCount="0"/></Keywords></PDFiD>')

    def test_unknown_keyword_is_noted(self):
        data = pa.parse_pdfid_xml(self.XML)
        self.assertEqual(data.unrecognized, ["keyword /NewThing (count 2)"])
        notes = [f for f in pa.findings_from(data) if f.ref.get("kb") == outputcheck.KB]
        self.assertEqual(len(notes), 1)
        self.assertIn("keyword(s) not recognized", notes[0].title)
        self.assertEqual(pa.parse_pdfid_xml(self.XML, all_names=True).unrecognized, [])

    def test_text_fallback(self):
        text = ("PDFiD 0.2.10 x.pdf\n PDF Header: %PDF-1.7\n obj                    3\n /JS     1\n"
                " Total entropy:           7.9 (    1234 bytes)\n"
                "This program has not been tested with this version of Python (3.15.0)\n"
                " Score: weird new section\n")
        data = pa.parse_pdfid_text(text)
        self.assertEqual([r.name for r in data.keywords], ["obj", "/JS"])
        self.assertEqual(data.unrecognized, [" Score: weird new section"])

    def test_no_keywords_is_a_failure(self):
        body = FAKE_PDFID.replace('for name in ["obj", "/JS", "/JavaScript", "/OpenAction", "/Launch"]:',
                                  'for name in []:')
        d = tempfile.mkdtemp()
        fake = os.path.join(d, "pdfid.py")
        with open(fake, "w") as fh:
            fh.write(body)
        sample = os.path.join(d, "s.pdf")
        with open(sample, "wb") as fh:
            fh.write(MIN_PDF)
        old = os.environ.get("MTW_PDFID")
        os.environ["MTW_PDFID"] = fake
        pa.clear_cache()
        try:
            res = pa.run(sample, pa.PdfidOptions())
        finally:
            pa.clear_cache()
            if old is None:
                os.environ.pop("MTW_PDFID", None)
            else:
                os.environ["MTW_PDFID"] = old
        self.assertFalse(res.ok)
        self.assertIn("output not recognized", res.error)


class OledumpOutputTests(unittest.TestCase):
    LISTING = ("A: word/vbaProject.bin\n A1:       468 'PROJECT'\n A2: M    1388 'VBA/ThisDocument'\n")

    def test_known_and_partial(self):
        self.assertEqual(od.parse_listing(self.LISTING).unrecognized, [])
        sl = od.parse_listing(self.LISTING + "Stream summary: 2 streams, 1 macro\n")
        self.assertEqual(len(sl.streams), 2)
        titles = [f.title for f in od.findings_from(sl)]
        self.assertTrue(any("not recognized" in t for t in titles))
        self.assertTrue(any("VBA code" in t for t in titles))

    def test_run_list(self):
        with _EnvTool("MTW_OLEDUMP", "print('Streams in new format: PROJECT, VBA/ThisDocument')\n"):
            res = od.run_list("x.docm")
        self.assertFalse(res.ok)
        self.assertIn("output not recognized", res.error)
        with _EnvTool("MTW_OLEDUMP", "print('Warning: no OLE file was found inside this ZIP container')\n"):
            res = od.run_list("x.docx")
        self.assertTrue(res.ok)
        self.assertEqual(res.findings, [])


class OtherToolOutputTests(unittest.TestCase):
    def _patch(self, obj, name, value):
        old = getattr(obj, name)
        setattr(obj, name, value)
        self.addCleanup(setattr, obj, name, old)

    def test_msodde(self):
        self._patch(scripts, "run_module", lambda *a, **k: scripts.RunResult("msodde", b"Results: none\n", "", 0))
        res = objects_adapter.msodde("x.docx")
        self.assertFalse(res.ok)
        self.assertIn("output not recognized", res.error)
        self._patch(scripts, "run_module", lambda *a, **k: scripts.RunResult(
            "msodde", b"msodde 0.60\nDDE Links:\n", "", 0))
        self.assertTrue(objects_adapter.msodde("x.docx").ok)

    def test_peepdf_layout(self):
        self._patch(pe, "_run", lambda *a: scripts.RunResult("peepdf", json.dumps({"report": {}}).encode(), "", 0))
        res = pe.overview("x.pdf")
        self.assertFalse(res.ok)
        self.assertIn("unexpected JSON layout", res.error)
        good = {"peepdf_analysis": {"basic": {"num_objects": 3}, "advanced": []}}
        self._patch(pe, "_run", lambda *a: scripts.RunResult("peepdf", json.dumps(good).encode(), "", 0))
        self.assertTrue(pe.overview("x.pdf").ok)

    def test_xlm_note(self):
        self._patch(scripts, "run_cmd", lambda *a, **k: scripts.RunResult(
            "xlm", b"Completely different output\nhttp://evil.example/x\n", "", 0))
        res = macro_adapter.emulate_xlm("x.xls")
        kbs = [f.ref.get("kb") for f in res.findings]
        self.assertIn(outputcheck.KB, kbs)
        self.assertIn("xlm:ioc", kbs)


ENC_LISTING = textwrap.dedent("""\
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
        /S /Launch
        /F (\x8f\x12\xa0\x9bAb)
      >>


    obj 5 0
     Type: /Annot
     Referencing:

      <<
        /Type /Annot
        /Subtype /Link
        /A
          <<
            /S /SubmitForm
            /F (Kq7z)
          >>
      >>


    trailer
      <<
        /Root 1 0 R
        /Encrypt 9 0 R
      >>
""")

FORM_POST = textwrap.dedent("""\
    obj 3 0
     Type: /Page
     Referencing:

      <<
        /Type /Page
        /AA << /O << /S /JavaScript /JS (console.println\\("x"\\);) >> >>
      >>


    obj 23 0
     Type: /Annot
     Referencing:

      <<
        /Type /Annot
        /Subtype /Link
        /A
          <<
            /S /SubmitForm
            /F (https://example.com/mtw-submit)
          >>
      >>
""")


class ReportFixTests(unittest.TestCase):
    def test_encrypted_targets_never_become_iocs(self):
        pdf = pp.parse_full_listing(ENC_LISTING)
        pdf.triggers = pp.analyze_triggers(pdf)
        self.assertTrue(pdf.encrypted)
        self.assertEqual({t.target for t in pdf.triggers}, {pp.UNREADABLE})
        self.assertEqual(pp.iocs(pdf), [])

    def test_inline_action_text_and_submitform_finding(self):
        pdf = pp.parse_full_listing(FORM_POST)
        pdf.triggers = pp.analyze_triggers(pdf)
        found = pp.findings_from(pdf, pdf.triggers)
        self.assertFalse(any("None" in f.detail for f in found), [f.detail for f in found])
        sub = [f for f in found if "submitted" in f.title]
        self.assertEqual(len(sub), 1)
        self.assertEqual(sub[0].severity, Severity.MEDIUM)
        self.assertIn("hxxps://example[.]com/mtw-submit", sub[0].title)
        self.assertEqual(pp.iocs(pdf), ["https://example.com/mtw-submit"])

    def test_lowered_detail_drops_rated_high(self):
        facts = {"encrypted": False, "js_triggers": 2, "js_unknown": 0, "js_unexplained": 0, "launch": 0,
                 "js_names": 2, "unrecognized": 0}
        f = Finding("pdfid", Severity.HIGH, "/AA x1", "Additional actions. Rated High because the file also "
                    "contains JavaScript or /Launch.", ref={"keyword": "/AA", "count": 1, "hex": 0})
        correlate.apply([f], {"pdf-parser": facts})
        self.assertNotIn("Rated High", f.detail)
        self.assertIn("Lowered to Medium", f.detail)
        correlate.apply([f], {})
        self.assertIn("Rated High", f.detail)


class VerdictTests(unittest.TestCase):
    def _note(self):
        return outputcheck.note("pdf-parser", [" Signature: abc"], "0.7.10")

    def test_low_risk_becomes_unverified(self):
        s = _session([self._note()])
        s.tools_run.add("pdf-parser")
        title, action = report.verdict(s)
        self.assertIn("UNVERIFIED", title)
        self.assertIn("wasn't recognized", action)
        self.assertEqual(s.output_warnings, {"pdf-parser": self._note().title})

    def test_high_risk_still_noted(self):
        s = _session([self._note(), Finding("pdfid", Severity.HIGH, "/JS x1", "")])
        title, action = report.verdict(s)
        self.assertNotIn("UNVERIFIED", title)
        self.assertIn("wasn't recognized", action)
        self.assertEqual(s.risk, Severity.HIGH)


class OfficeFalsePositiveTests(unittest.TestCase):
    """Harmless Office features that real REMnux tools reported as High (found on REMnux)."""

    @staticmethod
    def _oleid(count):
        return Finding("oleid", Severity.HIGH, f"External Relationships: {count}", "",
                       ref={"indicator": "ext_rels", "kb": "oleid:ext_rels"})

    @staticmethod
    def _part(kb, sev=Severity.LOW):
        return Finding("parts", sev, "External hyperlink: x", "", ref={"kb": kb, "tab": "parts"})

    def test_hyperlink_only_lowers_oleid_external_rels(self):
        f = self._oleid(1)
        self.assertEqual(correlate.apply([f, self._part("ooxml:external")], {}), 1)
        self.assertEqual(f.severity, Severity.LOW)
        correlate.apply([f], {})                       # parts gone: restored
        self.assertEqual(f.severity, Severity.HIGH)

    def test_remote_template_keeps_oleid_high(self):
        f = self._oleid(2)
        correlate.apply([f, self._part("ooxml:external"), self._part("ooxml:template", Severity.HIGH)], {})
        self.assertEqual(f.severity, Severity.HIGH)

    def test_more_relationships_than_parts_saw_keeps_high(self):
        f = self._oleid(3)
        correlate.apply([f, self._part("ooxml:external")], {})
        self.assertEqual(f.severity, Severity.HIGH)

    def test_msodde_hyperlink_field_is_low_dde_is_high(self):
        out = (b"msodde 0.60\nDDE Links:\nHYPERLINK \"https://example.com/a\"\n"
               b'DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc"\n')
        orig = scripts.run_module
        scripts.run_module = lambda *a, **k: scripts.RunResult("msodde", out, "", 0)
        try:
            res = objects_adapter.msodde("x.rtf")
        finally:
            scripts.run_module = orig
        sev = {f.title.split(":", 1)[0]: f.severity for f in res.findings}
        self.assertEqual(sev["Hyperlink field"], Severity.LOW)
        self.assertEqual(sev["DDE field"], Severity.HIGH)

    def test_rtf_is_not_scanned_for_macros(self):
        from app.adapters import office_adapter
        with tempfile.NamedTemporaryFile("wb", suffix=".rtf", delete=False) as fh:
            fh.write(b"{\\rtf1 hello}")
        try:
            data = office_adapter.OfficeTriageData()
            office_adapter._run_vba_and_mraptor(fh.name, data)
        finally:
            os.unlink(fh.name)
        self.assertEqual(data.verdict, "NO MACRO")
        self.assertEqual(data.vba_error, "")


if __name__ == "__main__":
    unittest.main()


class PdfidPluginTests(unittest.TestCase):
    PDFID_SRC = ("class cPluginParent():\n    onlyValidPDF = True\n\n"
                 "def ProcessFile(oPDFiD, options, plugins):\n"
                 "    for cPlugin in plugins:\n"
                 "        oPlugin = cPlugin(oPDFiD, options.pluginoptions)\n")
    OLD = ("class cPDFiDEmbeddedFile(cPluginParent):\n    name = 'EmbeddedFile plugin'\n\n"
           "    def __init__(self, oPDFiD):\n        self.oPDFiD = oPDFiD\n\nAddPlugin(cPDFiDEmbeddedFile)\n")
    NEW = ("class cPDFiDTriage(cPluginParent):\n    name = 'Triage plugin'\n\n"
           "    def __init__(self, oPDFiD, options):\n        self.oPDFiD = oPDFiD\n\nAddPlugin(cPDFiDTriage)\n")

    def test_compatibility_from_source(self):
        d = tempfile.mkdtemp()
        paths = {}
        for name, src in (("pdfid.py", self.PDFID_SRC), ("plugin_embeddedfile.py", self.OLD),
                          ("plugin_triage.py", self.NEW)):
            paths[name] = os.path.join(d, name)
            with open(paths[name], "w") as fh:
                fh.write(src)
        ok, name, reason = pa.plugin_status(paths["pdfid.py"], paths["plugin_embeddedfile.py"])
        self.assertFalse(ok)
        self.assertEqual(name, "EmbeddedFile plugin")
        self.assertIn("older pdfid", reason)
        ok, name, _ = pa.plugin_status(paths["pdfid.py"], paths["plugin_triage.py"])
        self.assertTrue(ok)
        self.assertEqual(name, "Triage plugin")

    def test_plugin_output_becomes_findings(self):
        text = ("PDFiD 0.2.10 x.pdf\n PDF Header: %PDF-1.7\n obj                   20\n /JS                    5\n"
                "Triage plugin score:        1.00\n"
                "Triage plugin instructions: Sample is likely malicious and requires further analysis\n"
                "Error instantiating plugin: EmbeddedFile plugin\n")
        data = pa.parse_pdfid_text(text)
        self.assertEqual(data.unrecognized, [])         # plugin lines are known output
        pa.parse_plugin_output(text, data)
        self.assertEqual(data.plugin_results,
                         [["Triage plugin", 1.0, "Sample is likely malicious and requires further analysis"]])
        self.assertEqual(data.plugin_errors, ["Error instantiating plugin: EmbeddedFile plugin"])
        titles = {f.title: f.severity for f in pa.findings_from(data)}
        self.assertEqual(titles.get("pdfid Triage plugin: score 1.00"), Severity.INFO)
        self.assertEqual(titles.get("pdfid Error instantiating plugin: EmbeddedFile plugin"), Severity.INFO)
