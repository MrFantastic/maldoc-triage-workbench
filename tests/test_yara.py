"""YARA scanning with the user's own rules: rule discovery, the in-app scans (whole file and
ZIP parts), parsing Didier Stevens' tools' -y output, and the findings."""
from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import textwrap
import unittest
import zipfile
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.adapters import isolated, scripts, yara_adapter  # noqa: E402
from app.core.models import Severity  # noqa: E402

try:
    import yara  # type: ignore  # noqa: F401
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

RULES = textwrap.dedent('''
    rule MTW_marker : tagA tagB {
        meta: description = "harmless test marker"
        strings: $a = "MTW-YARA-MARKER"
        condition: $a
    }
    rule MTW_document_part {
        condition: streamname == "word/document.xml"
    }
''')

OLEDUMP_OUT = textwrap.dedent('''\
    A: word/vbaProject.bin
     A1:       468 'PROJECT'
     A3: M    1251 'VBA/ThisDocument'
                   YARA rule: MTW_marker
     A4: O   60326 'MBD0049DB15/\\x01Ole10Native'
                   YARA rule (stream decoder: XOR 1 byte key 0x14): Contains_PE_File
    All VBA source code:
                   YARA rule: MTW_vba
''')
PDFPARSER_OUT = textwrap.dedent('''\
    YARA rule: MTW_marker (/rules/a.yar)
    obj 7 0
     Type: /EmbeddedFile
     Referencing:
    YARA rule (stream decoder: XOR 1 byte key 0x01): Other (/rules/b.yar)
    YARA rule: MTW_marker (/rules/a.yar)
    obj 12 0
     Type:
''')
RTFDUMP_OUT = textwrap.dedent('''\
        1 Level  1        c=    2 p=00000000 l=    1234 h=       0;       0 b=       0
        5 Level  3        c=    0 p=00000123 l=   12345 h=   12000;    5000 b=       0   O u=       0 \\*\\objdata
                   YARA rule: MTW_marker
''')


class RuleFileTests(unittest.TestCase):
    def test_file_or_every_rule_file_under_a_folder(self):
        with tempfile.TemporaryDirectory() as d:
            for rel in ("b.yar", "a.YARA", "README.md", "sub/c.yar", "sub/notes.txt"):
                p = os.path.join(d, rel)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                open(p, "w").close()
            found = [os.path.relpath(f, d).replace(os.sep, "/") for f in yara_adapter.rule_files(d)]
            self.assertEqual(found, ["a.YARA", "b.yar", "sub/c.yar"])
            self.assertEqual(yara_adapter.rule_files(os.path.join(d, "b.yar")), [os.path.join(d, "b.yar")])
        self.assertEqual(yara_adapter.rule_files(""), [])
        self.assertEqual(yara_adapter.rule_files("/no/such/rules"), [])


class ToolOutputTests(unittest.TestCase):
    def test_oledump(self):
        hits = yara_adapter.parse_tool_output("oledump", OLEDUMP_OUT)
        self.assertEqual([(h.rule, h.where, h.decoder) for h in hits],
                         [("MTW_marker", "stream A3 'VBA/ThisDocument'", ""),
                          ("Contains_PE_File", "stream A4 'MBD0049DB15/\\x01Ole10Native'", "XOR 1 byte key 0x14"),
                          ("MTW_vba", "all VBA code", "")])

    def test_pdf_parser_prints_the_rule_before_the_object(self):
        hits = yara_adapter.parse_tool_output("pdf-parser", PDFPARSER_OUT)
        self.assertEqual([(h.rule, h.where, h.namespace) for h in hits],
                         [("MTW_marker", "object 7", "/rules/a.yar"), ("Other", "object 12", "/rules/b.yar"),
                          ("MTW_marker", "object 12", "/rules/a.yar")])

    def test_rtfdump(self):
        hits = yara_adapter.parse_tool_output("rtfdump", RTFDUMP_OUT)
        self.assertEqual([(h.rule, h.where) for h in hits], [("MTW_marker", "object 5")])


class FindingTests(unittest.TestCase):
    def test_one_medium_finding_per_rule(self):
        d = yara_adapter.YaraData(matches=[
            yara_adapter.YaraMatch("R1", "whole file", "yara", meta={"description": "what R1 finds"}),
            yara_adapter.YaraMatch("R1", "stream 3 'Macros'", "oledump"),
            yara_adapter.YaraMatch("R2", "object 4", "pdf-parser")])
        found = yara_adapter.findings_from(d)
        self.assertEqual([(f.title, f.severity) for f in found],
                         [("YARA rule R1 matched", Severity.MEDIUM), ("YARA rule R2 matched", Severity.MEDIUM)])
        self.assertIn("what R1 finds", found[0].detail)
        self.assertIn("whole file (yara); stream 3 'Macros' (oledump)", found[0].detail)
        self.assertEqual(found[0].ref, {"kb": "yara:match", "tab": "yara"})


@unittest.skipUnless(HAVE_YARA, "yara-python is not installed")
class ScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mtw-yara-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.rules = os.path.join(self.tmp, "rules.yar")
        with open(self.rules, "w", encoding="utf-8") as fh:
            fh.write(RULES)

    def write(self, name: str, data: bytes) -> str:
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as fh:
            fh.write(data)
        return p

    def test_whole_file(self):
        p = self.write("s.bin", b"junk " * 10 + b"MTW-YARA-MARKER" + b" junk")
        d = yara_adapter.scan(p, [self.rules], zip_parts=False)
        self.assertEqual(d.error, "")
        self.assertEqual([(m.rule, m.where, m.tags) for m in d.matches],
                         [("MTW_marker", "whole file", ["tagA", "tagB"])])
        self.assertEqual(d.matches[0].meta, {"description": "harmless test marker"})
        self.assertEqual(d.matches[0].strings, ["0x32 $a: 'MTW-YARA-MARKER'"])

    def test_zip_parts_are_scanned_decompressed_with_their_name(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/document.xml", "<w:document>MTW-YARA-MARKER</w:document>")
        p = self.write("s.docx", buf.getvalue())
        d = yara_adapter.scan(p, [self.rules], zip_parts=True)
        self.assertEqual(sorted((m.rule, m.where) for m in d.matches),
                         [("MTW_document_part", "part word/document.xml"), ("MTW_marker", "part word/document.xml")])

    def test_rules_that_dont_compile(self):
        bad = self.write("bad.yar", b"rule broken { condition: nonsense_identifier }")
        d = yara_adapter.scan(self.write("s.bin", b"x"), [bad], zip_parts=False)
        self.assertIn("don't compile", d.error)
        self.assertEqual(d.matches, [])

    def test_runs_in_a_worker_and_with_the_tools(self):
        """run(): the worker scan plus pdf-parser's -y pass (a stand-in), with two rule files
        passed to it as an @file list that the displayed command replaces with their folder."""
        second = self.write("more.yara", b"rule MTW_second { condition: false }")
        # the stand-in reports a match only if it was given both rule files as an @file list
        fake = self.write("fake-pdf-parser.py",
                          b"import sys\narg = sys.argv[sys.argv.index('-y') + 1]\n"
                          b"listed = open(arg[1:]).read().split() if arg.startswith('@') else []\n"
                          b"if len(listed) == 2 and all(f.endswith(('rules.yar', 'more.yara')) for f in listed):\n"
                          b"    print('YARA rule: MTW_marker (r)')\n"
                          b"print('obj 3 0')\n")
        p = self.write("s.pdf", b"%PDF-1.7\nMTW-YARA-MARKER\n%%EOF\n")
        with mock.patch.dict(os.environ, {"MTW_PDF_PARSER": fake}):
            res = yara_adapter.run(p, "PDF", [self.rules, second])
        self.assertTrue(res.ok, res.error)
        d = res.data
        self.assertEqual(sorted((m.rule, m.where, m.found_by) for m in d.matches),
                         [("MTW_marker", "object 3", "pdf-parser"), ("MTW_marker", "whole file", "yara")])
        self.assertEqual(len(res.findings), 1)
        shown = f"-y {scripts.quote(self.tmp)}"
        self.assertTrue(any(shown in c and "# its .yar / .yara files" in c for c in d.commands),
                        d.commands)                       # the temporary @file list isn't shown
        self.assertEqual(d.notes, [])


class ToolFailureTests(unittest.TestCase):
    def test_a_tool_that_crashes_leaves_a_note(self):
        with tempfile.TemporaryDirectory() as d:
            fake = os.path.join(d, "fake-rtfdump.py")
            with open(fake, "w") as fh:
                fh.write("import sys\n"
                         "sys.stderr.write('Traceback (most recent call last):\\n')\n"
                         "sys.stderr.write('yara.SyntaxError: r.yar(1): undefined identifier \"streamname\"\\n')\n"
                         "sys.exit(1)\n")
            data = yara_adapter.YaraData()
            with mock.patch.dict(os.environ, {"MTW_RTFDUMP": fake}):
                yara_adapter._tool_pass("rtfdump", "rtfdump.py", os.path.join(d, "x.rtf"), "r.yar", data)
        self.assertEqual(len(data.notes), 1, data.notes)
        self.assertIn("rtfdump couldn't scan RTF objects", data.notes[0])
        self.assertIn("undefined identifier", data.notes[0])


class WorkerTaskTests(unittest.TestCase):
    @unittest.skipUnless(HAVE_YARA, "yara-python is not installed")
    def test_result_crosses_the_worker_boundary(self):
        with tempfile.TemporaryDirectory() as d:
            rules = os.path.join(d, "r.yar")
            with open(rules, "w") as fh:
                fh.write(RULES)
            sample = os.path.join(d, "s.bin")
            with open(sample, "wb") as fh:
                fh.write(b"MTW-YARA-MARKER")
            data = isolated.yara_scan(sample, [rules], False)
        self.assertIsInstance(data, yara_adapter.YaraData)
        self.assertEqual(data.matches[0].rule, "MTW_marker")


if __name__ == "__main__":
    unittest.main()
