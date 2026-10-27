"""The sample's bytes are read once (never more than the limit) and every tool reads a private
copy of exactly those bytes, so the hashes always describe what was analysed. Commands that
are shown or copied still name the original file."""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.core import report  # noqa: E402
from app.core.models import Family  # noqa: E402
from app.core.safety import quote_arg  # noqa: E402
from app.core.session import Sample, SampleTooLarge, Session  # noqa: E402

PDF = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"


def sha(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class SampleCopyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mtw-sample-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.work = os.path.join(self.tmp, "output", ".work")
        self.path = os.path.join(self.tmp, "in box", "invoice.doc")   # a space, and the wrong extension
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "wb") as fh:
            fh.write(PDF)

    def test_read_is_bounded_even_if_the_size_check_is_fooled(self):
        with open(self.path, "ab") as fh:
            fh.write(b"0" * 1000)
        with mock.patch("os.path.getsize", return_value=10):     # as if the file grew after the check
            with self.assertRaises(SampleTooLarge):
                Sample.load(self.path, max_bytes=100, isolate=False)

    def test_tools_read_a_private_copy_of_the_hashed_bytes(self):
        s = Sample.load(self.path, isolate=False, work_dir=self.work)
        self.assertEqual(s.path, os.path.abspath(self.path))
        self.assertNotEqual(s.work_path, s.path)
        self.assertTrue(s.work_path.startswith(os.path.abspath(self.work)))
        self.assertEqual(os.path.basename(s.work_path), "invoice.doc")   # outputs are named after it
        self.assertEqual(sha(s.work_path), s.sha256)
        if os.name != "nt":
            self.assertEqual(os.stat(os.path.dirname(s.work_path)).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(s.work_path).st_mode & 0o777, 0o600)
        with open(self.path, "wb") as fh:                         # the original is replaced
            fh.write(b"something else")
        self.assertFalse(s.verify_unchanged())                    # still reported on close
        self.assertEqual(sha(s.work_path), s.sha256)              # but the tools' copy is what was hashed
        s.discard_copy()
        self.assertFalse(os.path.exists(os.path.dirname(s.work_path)))
        self.assertTrue(os.path.exists(self.path))                # never the original

    def test_route_uses_the_original_name(self):
        s = Sample.load(self.path, isolate=False, work_dir=self.work)
        self.assertEqual(s.family, Family.PDF)
        self.assertTrue(any("Extension '.doc'" in w.title for w in s.route.warnings))

    def test_commands_name_the_original(self):
        s = Sample.load(self.path, isolate=False, work_dir=self.work)
        self.assertEqual(s.shown(f"pdfid.py -e {quote_arg(s.work_path)}"), f"pdfid.py -e {quote_arg(s.path)}")
        # an unquoted copy path becomes the original, quoted when it needs to be
        self.assertEqual(s.shown(f"peepdf -f {s.work_path}"), f"peepdf -f {quote_arg(s.path)}")
        self.assertEqual(s.shown(""), "")

    def test_without_a_work_dir_tools_read_the_original(self):
        s = Sample.load(self.path, isolate=False)
        self.assertEqual(s.work_path, s.path)
        self.assertEqual(s.shown(f"pdfid.py {s.path}"), f"pdfid.py {s.path}")
        s.discard_copy()
        self.assertTrue(os.path.exists(self.path))


class ReportWordingTests(unittest.TestCase):
    def test_footer_says_whether_xlm_emulation_ran(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.pdf")
            with open(p, "wb") as fh:
                fh.write(PDF)
            sess = Session(Sample.load(p, isolate=False))
        self.assertIn("the sample was not executed or rendered", report.html_report(sess))
        sess.tools_run.add("xlmdeobfuscator")
        html = report.html_report(sess)
        self.assertIn("XLM emulation", html)
        self.assertNotIn("not executed or rendered", html)


if __name__ == "__main__":
    unittest.main()
