"""Pinned, fail-closed installation of the vendored tools (setup_vendor.py + vendor_pins)."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.core import vendor_manifest, vendor_pins  # noqa: E402


def _load_setup_vendor():
    spec = importlib.util.spec_from_file_location("mtw_setup_vendor", os.path.join(ROOT, "setup_vendor.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SV = _load_setup_vendor()
FAKE = {SV.rel_path(n, s): f"# harmless stand-in for {n}\n".encode() for n, s, _ in SV.FILES}
FAKE_PINS = {rel: hashlib.sha256(data).hexdigest() for rel, data in FAKE.items()}
COMMIT = "a" * 40


def fake_fetch(overrides=None, missing=()):
    """A fetch() that serves FAKE by upstream file name, with optional changed or missing files."""
    by_name = {rel.split("/")[-1]: data for rel, data in FAKE.items()}
    by_name.update(overrides or {})

    def fetch(url):
        name = url.rsplit("/", 1)[-1]
        if name in missing:
            raise OSError("404 Not Found")
        return by_name[name]
    return fetch


@contextlib.contextmanager
def pinned_to_fakes():
    with mock.patch.object(vendor_pins, "FILES", FAKE_PINS), mock.patch.object(vendor_pins, "COMMIT", COMMIT):
        yield


def run_quietly(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()) as out:
        rc = fn(*args, **kwargs)
    return rc, out.getvalue()


class PinsFileTests(unittest.TestCase):
    def test_pins_are_well_formed_and_cover_every_file(self):
        self.assertRegex(vendor_pins.COMMIT, r"^[0-9a-f]{40}$")
        self.assertRegex(vendor_pins.COMMIT_DATE, r"^\d{4}-\d{2}-\d{2}$")
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", h) for h in vendor_pins.FILES.values()))
        self.assertEqual(sorted(vendor_pins.FILES), sorted(SV.rel_path(n, s) for n, s, _ in SV.FILES))

    def test_render_round_trips(self):
        ns = {}
        exec(SV.render_pins(vendor_pins.COMMIT, vendor_pins.COMMIT_DATE, vendor_pins.FILES, ("x",)), ns)
        self.assertEqual((ns["COMMIT"], ns["FILES"]), (vendor_pins.COMMIT, vendor_pins.FILES))


class FetchToolsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.vendor = os.path.join(self.tmp.name, "vendor")
        os.makedirs(self.vendor)

    def tearDown(self):
        self.tmp.cleanup()

    def installed(self):
        return sorted(vendor_manifest.scan(self.vendor))

    def test_all_files_match_pins(self):
        with pinned_to_fakes(), mock.patch.object(SV, "fetch", fake_fetch()):
            rc, _ = run_quietly(SV.fetch_tools, vendor=self.vendor)
            self.assertEqual(rc, 0)
            self.assertEqual(self.installed(), sorted(FAKE))
            self.assertEqual(vendor_manifest.verify(self.vendor), ("verified", []))
            self.assertEqual(vendor_manifest.file_status(self.vendor, os.path.join(self.vendor, "pdfid.py")),
                             "verified")

    def test_one_mismatch_installs_nothing(self):
        with pinned_to_fakes(), mock.patch.object(SV, "fetch", fake_fetch({"plugin_msg.py": b"tampered\n"})):
            rc, out = run_quietly(SV.fetch_tools, vendor=self.vendor)
        self.assertEqual(rc, 1)
        self.assertIn("SHA-256 mismatch", out)
        self.assertIn("Nothing was installed", out)
        self.assertEqual(self.installed(), [])

    def test_missing_required_tool_installs_nothing(self):
        with pinned_to_fakes(), mock.patch.object(SV, "fetch", fake_fetch(missing=("pdf-parser.py",))):
            rc, _ = run_quietly(SV.fetch_tools, vendor=self.vendor)
        self.assertEqual(rc, 1)
        self.assertEqual(self.installed(), [])

    def test_missing_optional_tool_is_skipped(self):
        with pinned_to_fakes(), mock.patch.object(SV, "fetch", fake_fetch(missing=("plugin_dridex.py",))):
            rc, _ = run_quietly(SV.fetch_tools, vendor=self.vendor)
            self.assertEqual(rc, 0)
            self.assertNotIn("oledump/plugin_dridex.py", self.installed())
            self.assertEqual(vendor_manifest.verify(self.vendor)[0], "verified")

    def test_unpinned_ref_is_refused_without_flag(self):
        fetch = mock.Mock(side_effect=AssertionError("must not download"))
        with pinned_to_fakes(), mock.patch.object(SV, "fetch", fetch):
            rc, out = run_quietly(SV.fetch_tools, ref="master", vendor=self.vendor)
        self.assertEqual(rc, 2)
        self.assertIn("--allow-unverified", out)
        fetch.assert_not_called()

    def test_unpinned_ref_with_flag_is_unverified(self):
        changed = {"pdfid.py": b"# another revision\n"}
        with pinned_to_fakes(), mock.patch.object(SV, "fetch", fake_fetch(changed)):
            rc, _ = run_quietly(SV.fetch_tools, ref="master", allow_unverified=True, vendor=self.vendor)
            self.assertEqual(rc, 0)
            self.assertEqual(vendor_manifest.verify(self.vendor)[0], "UNVERIFIED")
            self.assertEqual(vendor_manifest.file_status(self.vendor, os.path.join(self.vendor, "pdfid.py")),
                             "UNVERIFIED")

    def test_tampering_is_caught_even_after_rerecording(self):
        with pinned_to_fakes(), mock.patch.object(SV, "fetch", fake_fetch()):
            run_quietly(SV.fetch_tools, vendor=self.vendor)
            with open(os.path.join(self.vendor, "oledump", "oledump.py"), "ab") as fh:
                fh.write(b"import os\n")
            old = vendor_manifest.load(self.vendor)
            vendor_manifest.record(self.vendor, "recorded locally (--record)", old["ref"], old["pinned"])
            status, problems = vendor_manifest.verify(self.vendor)
            self.assertEqual(status, "MODIFIED")
            self.assertTrue(any("oledump/oledump.py" in p and "pinned" in p for p in problems))
            self.assertEqual(vendor_manifest.file_status(
                self.vendor, os.path.join(self.vendor, "oledump", "oledump.py")), "CHANGED")

    def test_copy_from_a_matching_folder_is_verified(self):
        src = os.path.join(self.tmp.name, "suite")
        os.makedirs(src)
        for rel, data in FAKE.items():
            with open(os.path.join(src, rel.split("/")[-1]), "wb") as fh:
                fh.write(data)
        with pinned_to_fakes():
            rc, _ = run_quietly(SV.fetch_tools, copy_from=src, vendor=self.vendor)
            self.assertEqual(rc, 0)
            self.assertEqual(vendor_manifest.verify(self.vendor)[0], "verified")


class UpdatePinTests(unittest.TestCase):
    def serve(self, raw_overrides=None):
        blobs = [{"path": rel.split("/")[-1], "type": "blob",
                  "sha": hashlib.sha1(b"blob %d\0" % len(d) + d).hexdigest()} for rel, d in FAKE.items()]
        tree = json.dumps({"tree": blobs}).encode()
        info = json.dumps({"commit": {"committer": {"date": "2026-10-01T12:00:00Z"}}}).encode()
        raw = fake_fetch(raw_overrides)

        def fetch(url):
            if "/git/trees/" in url:
                return tree
            if "/commits/" in url:
                return info
            return raw(url)
        return fetch

    def test_writes_pins_when_both_services_agree(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "vendor_pins.py")
            with mock.patch.object(SV, "fetch", self.serve()):
                rc, _ = run_quietly(SV.update_pin, COMMIT, pins_file=path)
            self.assertEqual(rc, 0)
            ns = {}
            with open(path, encoding="utf-8") as fh:
                exec(fh.read(), ns)
            self.assertEqual((ns["COMMIT"], ns["COMMIT_DATE"], ns["FILES"]), (COMMIT, "2026-10-01", FAKE_PINS))

    def test_disagreement_leaves_pins_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "vendor_pins.py")
            with mock.patch.object(SV, "fetch", self.serve({"zipdump.py": b"served differently\n"})):
                rc, out = run_quietly(SV.update_pin, COMMIT, pins_file=path)
            self.assertEqual(rc, 1)
            self.assertIn("does not match the commit's tree", out)
            self.assertFalse(os.path.exists(path))

    def test_needs_a_full_commit_hash(self):
        rc, _ = run_quietly(SV.update_pin, "master")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
