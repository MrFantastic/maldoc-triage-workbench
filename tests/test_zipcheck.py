"""ZIP preflight (core/zipcheck.py): malformed or over-budget archives are rejected before
zipfile parses them; valid ones (including ZIP64, comments and prefix data) pass."""
from __future__ import annotations

import io
import os
import struct
import sys
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.core import zipcheck  # noqa: E402

EOCD = struct.Struct("<4s4H2LH")


def make_zip(n=3, comment=b"") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(n):
            zf.writestr(f"part{i}.xml", f"<x>{i}</x>")
        zf.comment = comment
    return buf.getvalue()


def patch_eocd(data: bytes, **fields) -> bytes:
    """Rewrite fields of the end record: disk, cd_disk, n_disk, n_total, cd_size, cd_offset."""
    names = ("sig", "disk", "cd_disk", "n_disk", "n_total", "cd_size", "cd_offset", "clen")
    at = data.rfind(b"PK\x05\x06")
    values = dict(zip(names, EOCD.unpack_from(data, at)))
    values.update(fields)
    out = bytearray(data)
    EOCD.pack_into(out, at, *(values[n] for n in names))
    return bytes(out)


def to_zip64(data: bytes, n_override=None) -> bytes:
    """Re-express a small zip with a ZIP64 end record + locator, as large archives do."""
    at = data.rfind(b"PK\x05\x06")
    _s, _d, _cd, n, total, size, offset, _c = EOCD.unpack_from(data, at)
    total = total if n_override is None else n_override
    rec = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, total, total, size, offset)
    loc = struct.pack("<4sLQL", b"PK\x06\x07", 0, at, 1)
    end = EOCD.pack(b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    return data[:at] + rec + loc + end


def zip64_layout(data: bytes, ext: bytes = b"") -> bytes:
    """Like to_zip64, with optional ZIP64 extensible data in the record."""
    at = data.rfind(b"PK\x05\x06")
    _s, _d, _cd, _n, total, size, offset, _c = EOCD.unpack_from(data, at)
    rec = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44 + len(ext), 45, 45, 0, 0, total, total, size, offset) + ext
    return finish64(data[:at] + rec, at)


def finish64(body: bytes, record_offset: int) -> bytes:
    """Append a ZIP64 locator pointing at record_offset and an end record full of ZIP64 markers."""
    loc = struct.pack("<4sLQL", b"PK\x06\x07", 0, record_offset, 1)
    return body + loc + EOCD.pack(b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)


class ZipCheckTests(unittest.TestCase):
    def assertZipfileReads(self, data, n):
        """zipfile reads the same entries, where this Python's zipfile supports the layout
        (extensible data needs a zipfile with the CVE-2025-8291 fix)."""
        try:
            names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        except zipfile.BadZipFile as exc:
            self.skipTest(f"this Python's zipfile can't read it: {exc}")
        self.assertEqual(len(names), n)

    def assertRejected(self, data, fragment, **kw):
        result = zipcheck.check(data, **kw)
        self.assertFalse(result.ok, f"accepted: {result}")
        self.assertIn(fragment, result.reason)
        return result

    def test_normal_archive_passes(self):
        r = zipcheck.check(make_zip(3))
        self.assertTrue(r.ok)
        self.assertEqual((r.entries, r.zip64, r.prefix), (3, False, 0))

    def test_comment_and_prefix_pass_like_zipfile(self):
        self.assertTrue(zipcheck.check(make_zip(2, comment=b"a comment")).ok)
        data = b"MZ stub of a self-extractor " * 10 + make_zip(2)
        r = zipcheck.check(data)
        self.assertTrue(r.ok)
        self.assertEqual(r.prefix, 280)
        self.assertEqual(len(zipfile.ZipFile(io.BytesIO(data)).namelist()), 2)

    def test_zip64_passes_and_zipfile_agrees(self):
        data = to_zip64(make_zip(4))
        r = zipcheck.check(data)
        self.assertTrue(r.ok, r.reason)
        self.assertTrue(r.zip64)
        self.assertEqual(len(zipfile.ZipFile(io.BytesIO(data)).namelist()), 4)

    def test_too_many_entries(self):
        self.assertRejected(make_zip(12), "limit is 10", max_entries=10)
        lying = patch_eocd(make_zip(12), n_disk=3, n_total=3)     # claims 3, holds 12
        self.assertRejected(lying, "more than 10", max_entries=10)

    def test_declared_count_must_match(self):
        self.assertRejected(patch_eocd(make_zip(3), n_disk=2, n_total=2),
                            "declares 2 entries but the directory holds 3")
        self.assertRejected(patch_eocd(make_zip(3), n_disk=999, n_total=999), "can't fit")

    def test_directory_size_and_offset(self):
        self.assertRejected(patch_eocd(make_zip(3), cd_size=0x7FFFFFF0), "exceeds")
        data = make_zip(3)
        self.assertRejected(patch_eocd(data, cd_offset=len(data)), "outside the archive")
        size = EOCD.unpack_from(data, data.rfind(b"PK\x05\x06"))[5]
        self.assertRejected(patch_eocd(data, cd_size=size + 7), "outside the archive")

    def test_small_budget(self):
        self.assertRejected(make_zip(50), "exceeds", max_cd_bytes=200)

    def test_multi_disk_and_zip64_markers(self):
        self.assertRejected(patch_eocd(make_zip(), disk=1), "multi-disk")
        self.assertRejected(patch_eocd(make_zip(), cd_size=0xFFFFFFFF), "ZIP64 size markers")
        self.assertRejected(patch_eocd(make_zip(), n_total=0xFFFF), "ZIP64 size markers")

    def test_zip64_inconsistencies(self):
        self.assertRejected(to_zip64(make_zip(3), n_override=9), "can't fit")
        data = make_zip(2)
        at = data.rfind(b"PK\x05\x06")
        loc = struct.pack("<4sLQL", b"PK\x06\x07", 0, 0, 1)        # locator with no record before it
        self.assertRejected(data[:at] + loc + data[at:], "no ZIP64 end record")

    def test_zip64_extensible_data_like_zipfile(self):
        data = zip64_layout(make_zip(3), ext=b"E" * 24)          # extensible data, which ZIP64 allows
        r = zipcheck.check(data)
        self.assertTrue(r.ok, r.reason)
        self.assertEqual((r.entries, r.zip64, r.prefix), (3, True, 0))
        self.assertZipfileReads(data, 3)

    def test_zip64_with_prefix_like_zipfile(self):
        data = b"MZ stub " * 8 + zip64_layout(make_zip(2))            # data prepended to a ZIP64 archive
        r = zipcheck.check(data)
        self.assertTrue(r.ok, r.reason)
        self.assertEqual((r.entries, r.prefix), (2, 64))
        self.assertZipfileReads(data, 2)

    def test_zip64_record_hidden_in_another(self):
        """The locator points at a record describing many entries; a second record right before
        the locator (inside the first one's extensible data) describes only two. Current
        zipfile follows the locator, so the check must too, and older zipfile reads the
        second one, so two records are refused."""
        big = make_zip(30)
        at = big.rfind(b"PK\x05\x06")
        _s, _d, _cd, _n, total, size, offset, _c = EOCD.unpack_from(big, at)
        two = big[offset:offset + 2 * (46 + len("part0.xml"))]
        inner = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, 2, 2, len(two), at + 56)
        outer = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44 + len(two) + 56, 45, 45, 0, 0,
                            total, total, size, offset) + two + inner
        data = finish64(big[:at] + outer, at)
        self.assertRejected(data, "two different ZIP64 end records", max_entries=20)

    def test_zip64_record_must_match_locator(self):
        data = bytearray(zip64_layout(make_zip(3)))
        rec = data.rfind(b"PK\x06\x06")
        struct.pack_into("<Q", data, rec + 4, 60)                      # wrong record size
        self.assertRejected(bytes(data), "doesn't match its locator")
        data = make_zip(3)
        at = data.rfind(b"PK\x05\x06")
        loc = struct.pack("<4sLQL", b"PK\x06\x07", 0, len(data) * 4, 1)  # points past the end
        self.assertRejected(data[:at] + loc + data[at:], "points past")

    def test_corrupt_and_truncated(self):
        data = bytearray(make_zip(3))
        cd = data.find(b"PK\x01\x02")
        data[cd:cd + 4] = b"XX\x01\x02"
        self.assertRejected(bytes(data), "bad central directory entry")
        whole = make_zip(3)
        self.assertRejected(whole[:len(whole) // 2], "no end-of-central-directory record")
        self.assertRejected(b"not a zip at all", "no end-of-central-directory record")

    def test_path_and_file_sources(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as fh:
            fh.write(make_zip(2))
        try:
            self.assertTrue(zipcheck.check(fh.name).ok)
            with open(fh.name, "rb") as f:
                self.assertTrue(zipcheck.check(f).ok)
        finally:
            os.unlink(fh.name)



class RejectedArchiveTests(unittest.TestCase):
    """A rejected archive is identified by signature, flagged, and never parsed by zipfile."""

    def lying_docx(self) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr("word/document.xml", "<w:document/>")
        return patch_eocd(buf.getvalue(), n_disk=7, n_total=7)

    def test_router_flags_and_skips_zipfile(self):
        from unittest import mock
        from app.core import router
        data = self.lying_docx()          # built before zipfile.ZipFile is patched (module-wide)
        with mock.patch.object(router.zipfile, "ZipFile", side_effect=AssertionError("parsed")):
            info = router.identify(data, "x.docx")
        self.assertEqual(info.family.name, "OOXML")
        self.assertIn("structure rejected", info.subtype)
        self.assertTrue(any(w.ref.get("kb") == "router:zip_rejected" for w in info.warnings))

    def test_parts_tool_fails_closed(self):
        import tempfile
        from app.adapters import container_adapter
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as fh:
            fh.write(self.lying_docx())
        try:
            res = container_adapter.read_parts(fh.name)
            self.assertFalse(res.ok)
            self.assertIn("ZIP structure rejected before parsing", res.error)
            with self.assertRaises(container_adapter.ZipRejected):
                container_adapter.read_part(fh.name, "word/document.xml")
        finally:
            os.unlink(fh.name)


if __name__ == "__main__":
    unittest.main()
