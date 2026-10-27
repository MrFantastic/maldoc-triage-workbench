"""Bounded ZIP structure check, run before Python's zipfile parses a sample.

zipfile reads the whole central directory into memory and builds one ZipInfo object per
entry before the app can apply any limit, so a crafted archive (up to the 256 MB sample
limit) could make it allocate gigabytes. This module finds the end-of-central-directory
record exactly the way zipfile does, including the ZIP64 record (found through the
locator's offset, with any "extensible data", as current zipfile does since the fix for
CVE-2025-8291), then checks that what it declares is consistent and within budget, and
counts the directory entries without building any objects. Only an archive that passes
is handed to zipfile.

Rejected: no end record; multi-disk; ZIP64 markers without a ZIP64 record; a ZIP64
locator that points nowhere valid, or a ZIP64 record that doesn't match it; two
different ZIP64 records (older zipfile versions would read the other one); a directory
that starts before the file or runs past the end record; a directory larger than
MAX_CD_BYTES; more than MAX_ENTRIES entries; an entry count the directory can't hold; a
directory entry with a bad signature or that overruns the directory; a declared count
that doesn't match the entries actually present.
"""
from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass

MAX_ENTRIES = 20_000
MAX_CD_BYTES = 32 * 1024 * 1024

_EOCD = struct.Struct("<4s4H2LH")          # 22 bytes
_EOCD_SIG = b"PK\x05\x06"
_LOC64 = struct.Struct("<4sLQL")           # 20 bytes
_LOC64_SIG = b"PK\x06\x07"
_EOCD64 = struct.Struct("<4sQ2H2L4Q")      # 56 bytes
_EOCD64_SIG = b"PK\x06\x06"
_CD_SIG = b"PK\x01\x02"
_CD_FIXED = 46


@dataclass
class ZipCheck:
    ok: bool
    reason: str = ""
    entries: int = 0
    cd_size: int = 0
    zip64: bool = False
    prefix: int = 0          # bytes before the archive (self-extractor / appended zip)

    def __bool__(self) -> bool:
        return self.ok


def _bad(reason: str, **kw) -> ZipCheck:
    return ZipCheck(False, reason, **kw)


def _find_end(fp, size: int):
    """(eocd fields, eocd offset) the way zipfile._EndRecData finds them, or None."""
    if size >= _EOCD.size:
        fp.seek(size - _EOCD.size)
        data = fp.read(_EOCD.size)
        if data[:4] == _EOCD_SIG and data[-2:] == b"\0\0":
            return _EOCD.unpack(data), size - _EOCD.size
    start = max(size - (1 << 16) - _EOCD.size, 0)
    fp.seek(start)
    data = fp.read()
    pos = data.rfind(_EOCD_SIG)
    if pos < 0 or len(data) - pos < _EOCD.size:
        return None
    return _EOCD.unpack(data[pos:pos + _EOCD.size]), start + pos


def check(source, max_entries: int = MAX_ENTRIES, max_cd_bytes: int = MAX_CD_BYTES) -> ZipCheck:
    """source: a path, bytes, or a seekable binary file."""
    if isinstance(source, (bytes, bytearray, memoryview)):
        return _check(io.BytesIO(source), max_entries, max_cd_bytes)
    if isinstance(source, (str, os.PathLike)):
        with open(source, "rb") as fp:
            return _check(fp, max_entries, max_cd_bytes)
    return _check(source, max_entries, max_cd_bytes)


def _check(fp, max_entries: int, max_cd_bytes: int) -> ZipCheck:
    fp.seek(0, 2)
    size = fp.tell()
    found = _find_end(fp, size)
    if found is None:
        return _bad("no end-of-central-directory record")
    (_sig, disk, cd_disk, n_disk, n_total, cd_size, cd_offset, _clen), eocd_at = found
    zip64 = False
    cd_end = eocd_at                       # the directory must end before this offset
    if eocd_at >= _LOC64.size:
        fp.seek(eocd_at - _LOC64.size)
        loc = fp.read(_LOC64.size)
        if len(loc) == _LOC64.size and loc[:4] == _LOC64_SIG:
            _s, loc_disk, reloff, disks = _LOC64.unpack(loc)
            if loc_disk != 0 or disks > 1:
                return _bad("ZIP64 multi-disk archive")
            # As current zipfile does: the record is where the locator points, and may carry
            # extensible data up to the locator. If it isn't there, data was prepended to the
            # archive and the record must sit right before the locator, with no extensible data.
            fixed_at = eocd_at - _LOC64.size - _EOCD64.size
            if fixed_at < 0 or reloff > fixed_at:
                return _bad("ZIP64 locator points past where its end record can be")

            def record_at(offset: int) -> bytes:
                fp.seek(offset)
                data = fp.read(_EOCD64.size)
                return data if len(data) == _EOCD64.size and data[:4] == _EOCD64_SIG else b""

            rec, rec_at = record_at(reloff), reloff
            if not rec and reloff != fixed_at:
                rec, rec_at = record_at(fixed_at), fixed_at
            if not rec:
                return _bad("ZIP64 locator points to no ZIP64 end record")
            if rec_at != fixed_at and record_at(fixed_at):
                return _bad("two different ZIP64 end records")      # older zipfile reads the second one
            (_s, rec_size, _cv, _rv, disk, cd_disk, n_disk, n_total, cd_size, cd_offset) = _EOCD64.unpack(rec)
            if rec_size + 12 != _EOCD64.size + (fixed_at - rec_at) or cd_offset + cd_size != reloff:
                return _bad("ZIP64 end record doesn't match its locator")
            zip64 = True
            cd_end = rec_at
    if not zip64 and (0xFFFF in (n_disk, n_total) or 0xFFFFFFFF in (cd_size, cd_offset)):
        return _bad("ZIP64 size markers without a ZIP64 end record")
    if disk != 0 or cd_disk != 0 or n_disk != n_total:
        return _bad("multi-disk (spanned) archive")
    prefix = cd_end - cd_size - cd_offset
    start = cd_offset + prefix
    info = dict(entries=n_total, cd_size=cd_size, zip64=zip64)
    if cd_size > max_cd_bytes:
        return _bad(f"central directory of {cd_size:,} bytes exceeds the {max_cd_bytes:,}-byte limit", **info)
    if n_total > max_entries:
        return _bad(f"{n_total:,} entries declared; the limit is {max_entries:,}", **info)
    if start < 0 or prefix < 0 or start + cd_size > cd_end:
        return _bad("central directory lies outside the archive", **info)
    if n_total * _CD_FIXED > cd_size:
        return _bad(f"{n_total:,} entries can't fit in a {cd_size:,}-byte central directory", **info)
    fp.seek(start)
    cd = fp.read(cd_size)
    if len(cd) != cd_size:
        return _bad("central directory is truncated", **info)
    pos = count = 0
    while pos < cd_size:
        if cd_size - pos < _CD_FIXED or cd[pos:pos + 4] != _CD_SIG:
            return _bad(f"bad central directory entry at offset {start + pos}", **info)
        name_len, extra_len, comment_len = struct.unpack_from("<3H", cd, pos + 28)
        pos += _CD_FIXED + name_len + extra_len + comment_len
        count += 1
        if count > max_entries:
            return _bad(f"more than {max_entries:,} entries", **info)
    if pos != cd_size:
        return _bad("a central directory entry runs past the directory", **info)
    if count != n_total:
        return _bad(f"end record declares {n_total:,} entries but the directory holds {count:,}", **info)
    return ZipCheck(True, entries=count, cd_size=cd_size, zip64=zip64, prefix=prefix)
