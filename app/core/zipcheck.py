"""Bounded ZIP structure check, run before Python's zipfile parses a sample.

zipfile reads the whole central directory into memory and builds one ZipInfo object per
entry before the app can apply any limit, so a crafted archive (up to the 256 MB sample
limit) could make it allocate gigabytes. This module finds the end-of-central-directory
record exactly the way zipfile does (including the ZIP64 record), then checks that what
it declares is consistent and within budget, and counts the directory entries without
building any objects. Only an archive that passes is handed to zipfile.

Rejected: no end record; multi-disk; ZIP64 markers without a ZIP64 record (or a locator
without its record); a directory that starts before the file or runs past the end
record; a directory larger than MAX_CD_BYTES; more than MAX_ENTRIES entries; an entry
count the directory can't hold; a directory entry with a bad signature or that overruns
the directory; a declared count that doesn't match the entries actually present.
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
            _s, loc_disk, _rel, disks = _LOC64.unpack(loc)
            if loc_disk != 0 or disks > 1:
                return _bad("ZIP64 multi-disk archive")
            rec_at = eocd_at - _LOC64.size - _EOCD64.size
            if rec_at < 0:
                return _bad("ZIP64 locator without a ZIP64 end record")
            fp.seek(rec_at)
            rec = fp.read(_EOCD64.size)
            if len(rec) != _EOCD64.size or rec[:4] != _EOCD64_SIG:
                return _bad("ZIP64 locator without a ZIP64 end record")
            (_s, rec_size, _cv, _rv, disk, cd_disk, n_disk, n_total, cd_size, cd_offset) = _EOCD64.unpack(rec)
            if rec_size < _EOCD64.size - 12:
                return _bad("ZIP64 end record too short")
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
