"""Write password-protected zips ("infected" convention) for extracted artifacts.

Python's zipfile reads encrypted zips but can't write them, so this writes
traditional PKWARE (ZipCrypto) encryption itself. ZipCrypto is weak crypto,
and that's fine: the password is public by convention. Its job is to stop
antivirus from quarantining the artifacts, and to stop anyone opening a
payload by double-click. Every unzip tool and every sandbox accepts it.
"""
from __future__ import annotations

import datetime as _dt
import os
import secrets
import struct
import zlib

DEFAULT_PASSWORD = b"infected"
_CRC_TABLE = [0] * 256
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    _CRC_TABLE[_i] = _c


class _ZipCrypto:
    def __init__(self, password: bytes):
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for b in password:
            self._update(b)

    def _update(self, b: int) -> None:
        t = _CRC_TABLE
        self.k0 = (self.k0 >> 8) ^ t[(self.k0 ^ b) & 0xFF]
        self.k1 = ((self.k1 + (self.k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = (self.k2 >> 8) ^ t[(self.k2 ^ (self.k1 >> 24)) & 0xFF]

    def encrypt(self, data: bytes) -> bytes:
        t = _CRC_TABLE
        k0, k1, k2 = self.k0, self.k1, self.k2
        out = bytearray(len(data))
        for i, p in enumerate(data):
            tmp = (k2 | 2) & 0xFFFF
            out[i] = p ^ (((tmp * (tmp ^ 1)) >> 8) & 0xFF)
            k0 = (k0 >> 8) ^ t[(k0 ^ p) & 0xFF]
            k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
            k2 = (k2 >> 8) ^ t[(k2 ^ (k1 >> 24)) & 0xFF]
        self.k0, self.k1, self.k2 = k0, k1, k2
        return bytes(out)


def _dos_time(ts: float) -> tuple[int, int]:
    d = _dt.datetime.fromtimestamp(ts)
    if d.year < 1980:
        d = _dt.datetime(1980, 1, 1)
    return ((d.hour << 11) | (d.minute << 5) | (d.second // 2),
            ((d.year - 1980) << 9) | (d.month << 5) | d.day)


def write(dest: str, entries: list[tuple[str, bytes]], password: bytes = DEFAULT_PASSWORD,
          progress=None) -> int:
    """Write entries [(name in zip, data)] to dest, every entry encrypted. Returns bytes written.
    progress(done_bytes, total_bytes) is called between entries."""
    if len(entries) > 0xFFFF:
        raise ValueError("too many files for one zip; export fewer artifacts at a time")
    total = sum(len(d) for _, d in entries)
    done = 0
    central = bytearray()
    offset = 0
    tm, dt = _dos_time(_dt.datetime.now().timestamp())
    seen: set[str] = set()
    with open(dest, "wb") as fh:
        for name, data in entries:
            base, n = name, 2
            while name in seen:                       # keep names unique inside the zip
                root, ext = os.path.splitext(base)
                name, n = f"{root}_{n}{ext}", n + 1
            seen.add(name)
            fname = name.replace("\\", "/").lstrip("/").encode("utf-8")
            crc = zlib.crc32(data) & 0xFFFFFFFF
            comp = zlib.compressobj(6, zlib.DEFLATED, -15)
            body = comp.compress(data) + comp.flush()
            method = 8
            if len(body) >= len(data):
                body, method = data, 0
            z = _ZipCrypto(password)
            header = secrets.token_bytes(11) + bytes([crc >> 24])
            enc = z.encrypt(header) + z.encrypt(body)
            flags = 0x1 | 0x800                      # encrypted, UTF-8 names
            local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, method, tm, dt, crc,
                                len(enc), len(data), len(fname), 0)
            fh.write(local + fname + enc)
            central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, method, tm, dt,
                                   crc, len(enc), len(data), len(fname), 0, 0, 0, 0, 0, offset) + fname
            offset += len(local) + len(fname) + len(enc)
            done += len(data)
            if progress:
                progress(done, total)
        if offset > 0xFFFFFFFF:
            raise ValueError("too large for a classic zip; export fewer artifacts at a time")
        fh.write(central)
        fh.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries),
                             len(central), offset, 0))
        return offset + len(central) + 22


def write_files(dest: str, paths: list[str], manifest_text: str = "",
                password: bytes = DEFAULT_PASSWORD, progress=None) -> int:
    """Zip files (by base name) and an optional MANIFEST.txt, every entry encrypted; return bytes written."""
    entries = []
    for p in paths:
        with open(p, "rb") as fh:
            entries.append((os.path.basename(p), fh.read()))
    if manifest_text:
        entries.append(("MANIFEST.txt", manifest_text.encode("utf-8")))
    return write(dest, entries, password, progress)
