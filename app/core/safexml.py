"""Parse attacker-controlled XML (OOXML relationships and docProps).

OOXML parts never legitimately contain DTDs, so any <!DOCTYPE or <!ENTITY is
refused before parsing: no entity expansion ("billion laughs") and no external
entity fetches. defusedxml is used when installed, as a second layer.
"""
from __future__ import annotations

import re
from xml.etree import ElementTree as _ET

try:  # optional second layer
    from defusedxml import ElementTree as _DET  # type: ignore
except ImportError:  # pragma: no cover - depends on environment
    _DET = None

ParseError = _ET.ParseError
_DTD = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)
MAX_XML_BYTES = 32 * 1024 * 1024


class UnsafeXML(ValueError):
    """An XML part was refused: too large, or it declares a DTD or entities."""


def fromstring(data: bytes | str):
    """Parse XML after refusing DTDs, entity declarations and oversized input (defusedxml when installed)."""
    raw = data.encode("utf-8", "replace") if isinstance(data, str) else data
    if len(raw) > MAX_XML_BYTES:
        raise UnsafeXML(f"XML part larger than {MAX_XML_BYTES:,} bytes")
    if _DTD.search(raw):
        raise UnsafeXML("DTD / entity declaration in an Office XML part (not allowed, possible XML attack)")
    if _DET is not None:
        return _DET.fromstring(raw)
    return _ET.fromstring(raw)
