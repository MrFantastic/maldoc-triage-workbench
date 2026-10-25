"""Shared, GUI-independent data models.

Everything in app.core is deliberately free of Qt imports so it can be
unit-tested headless and reused by a future CLI or batch mode.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    """Finding severity, from INFO to HIGH."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_text(cls, text: str | None) -> "Severity":
        t = (text or "").strip().lower()
        if t in ("high", "critical"):
            return cls.HIGH
        if t in ("medium", "med"):
            return cls.MEDIUM
        if t == "low":
            return cls.LOW
        return cls.INFO


# finding source -> the tool (and so the version) behind it
SOURCE_TOOL = {
    "pdfid": "pdfid", "pdf-parser": "pdf-parser", "peepdf": "peepdf", "oledump": "oledump",
    "oleid": "oletools", "mraptor": "oletools", "olevba": "oletools", "msodde": "oletools",
    "oleobj": "oletools", "rtfobj": "oletools", "metadata": "oletools",
    "xlmdeobfuscator": "XLMMacroDeobfuscator",
}


class Family(enum.Enum):
    """Top-level file family, decided by content (magic bytes), never extension."""
    PDF = "PDF"
    OLE = "OLE2 (legacy Office)"
    OOXML = "OOXML (zip-based Office)"
    RTF = "RTF"
    OFFICE_TEXT = "Office text format (MHT / XML / SLK)"
    ZIP = "Zip archive (not Office)"
    UNKNOWN = "Unknown"


@dataclass
class Finding:
    """A single noteworthy observation, produced by any tool module."""
    source: str                 # e.g. "pdfid", "mraptor", "router"
    severity: Severity
    title: str                  # short, shown in the findings list
    detail: str = ""            # longer explanation / evidence
    ref: dict[str, Any] = field(default_factory=dict)  # pivot info, e.g. {"offset": 1234}

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "severity": self.severity.label,
            "title": self.title,
            "detail": self.detail,
            "ref": self.ref,
        }


@dataclass
class ToolResult:
    """Common envelope every adapter returns."""
    tool: str
    ok: bool
    command: str = ""           # CLI-equivalent command shown to the analyst
    raw_output: str = ""        # what the CLI would have printed
    error: str = ""
    data: Any = None            # adapter-specific structured result
    findings: list[Finding] = field(default_factory=list)
