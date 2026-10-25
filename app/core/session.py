"""A loaded sample and the analysis session around it (Qt-free)."""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any

from .models import Family, Finding, Severity
from .router import RouteInfo, identify
from .safety import defang

MAX_SAMPLE_BYTES = 256 * 1024 * 1024  # refuse anything larger than 256 MB


class SampleTooLarge(Exception):
    """The file is larger than the app will load."""


@dataclass
class Sample:
    """The file under analysis: its bytes, hashes and route."""
    path: str
    data: bytes
    md5: str
    sha1: str
    sha256: str
    route: RouteInfo

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def family(self) -> Family:
        return self.route.family

    def verify_unchanged(self) -> bool:
        """Re-hash the file on disk; False means something modified the original."""
        try:
            with open(self.path, "rb") as fh:
                return hashlib.sha256(fh.read()).hexdigest() == self.sha256
        except OSError:
            return False

    @classmethod
    def load(cls, path: str, max_bytes: int = MAX_SAMPLE_BYTES, isolate: bool = True) -> "Sample":
        """Read and hash the sample. Its structure (OLE directory, zip listing) is
        parsed in a worker process; if that fails, a byte-signature-only
        identification is used and a finding says so."""
        size = os.path.getsize(path)
        if size > max_bytes:
            raise SampleTooLarge(f"{size:,} bytes exceeds the {max_bytes:,} byte limit")
        # Opened read-only, read once; tools receive the path, never a writable handle.
        with open(path, "rb") as fh:
            data = fh.read()
        return cls(
            path=os.path.abspath(path),
            data=data,
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(),
            route=_route(path, data, isolate),
        )


def _route(path: str, data: bytes, isolate: bool) -> RouteInfo:
    if not isolate:
        return identify(data, path)
    from ..adapters import isolated
    try:
        return isolated.identify(path, os.path.basename(path))
    except Exception as exc:   # worker crash / timeout: fall back to signatures only
        route = identify(data, path, deep=False)
        route.warnings.append(Finding(
            "router", Severity.MEDIUM, "File structure could not be parsed",
            f"Identification fell back to byte signatures only: {exc}",
            ref={"kb": "router:identify_failed"}))
        return route


@dataclass
class Session:
    """Everything learned about one sample: findings, IOCs, notes, tool runs and failures."""
    sample: Sample
    findings: list[Finding] = field(default_factory=list)
    notes: str = ""
    parent_note: str = ""             # e.g. "decrypted from invoice.xls (SHA256 ...)"
    tools_run: set[str] = field(default_factory=set)
    iocs: dict[str, list[str]] = field(default_factory=dict)   # source -> raw indicators
    commands: list[str] = field(default_factory=list)          # CLI-equivalent commands run
    tool_errors: dict[str, str] = field(default_factory=dict)  # source -> why it failed
    facts: dict[str, dict] = field(default_factory=dict)       # source -> what that tool established
    artifacts: list[str] = field(default_factory=list)         # files the app wrote for this sample
    tool_versions: dict[str, str] = field(default_factory=dict)  # tool -> version detected this run
    opened_at: str = field(default_factory=lambda: _dt.datetime.now().isoformat(timespec="seconds"))

    def __post_init__(self) -> None:
        self.findings.extend(self.sample.route.warnings)

    def replace_findings(self, source: str, new: list[Finding]) -> None:
        """Re-running a tool replaces its earlier findings instead of duplicating them."""
        self.findings = [f for f in self.findings if f.source != source] + list(new)
        self.tools_run.add(source)
        self.tool_errors.pop(source, None)
        self.correlate()

    def set_facts(self, source: str, facts: dict) -> None:
        self.facts[source] = dict(facts)
        self.correlate()

    def correlate(self) -> int:
        from . import correlate
        return correlate.apply(self.findings, self.facts)

    def add_artifact(self, path: str) -> None:
        if path and path not in self.artifacts:
            self.artifacts.append(path)

    def mark_failed(self, source: str, error: str) -> None:
        """A tool could not run. Its old findings stay out of the verdict's 'clean' claim."""
        self.tool_errors[source] = (error or "failed").strip().splitlines()[0][:300]
        self.tools_run.discard(source)
        self.facts.pop(source, None)
        self.correlate()

    @property
    def output_warnings(self) -> dict[str, str]:
        """source -> note, for tools whose output was only partly recognized."""
        from .outputcheck import warnings
        return warnings(self.findings)

    @property
    def incomplete(self) -> bool:
        """True when no analysis tool succeeded: the verdict must not say 'clean'."""
        return bool(self.tool_errors) and not self.tools_run

    def set_iocs(self, source: str, values: list[str]) -> None:
        self.iocs[source] = sorted({v.strip() for v in values if v and v.strip()})

    @property
    def all_iocs(self) -> list[tuple[str, str]]:
        """(indicator, source) pairs, de-duplicated by indicator."""
        seen: dict[str, str] = {}
        for src, vals in self.iocs.items():
            for v in vals:
                seen.setdefault(v, src)
        return sorted((v, s) for v, s in seen.items())

    @property
    def risk(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def export_dict(self) -> dict[str, Any]:
        s = self.sample
        return {
            "generated_by": "Maldoc Triage Workbench",
            "opened_at": self.opened_at,
            "sample": {
                "name": s.name, "path": s.path, "size": s.size,
                "md5": s.md5, "sha1": s.sha1, "sha256": s.sha256,
                "family": s.family.value, "subtype": s.route.subtype,
                "header_offset": s.route.header_offset, "pdf_version": s.route.pdf_version,
            },
            "parent": self.parent_note,
            "tools_run": sorted(self.tools_run),
            "tool_errors": self.tool_errors,
            "output_not_recognized": self.output_warnings,
            "tool_versions": self.tool_versions,
            "analysis_incomplete": self.incomplete,
            "iocs_defanged": [{"indicator": defang(v), "source": s} for v, s in self.all_iocs],
            "commands": list(dict.fromkeys(self.commands)),
            "artifacts": self.artifacts,
            "overall_risk": self.risk.label,
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda f: -f.severity)],
            "notes": self.notes,
        }

    def export_json(self) -> str:
        return json.dumps(self.export_dict(), indent=2)
