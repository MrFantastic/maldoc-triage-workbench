"""Notice when a tool's output isn't in the shape this app's parsers expect.

The app reads several tools by parsing their printed text, so a new tool
version that changes its format could make findings disappear without any
error. Each parser therefore records what it couldn't recognize:

  * nothing recognized at all → the tool is treated as FAILED, so the verdict
    says INCOMPLETE instead of "nothing found";
  * some lines not recognized → an Info finding says so (with the tool version
    and the first unrecognized lines), even when other findings exist, and the
    verdict notes that this tool's results may be partial.
"""
from __future__ import annotations

import re

from .models import Finding, Severity
from .safety import defang

KB = "tool:unrecognized_output"

# Messages tools print that aren't analysis output and aren't a format change.
_NOTICES = [
    re.compile(r"^This program has not been tested with this version of Python"),
    re.compile(r"^Should you encounter problems, please use Python version"),
]


def is_notice(line: str) -> bool:
    """True for a known harmless notice, such as a Python-version warning from Didier Stevens' tools."""
    s = line.strip()
    return any(p.match(s) for p in _NOTICES)


def keep(lines: list[str], line: str, limit: int = 200) -> None:
    """Record an unrecognized line (bounded; the count is what matters past that)."""
    s = line.rstrip()
    if s.strip() and not is_notice(s):
        lines.append(s[:300] if len(lines) < limit else "")


def _sample(lines: list[str], n: int = 5) -> str:
    shown = [defang(ln.strip()) for ln in lines if ln][:n]
    return "\n".join(f"  {ln}" for ln in shown)


def note(source: str, lines: list[str], version: str = "", tab: str | None = None,
         unit: str = "line(s) of output", consequence: str = "") -> Finding:
    """Info finding: part of a tool's output wasn't recognized. It doesn't raise the risk,
    but it's listed with the findings and qualifies the verdict."""
    n = len(lines)
    ver = f" {version}" if version else ""
    consequence = consequence or f"so findings from {source} may be incomplete"
    return Finding(
        source, Severity.INFO,
        f"{source}{ver}: {n} {unit} not recognized",
        f"Part of {source}'s output didn't match what this app knows how to read. Usually that means a "
        f"newer {source} version changed or added something, {consequence}. Check its raw output. "
        f"First unrecognized item(s):\n{_sample(lines)}",
        ref={"kb": KB, "tab": tab or source, "unrecognized": n, "version": version})


def failure(source: str, lines: list[str], version: str = "", what: str = "") -> str:
    """Error text for 'nothing in the output was recognized' (marks the tool as failed)."""
    ver = f" {version}" if version else ""
    first = f"{source}{ver} output not recognized" + (f" ({what})" if what else "")
    detail = ("This app couldn't read any results from it, so nothing it may have found is shown. "
              "A newer tool version may have changed its output format.")
    sample = _sample(lines)
    return f"{first}\n\n{detail}" + (f"\nFirst lines:\n{sample}" if sample else "")


def warnings(findings) -> dict[str, str]:
    """source -> title for every 'output not recognized' note among the findings."""
    return {f.source: f.title for f in findings if f.ref.get("kb") == KB}
