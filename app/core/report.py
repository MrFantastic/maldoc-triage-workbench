"""Report generation: self-contained HTML report, phishing summary text, IOC CSV.

Everything that leaves the app is defanged and HTML-escaped.
"""
from __future__ import annotations

import csv
import datetime as _dt
import html
import io

from .models import SOURCE_TOOL, Severity
from .safety import csv_safe, defang
from .session import Session

VERDICT = {
    Severity.HIGH: ("HIGH RISK: LIKELY MALICIOUS",
                    "Confirm before acting: open each High finding and follow its Investigate steps (look at the "
                    "actual payload: script, command, embedded file). If confirmed malicious: block the hashes "
                    "and IOCs below (EDR, mail gateway, proxy), purge the message from all mailboxes, and check "
                    "endpoint telemetry for anyone who opened it."),
    Severity.MEDIUM: ("SUSPICIOUS: REVIEW NEEDED",
                      "Review the Medium findings before releasing. Many are common in legitimate files (forms, "
                      "links); the Investigate panel explains when. Do not open outside the analysis VM."),
    Severity.LOW: ("LOW RISK",
                   "No strong malicious indicators from static triage. Review the low-severity items "
                   "below before closing."),
    Severity.INFO: ("NO INDICATORS FOUND",
                    "Static triage found nothing suspicious. Static analysis cannot rule out every "
                    "technique; use judgement on context (sender, lure, request)."),
}

_SEV_COLOR = {Severity.HIGH: "#c62828", Severity.MEDIUM: "#b26a00", Severity.LOW: "#1565c0",
              Severity.INFO: "#616161"}


def _stamp() -> str:
    """Local time with its UTC offset, so a shared report is unambiguous: 2026-10-24 23:41 (UTC-04:00)."""
    now = _dt.datetime.now().astimezone()
    off = now.strftime("%z")
    return f"{now:%Y-%m-%d %H:%M} (UTC{off[:3]}:{off[3:]})"


def verdict(session: Session) -> tuple[str, str]:
    """The verdict title and recommended action for a session."""
    failed = "; ".join(f"{k}: {v}" for k, v in sorted(session.tool_errors.items()))
    if session.incomplete:
        return ("INCOMPLETE: ANALYSIS DID NOT RUN",
                f"No analysis tool completed, so this file has NOT been checked. Failed: {failed}. "
                "Fix the tools (Help → Tool status lists what's missing and how to get it), then reload the file. "
                "Do not treat this file as clean.")
    title, action = VERDICT[session.risk]
    partial = session.output_warnings
    if partial:
        action += (f" NOTE: part of the output of {', '.join(sorted(partial))} wasn't recognized (possibly a "
                   "newer tool version), so those results may be incomplete. Check the raw output.")
        if session.risk <= Severity.LOW and not session.tool_errors:
            title += " (UNVERIFIED)"
    if session.tool_errors:
        action += (f" WARNING: some tools failed, so this result may be incomplete ({failed}). "
                   "Fix them and re-run before relying on a low-risk verdict.")
        if session.risk <= Severity.LOW:
            title += " (INCOMPLETE)"
    return title, action


def phishing_summary(session: Session, analyst: str = "") -> str:
    """Plain-text summary to paste into a ticket: verdict, hashes, findings and defanged IOCs."""
    s = session.sample
    title, action = verdict(session)
    lines = [
        f"Static triage: {s.name}",
        f"Verdict: {title}",
        "",
        f"SHA256: {s.sha256}",
        f"MD5:    {s.md5}",
        f"Type:   {s.family.value} ({s.route.subtype})",
        f"Size:   {s.size:,} bytes",
    ]
    if session.parent_note:
        lines.append(f"Parent: {session.parent_note}")
    top = [f for f in sorted(session.findings, key=lambda f: -f.severity) if f.severity >= Severity.MEDIUM]
    if top:
        lines += ["", "Key findings:"]
        lines += [f"  - [{f.severity.label}] {defang(f.title)}" for f in top[:12]]
    iocs = session.all_iocs
    if iocs:
        lines += ["", "IOCs (defanged):"]
        lines += [f"  - {defang(v)}" for v, _src in iocs[:30]]
    lines += ["", f"Recommended action: {action}"]
    used = _versions_used(session)
    lines += ["", "Tools: " + (", ".join(f"{t} {v}" for t, v in used.items()) if used else
                               ", ".join(sorted(session.tools_run)) or "none")]
    lines.append(f"Analyzed: {_stamp()}" + (f" by {analyst}" if analyst else ""))
    return "\n".join(lines)


def _versions_used(session: Session) -> dict[str, str]:
    """{tool: version} for the tools that ran (or failed) on this sample."""
    sources = set(session.tools_run) | set(session.tool_errors)
    out: dict[str, str] = {}
    for src in sorted(sources):
        tool = SOURCE_TOOL.get(src)
        if tool:
            out[tool] = session.tool_versions.get(tool) or "version unknown"
    return out


def ioc_csv(session: Session) -> str:
    """The IOCs as CSV (defanged and formula-safe), plus the sample's hash."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["indicator_defanged", "source", "sample_sha256"])
    for v, src in session.all_iocs:
        w.writerow([csv_safe(defang(v)), csv_safe(src), session.sample.sha256])
    w.writerow([session.sample.sha256, "sample hash", session.sample.sha256])
    return buf.getvalue()


_REPORT_CSS = """
 :root { --fg:#1d1d1f; --muted:#666; --line:#ddd; --bg:#fff; --head:#f5f5f7; }
 @media (prefers-color-scheme: dark) {
   :root { --fg:#e6e6e9; --muted:#9a9aa3; --line:#3a3b40; --bg:#1b1c20; --head:#24262b; }
 }
 body { font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg);
        background: var(--bg); max-width: 1100px; margin: 24px auto; padding: 0 16px; }
 h1 { font-size: 22px; margin: 0 0 4px; }
 h2 { font-size: 16px; margin: 28px 0 8px; border-bottom: 1px solid var(--line); padding-bottom: 4px; }
 .muted { color: var(--muted); }
 .verdict { display: inline-block; background: VERDICT_COLOR; color: #fff; font-weight: 700;
            padding: 6px 14px; border-radius: 6px; margin: 10px 0; }
 table { border-collapse: collapse; width: 100%; }
 th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid var(--line); }
 thead th { background: var(--head); }
 table.kv th { width: 160px; color: var(--muted); font-weight: 500; }
 .mono, pre { font-family: ui-monospace, Consolas, "DejaVu Sans Mono", monospace; font-size: 12.5px;
              word-break: break-all; }
 pre { background: var(--head); padding: 10px; border-radius: 6px; white-space: pre-wrap; }
 .action { border-left: 4px solid VERDICT_COLOR; padding: 8px 12px; background: var(--head); }
"""


def html_report(session: Session, analyst: str = "") -> str:
    """A self-contained HTML report of the session."""
    s = session.sample
    title, action = verdict(session)
    color = "#6e56cf" if session.incomplete else _SEV_COLOR[session.risk]
    e = html.escape

    def row(k, v, mono=False):
        cls = ' class="mono"' if mono else ""
        return f"<tr><th>{e(k)}</th><td{cls}>{e(str(v))}</td></tr>"

    findings = "".join(
        f"<tr><td style='color:{_SEV_COLOR[f.severity]};font-weight:600'>{e(f.severity.label)}</td>"
        f"<td>{e(f.source)}</td><td>{e(defang(f.title))}</td><td>{e(defang(f.detail))}</td></tr>"
        for f in sorted(session.findings, key=lambda f: (-f.severity, f.source)))
    iocs = "".join(f"<tr><td class='mono'>{e(defang(v))}</td><td>{e(src)}</td></tr>"
                   for v, src in session.all_iocs)
    cmds = "\n".join(e(c) for c in dict.fromkeys(session.commands))
    notes = e(session.notes).replace("\n", "<br>") if session.notes.strip() else "<i>None</i>"
    generated = _stamp()
    by = f" · analyst {e(analyst)}" if analyst else ""
    css = _REPORT_CSS.replace("VERDICT_COLOR", color)
    rows = [("File name", s.name, False), ("Size", f"{s.size:,} bytes", False), ("Type", s.family.value, False),
            ("Detail", s.route.subtype, False), ("MD5", s.md5, True), ("SHA1", s.sha1, True),
            ("SHA256", s.sha256, True)]
    if session.parent_note:
        rows.append(("Parent", session.parent_note, False))
    rows.append(("Tools run", ", ".join(sorted(session.tools_run)) or "none", False))
    rows.append(("Tool versions", ", ".join(f"{t} {v}" for t, v in _versions_used(session).items()) or "unknown",
                 False))
    if session.output_warnings:
        rows.append(("Output not recognized",
                     "; ".join(f"{k}: {v}" for k, v in sorted(session.output_warnings.items())), False))
    if session.tool_errors:
        rows.append(("Tools FAILED", "; ".join(f"{k}: {v}" for k, v in sorted(session.tool_errors.items())), False))
    sample_rows = "\n".join(row(k, v, mono) for k, v, mono in rows)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Triage report: {e(s.name)}</title>
<style>{css}</style></head><body>
<h1>Maldoc triage report</h1>
<div class="muted">{e(s.name)} · generated {generated}{by}</div>
<div class="verdict">{e(title)}</div>
<div class="action"><b>Recommended action:</b> {e(action)}</div>

<h2>Sample</h2>
<table class="kv">
{sample_rows}
</table>

<h2>Findings ({len(session.findings)})</h2>
<table><thead><tr><th>Severity</th><th>Source</th><th>Finding</th><th>Detail</th></tr></thead>
<tbody>{findings or "<tr><td colspan=4 class='muted'>No findings.</td></tr>"}</tbody></table>

<h2>Indicators of compromise ({len(session.all_iocs)}, defanged)</h2>
<table><thead><tr><th>Indicator</th><th>Source</th></tr></thead>
<tbody>{iocs or "<tr><td colspan=2 class='muted'>None extracted.</td></tr>"}</tbody></table>

<h2>Analyst notes</h2>
<p>{notes}</p>

<h2>Reproduce (CLI-equivalent commands)</h2>
<pre>{cmds or "None recorded."}</pre>

<p class="muted">Generated by Maldoc Triage Workbench. Static analysis only; the sample was never executed
or rendered.</p>
</body></html>"""
