"""Safety helpers: defanging, safe output paths, tool output dirs."""
from __future__ import annotations

import os
import re
import shlex
import subprocess

_SCHEME_RE = re.compile(r"\b(h)(tt)(ps?|p)(://)", re.IGNORECASE)
_FTP_RE = re.compile(r"\bftp://", re.IGNORECASE)
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>)\]]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def defang(text: str) -> str:
    """Make URLs / IPs non-clickable: http://evil.com -> hxxp://evil[.]com."""
    def _fix_url(m: re.Match) -> str:
        url = m.group(0)
        url = _SCHEME_RE.sub(lambda mm: "hxx" + mm.group(3) + mm.group(4), url)
        url = _FTP_RE.sub("fxp://", url)
        scheme, sep, rest = url.partition("://")
        host, slash, path = rest.partition("/")
        return f"{scheme}{sep}{host.replace('.', '[.]')}{slash}{path}"

    text = _URL_RE.sub(_fix_url, text)
    text = _IP_RE.sub(r"\1.\2.\3[.]\4", text)
    return text


_BAD_CHARS = re.compile(r'[^A-Za-z0-9._ -]')


def sanitize_filename(name: str, fallback: str = "extracted") -> str:
    """A safe file name: no folders or unsafe characters, at most 120 characters."""
    name = os.path.basename(name or "")
    name = _BAD_CHARS.sub("_", name).strip(" .")
    return name[:120] or fallback


def safe_output_path(out_dir: str, name: str, suffix: str = ".bin") -> str:
    """Return a non-existing path in out_dir. Extracted content always gets a
    neutral suffix (default .bin) so nothing can be double-clicked by accident."""
    os.makedirs(out_dir, exist_ok=True)
    base = sanitize_filename(name)
    if suffix and not base.lower().endswith(suffix.lower()):
        base += suffix
    candidate = os.path.join(out_dir, base)
    stem, ext = os.path.splitext(candidate)
    n = 1
    while os.path.exists(candidate):
        candidate = f"{stem}_{n}{ext}"
        n += 1
    return candidate


def default_output_dir() -> str:
    """The default folder for extracted files and logs (~/MTW_output)."""
    return os.path.join(os.path.expanduser("~"), "MTW_output")


def quote_arg(arg: str) -> str:
    """Quote an argument the way the analyst's own shell expects (cmd.exe on Windows)."""
    if os.name == "nt":
        return subprocess.list2cmdline([arg])
    return shlex.quote(arg)


def command_line(args: list[str]) -> str:
    """Join arguments into a displayed command line, quoting where needed."""
    return " ".join(quote_arg(a) for a in args)


def csv_safe(value) -> str:
    """Stop a spreadsheet from treating text that came from a sample as a formula."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text
