"""Decrypt PDFs that use an empty user password (the common "encrypted only to
restrict editing" case), so every tool can read their strings and scripts.

Runs inside a worker process: pikepdf/pypdf parse the hostile file.
Writes a new file; the original is never modified.
"""
from __future__ import annotations

import os

from ..core.safety import safe_output_path


class PdfPasswordRequired(Exception):
    """The PDF needs a password, and the one given (or the empty one) didn't open it."""


def available() -> str | None:
    """Name of the library that will be used, or None."""
    try:
        import pikepdf  # type: ignore  # noqa: F401
        return "pikepdf"
    except ImportError:
        pass
    try:
        import pypdf  # type: ignore  # noqa: F401
        return "pypdf"
    except ImportError:
        return None


def decrypt(path: str, out_dir: str, password: str = "") -> tuple[str, str]:
    """Return (output_path, library_used). Raises PdfPasswordRequired if the
    empty/given password doesn't open the file."""
    base = os.path.splitext(os.path.basename(path))[0] + ".decrypted"
    dest = safe_output_path(out_dir, base, suffix=".pdf.bin")
    lib = available()
    if lib == "pikepdf":
        import pikepdf  # type: ignore
        try:
            pdf = pikepdf.open(path, password=password)
        except pikepdf.PasswordError as exc:
            raise PdfPasswordRequired(str(exc)) from exc
        with pdf:
            if not pdf.is_encrypted:
                raise ValueError("This PDF is not encrypted.")
            # no object streams: every object stays visible to pdfid / pdf-parser
            pdf.save(dest, object_stream_mode=pikepdf.ObjectStreamMode.disable)
        return dest, "pikepdf"
    if lib == "pypdf":
        import pypdf  # type: ignore
        reader = pypdf.PdfReader(path, strict=False)
        if not reader.is_encrypted:
            raise ValueError("This PDF is not encrypted.")
        if not reader.decrypt(password):
            raise PdfPasswordRequired("the password did not open the document")
        writer = pypdf.PdfWriter(clone_from=reader)
        with open(dest, "wb") as fh:
            writer.write(fh)
        return dest, "pypdf"
    raise RuntimeError("No PDF library available: pip install pikepdf (or pypdf).")
