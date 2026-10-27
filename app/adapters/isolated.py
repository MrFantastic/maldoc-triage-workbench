"""GUI-side calls that parse a hostile file. Each runs in a separate worker
process (run.py --worker) with a timeout, an output cap and a kill switch, so
a parser hang, crash or memory blow-up can't take the app down. In the REMnux
edition, tasks that need oletools, msoffcrypto or jsbeautifier run under REMnux's
own environment for that library (toolenv.py); YARA under REMnux's Python that has it.

Signatures mirror the in-process adapter functions they replace.
"""
from __future__ import annotations

import json

from ..core import codec
from . import scripts, toolenv
from .macro_adapter import WrongPassword
from .pdf_crypto import PdfPasswordRequired


class WorkerError(RuntimeError):
    """The worker timed out, crashed, was stopped, or returned garbage."""


TIMEOUTS = {
    "identify": 60, "pdfid.run": 120, "pdfid.disarm": 120, "office.run": 240,
    "macro.analyse": 300, "macro.is_encrypted": 60, "macro.decrypt": 120,
    "parts.read": 180, "parts.preview": 60, "parts.extract": 120, "meta.read": 60,
    "js.beautify": 60, "pdf.decrypt": 180, "yara.scan": 600,
}
_REMOTE_ERRORS = {"WrongPassword": WrongPassword, "PdfPasswordRequired": PdfPasswordRequired}
MAX_REPLY = 256 * 1024 * 1024


def call(task: str, *args, timeout: int | None = None, **kwargs):
    """Run a worker task in its own process and return the decoded result; raise WorkerError if it fails."""
    from ..worker import RESULT_MARKER
    request = codec.dumps({"task": task, "args": list(args), "kwargs": kwargs}).encode("utf-8")
    limit = timeout or TIMEOUTS.get(task, 120)
    r = scripts.run_cmd(toolenv.worker_command(task), f"worker {task}", limit,
                        input_bytes=request, max_output=MAX_REPLY)
    if r.stopped:
        raise WorkerError(f"{task}: stopped by user")
    if r.timed_out:
        raise WorkerError(f"{task}: stopped after {limit} s. The file may be crafted to hang the parser; "
                          "treat that as suspicious.")
    if r.truncated:
        raise WorkerError(f"{task}: result too large")
    idx = r.stdout.rfind(RESULT_MARKER)
    if idx == -1:
        tail = (r.stderr or "").strip().splitlines()[-1:] or [f"exit code {r.returncode}"]
        raise WorkerError(f"{task}: the parser process crashed ({tail[0][:300]}). "
                          "A crash on a hostile file is itself suspicious.")
    try:
        reply = codec.decode(json.loads(r.stdout[idx + len(RESULT_MARKER):]))
    except (ValueError, TypeError) as exc:
        raise WorkerError(f"{task}: unreadable reply ({exc})") from exc
    if reply.get("ok"):
        return reply.get("result")
    err_type, err = reply.get("error_type", "Error"), reply.get("error", "")
    if err_type in _REMOTE_ERRORS:
        raise _REMOTE_ERRORS[err_type](err)
    raise WorkerError(f"{task}: {err_type}: {err}")


def tidy(message: str) -> str:
    """First line of a job failure, without the 'WorkerError: task:' plumbing prefix."""
    first = (message or "").strip().splitlines()[0] if (message or "").strip() else "unknown error"
    if first.startswith("WorkerError: "):
        first = first[len("WorkerError: "):]
        task, sep, rest = first.partition(": ")
        if sep and (task in TIMEOUTS or task.startswith("selftest.")):
            first = rest
    return first


# ------------------------------------------------------------------ wrappers


def identify(path: str, name: str):
    """router.identify, run in a worker."""
    return call("identify", path, name)


def pdfid_run(path, opts):
    """pdfid_adapter.run, run in a worker."""
    return call("pdfid.run", path, opts)


def pdfid_disarm(path, out_dir) -> tuple[str, str]:
    """pdfid_adapter.disarm, run in a worker: (output_path, cli_command)."""
    return tuple(call("pdfid.disarm", path, out_dir))


def office_run(path):
    """office_adapter.run (oleid and mraptor), run in a worker."""
    return call("office.run", path)


def macro_analyse(path, opts):
    """macro_adapter.analyse, run in a worker."""
    return call("macro.analyse", path, opts)


def macro_is_encrypted(path) -> bool:
    """macro_adapter.is_encrypted, run in a worker."""
    return bool(call("macro.is_encrypted", path))


def macro_decrypt(path, out_dir, password) -> tuple[str, str, str]:
    """macro_adapter.decrypt, run in a worker: (output_path, password_used, cli_command)."""
    return tuple(call("macro.decrypt", path, out_dir, password))


def read_parts(path):
    """container_adapter.read_parts, run in a worker."""
    return call("parts.read", path)


def preview_part(path, name) -> tuple[bytes, int]:
    """container_adapter.preview_part, run in a worker: (first bytes, full size)."""
    data, size = call("parts.preview", path, name)
    return data, size


def extract_part(path, name, out_dir) -> tuple[str, int, str]:
    """container_adapter.extract_part, run in a worker: (dest, size, sha256)."""
    return tuple(call("parts.extract", path, name, out_dir))


def read_metadata(path, family):
    """container_adapter.read_metadata, run in a worker."""
    return call("meta.read", path, family)


def beautify(code: str) -> tuple[str, str]:
    """peepdf_adapter.beautify, run in a worker on at most 5 MB of code: (code, engine)."""
    return tuple(call("js.beautify", code[:5_000_000]))


def yara_scan(path, files, zip_parts: bool):
    """yara_adapter.scan (the whole file, and each ZIP part when zip_parts), run in a worker."""
    return call("yara.scan", path, list(files), bool(zip_parts))


def pdf_decrypt(path, out_dir, password="") -> tuple[str, str]:
    """pdf_crypto.decrypt, run in a worker: (output_path, library_used)."""
    return tuple(call("pdf.decrypt", path, out_dir, password))
