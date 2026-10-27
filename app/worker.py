"""Helper-process entry points. Everything that parses a hostile file runs
here, in a separate process the GUI can time out and kill.

    run.py --worker                         one task: JSON request on stdin, JSON reply on stdout
    run.py --run-script <file.py> [args]    run a vendored tool script (frozen builds)
    run.py --run-module <module> [args]     python -m <module> equivalent (frozen builds)
    run.py --run-callable <mod:func> [args] call a console entry point (frozen builds)
    run.py --net-probe <file>               network-isolation self-check (scripts._isolation_works)

This module must not import Qt.
"""
from __future__ import annotations

import json
import os
import runpy
import sys
import traceback

RESULT_MARKER = b"\nMTW-RESULT:"
MEMORY_LIMIT = 3 * 1024 ** 3      # per worker, where the OS lets us set one


def _limit_memory() -> None:
    """Best effort: stop a decompression bomb from exhausting RAM (POSIX only)."""
    try:
        import resource  # type: ignore
    except ImportError:   # Windows: the per-task timeout and size caps still apply
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        limit = MEMORY_LIMIT if hard in (-1, resource.RLIM_INFINITY) else min(MEMORY_LIMIT, hard)
        resource.setrlimit(resource.RLIMIT_AS, (limit, hard))
    except (ValueError, OSError):
        pass


# --------------------------------------------------------------------------- tasks


def _identify(path: str, name: str):
    from .core.router import identify
    from .core.session import MAX_SAMPLE_BYTES
    with open(path, "rb") as fh:
        data = fh.read(MAX_SAMPLE_BYTES + 1)
    return identify(data, name)


def _pdfid_run(path, opts):
    from .adapters import pdfid_adapter
    return pdfid_adapter.run(path, opts)


def _pdfid_disarm(path, out_dir):
    from .adapters import pdfid_adapter
    return list(pdfid_adapter.disarm(path, out_dir))


def _office_run(path):
    from .adapters import office_adapter
    return office_adapter.run(path)


def _macro_analyse(path, opts):
    from .adapters import macro_adapter
    return macro_adapter.analyse(path, opts)


def _macro_is_encrypted(path):
    from .adapters import macro_adapter
    return macro_adapter.is_encrypted(path)


def _macro_decrypt(path, out_dir, password):
    from .adapters import macro_adapter
    return list(macro_adapter.decrypt(path, out_dir, password))


def _parts_read(path):
    from .adapters import container_adapter
    return container_adapter.read_parts(path)


def _parts_preview(path, name):
    from .adapters import container_adapter
    data, size = container_adapter.preview_part(path, name)
    return [data, size]


def _parts_extract(path, name, out_dir):
    from .adapters import container_adapter
    return list(container_adapter.extract_part(path, name, out_dir))


def _meta_read(path, family):
    from .adapters import container_adapter
    return container_adapter.read_metadata(path, family)


def _js_beautify(code):
    from .adapters import peepdf_adapter
    return list(peepdf_adapter.beautify(code))


def _pdf_decrypt(path, out_dir, password=""):
    from .adapters import pdf_crypto
    return list(pdf_crypto.decrypt(path, out_dir, password))


def _selftest_sleep(seconds):
    import time
    time.sleep(float(seconds))
    return "slept"


def _selftest_echo(value):
    return value


def _selftest_python():
    return sys.executable


TASKS = {
    "identify": _identify,
    "pdfid.run": _pdfid_run,
    "pdfid.disarm": _pdfid_disarm,
    "office.run": _office_run,
    "macro.analyse": _macro_analyse,
    "macro.is_encrypted": _macro_is_encrypted,
    "macro.decrypt": _macro_decrypt,
    "parts.read": _parts_read,
    "parts.preview": _parts_preview,
    "parts.extract": _parts_extract,
    "meta.read": _meta_read,
    "js.beautify": _js_beautify,
    "pdf.decrypt": _pdf_decrypt,
    "selftest.sleep": _selftest_sleep,
    "selftest.echo": _selftest_echo,
    "selftest.python": _selftest_python,
}


def _reply(payload: dict) -> None:
    from .core import codec
    body = json.dumps(codec.encode(payload), separators=(",", ":")).encode("utf-8")
    data = memoryview(RESULT_MARKER + body + b"\n")
    while data:                       # os.write may write only part of a large reply
        data = data[os.write(1, data):]


def worker_main() -> int:
    """run.py --worker: read a request from stdin, run the allowlisted task, print the reply.

    In the REMnux edition some tasks run under a REMnux tool environment's interpreter
    instead of the app's (adapters/toolenv.py); this code must work under both."""
    _limit_memory()
    os.environ["MTW_IN_WORKER"] = "1"     # a worker never looks for other environments itself
    if sys.stdin is not None:
        raw = sys.stdin.buffer.read()
    else:                       # pythonw: no sys.stdin object, but fd 0 is our pipe
        chunks = []
        while True:
            block = os.read(0, 1 << 20)
            if not block:
                break
            chunks.append(block)
        raw = b"".join(chunks)
    # anything a library prints goes to stderr, so stdout carries only our reply
    real_stdout_fd = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr if sys.stderr is not None else open(os.devnull, "w")
    try:
        from .core import codec
        req = codec.loads(raw)
        fn = TASKS.get(req.get("task"))
        if fn is None:
            payload = {"ok": False, "error_type": "UnknownTask", "error": f"unknown task {req.get('task')!r}"}
        else:
            try:
                payload = {"ok": True, "result": fn(*req.get("args", []), **req.get("kwargs", {}))}
            except Exception as exc:  # the analysis failed; report it, don't crash silently
                payload = {"ok": False, "error_type": type(exc).__name__, "error": str(exc),
                           "trace": traceback.format_exc()[-4000:]}
    except Exception as exc:
        payload = {"ok": False, "error_type": type(exc).__name__, "error": str(exc),
                   "trace": traceback.format_exc()[-4000:]}
    os.dup2(real_stdout_fd, 1)
    try:
        _reply(payload)
    except TypeError as exc:    # result not encodable
        _reply({"ok": False, "error_type": "EncodeError", "error": str(exc)})
    return 0


# --------------------------------------------------------------------------- tool modes


def run_script_main(argv: list[str]) -> int:
    """run.py --run-script SCRIPT ARGS...: run a tool script as __main__ with this interpreter."""
    script, args = argv[0], argv[1:]
    sys.argv = [script] + args
    sys.path.insert(0, os.path.dirname(os.path.abspath(script)))
    try:
        runpy.run_path(script, run_name="__main__")
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    return 0


def run_module_main(argv: list[str]) -> int:
    """run.py --run-module MODULE ARGS...: run an installed module (e.g. oletools.olevba) as __main__."""
    module, args = argv[0], argv[1:]
    sys.argv = [module] + args
    try:
        runpy.run_module(module, run_name="__main__", alter_sys=True)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    return 0


def run_callable_main(argv: list[str]) -> int:
    """run.py --run-callable module:function ARGS...: call a console-script entry point."""
    import importlib
    target, args = argv[0], argv[1:]
    mod_name, _, func_name = target.partition(":")
    sys.argv = [mod_name] + args
    try:
        rv = getattr(importlib.import_module(mod_name), func_name)()
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    return rv if isinstance(rv, int) else 0


def net_probe_main(argv: list[str]) -> int:
    """run.py --net-probe FILE: read FILE (one of the app's own) and print this process's network
    namespace; scripts._isolation_works compares it with the app's. Works in frozen builds too."""
    with open(argv[0], "rb"):
        pass
    print(os.readlink("/proc/self/ns/net"))
    return 0


MODES = {"--worker": lambda argv: worker_main(), "--run-script": run_script_main,
         "--run-module": run_module_main, "--run-callable": run_callable_main,
         "--net-probe": net_probe_main}


def dispatch(argv: list[str]) -> int | None:
    """If argv selects a helper mode, run it and return the exit code; else None."""
    if len(argv) > 1 and argv[1] in MODES:
        return MODES[argv[1]](argv[2:])
    return None
