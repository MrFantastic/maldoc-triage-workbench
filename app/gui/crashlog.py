"""Unhandled-exception logging.

Under pythonw there is no console, so an exception in a Qt callback or a worker
thread would vanish. This writes it to a dated log file in the output folder and
tells the window, which shows it in the log panel and once in a dialog.
"""
from __future__ import annotations

import datetime as _dt
import os
import sys
import threading
import traceback

from .. import APP_NAME, __version__


def install_crash_logging(log_dir: str, window_ref: list) -> str:
    """Send unhandled exceptions (GUI thread or worker threads) to a log file and the window,
    instead of losing them: under pythonw there is no console to print to."""
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, f"mtw-{_dt.date.today().isoformat()}.log")
    try:
        fh = open(path, "a", encoding="utf-8", buffering=1)
    except OSError:
        return ""
    if sys.stderr is None:      # pythonw
        sys.stderr = fh
    if sys.stdout is None:
        sys.stdout = fh
    lock = threading.Lock()

    def hook(exc_type, exc, tb) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            return
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        with lock:
            try:
                fh.write(f"[{_dt.datetime.now().isoformat(timespec='seconds')}] {APP_NAME} {__version__}\n{text}\n")
                fh.flush()
            except (OSError, ValueError):
                pass
        win = window_ref[0] if window_ref else None
        if win is not None:
            try:
                win.internal_error.emit(text, path)   # queued to the GUI thread
            except RuntimeError:
                pass

    sys.excepthook = hook
    threading.excepthook = lambda a: hook(a.exc_type, a.exc_value, a.exc_traceback)
    return path
