"""Run tool jobs off the GUI thread so a hostile or huge file can't freeze the UI.

Every job belongs to a session generation. Opening another file (or closing
this one) starts a new generation: results from older jobs are dropped and
their tool processes are killed, so one file's results can never land on
another. Stop kills the current generation's tool processes; their jobs then
fail with "Stopped by user".
"""
from __future__ import annotations

import itertools
import traceback
from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

from ..adapters import scripts


class _Signals(QObject):
    done = Signal(int, object)
    failed = Signal(int, str)


class _Job(QRunnable):
    def __init__(self, job_id: int, generation: int, fn: Callable[..., Any], args: tuple, kwargs: dict):
        super().__init__()
        self.job_id, self.generation = job_id, generation
        self.fn, self.args, self.kwargs = fn, args, kwargs
        self.signals = _Signals()

    def run(self) -> None:  # executes in a pool thread
        scripts.set_job_generation(self.generation)
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception as exc:
            self.signals.failed.emit(self.job_id, f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc()}")
        else:
            self.signals.done.emit(self.job_id, result)
        finally:
            scripts.set_job_generation(scripts.PERSISTENT)


class JobRunner(QObject):
    """submit(fn, on_done, on_fail, *args) -> job id. Callbacks run on the GUI thread,
    and only if the job still belongs to the current sample."""
    busy_changed = Signal(bool)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._pool = QThreadPool.globalInstance()
        self._ids = itertools.count(1)
        self._jobs: dict[int, tuple[_Job, Callable, Callable | None]] = {}
        self.generation = 0

    # ------------------------------------------------------------ generations
    def new_generation(self) -> int:
        """Forget the current sample: kill its tools, drop its pending results."""
        old = self.generation
        self.generation += 1
        scripts.kill_generation(lambda g: g <= old)
        return self.generation

    def stop_current(self) -> int:
        """Kill the current sample's running tools (their jobs report 'Stopped by user')."""
        current = self.generation
        return scripts.kill_generation(lambda g: g == current)

    def busy(self) -> bool:
        return any(job.generation in (self.generation, scripts.PERSISTENT) for job, _, _ in self._jobs.values())

    # ------------------------------------------------------------ submit
    def submit(self, fn: Callable[..., Any], on_done: Callable[[Any], None],
               on_fail: Callable[[str], None] | None = None, *args, **kwargs) -> int:
        """A job tied to the current sample."""
        return self._start(self.generation, fn, on_done, on_fail, args, kwargs)

    def submit_persistent(self, fn: Callable[..., Any], on_done: Callable[[Any], None],
                          on_fail: Callable[[str], None] | None = None, *args, **kwargs) -> int:
        """A job that survives loading another sample (tool download, reading tool help)."""
        return self._start(scripts.PERSISTENT, fn, on_done, on_fail, args, kwargs)

    def _start(self, generation, fn, on_done, on_fail, args, kwargs) -> int:
        job_id = next(self._ids)
        job = _Job(job_id, generation, fn, args, kwargs)
        job.signals.done.connect(self._on_done)
        job.signals.failed.connect(self._on_failed)
        self._jobs[job_id] = (job, on_done, on_fail)  # keep the signals object alive
        self._pool.start(job)
        self.busy_changed.emit(True)
        return job_id

    def _finish(self, job_id: int):
        entry = self._jobs.pop(job_id, None)
        self.busy_changed.emit(self.busy())
        if entry is None:
            return None
        job = entry[0]
        if job.generation not in (self.generation, scripts.PERSISTENT):
            return None             # result of a sample that is no longer open
        return entry

    def _on_done(self, job_id: int, result: Any) -> None:
        entry = self._finish(job_id)
        if entry:
            entry[1](result)

    def _on_failed(self, job_id: int, message: str) -> None:
        entry = self._finish(job_id)
        if entry and entry[2]:
            entry[2](message)
