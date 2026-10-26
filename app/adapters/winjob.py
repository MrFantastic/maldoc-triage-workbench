"""Windows: run each tool process in its own Job Object.

The process is created suspended, assigned to a fresh job, and only then resumed, so it
can't start a child before the job applies. The job:

  * kills every process in it when the job is closed or terminated (timeout, Stop, or the
    tool finishing while something it started is still running)
  * caps each process at MEMORY_LIMIT of committed memory (Windows has no RLIMIT_AS)
  * allows at most ACTIVE_PROCESS_LIMIT processes and no breakaway
  * suppresses the Windows Error Reporting dialog when a parser crashes

If the job can't be set up the process is killed and not run (fail closed).
Nested jobs are supported on every Windows version Python 3.10+ runs on.

This is cleanup and resource containment, not a security sandbox: the tool still runs
as the same user. The analysis VM is the security boundary.
"""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes

MEMORY_LIMIT = 3 * 1024 ** 3
ACTIVE_PROCESS_LIMIT = 32
CREATE_SUSPENDED = 0x00000004

_JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
_JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JobObjectExtendedLimitInformation = 9


class ContainmentError(OSError):
    """The process could not be put in its job; it has been killed."""


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _BASIC_LIMITS(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD)]


class _EXTENDED_LIMITS(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BASIC_LIMITS),
                ("IoInfo", _IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]


_api = None


def _load():
    global _api
    if _api is None:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        nt = ctypes.WinDLL("ntdll")
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        k32.SetInformationJobObject.restype = wintypes.BOOL
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k32.AssignProcessToJobObject.restype = wintypes.BOOL
        k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k32.TerminateJobObject.restype = wintypes.BOOL
        k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k32.TerminateProcess.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        nt.NtResumeProcess.argtypes = [wintypes.HANDLE]
        nt.NtResumeProcess.restype = ctypes.c_long
        _api = (k32, nt)
    return _api


def _fail(what: str) -> ContainmentError:
    err = ctypes.get_last_error()
    return ContainmentError(err, f"{what} failed (Windows error {err})")


def create_job(memory_limit: int = MEMORY_LIMIT, process_limit: int = ACTIVE_PROCESS_LIMIT,
               cpu_seconds: int = 0) -> int:
    """A new Job Object with the limits above (and a per-process CPU-time limit if cpu_seconds).
    Returns its handle."""
    k32, _nt = _load()
    job = k32.CreateJobObjectW(None, None)
    if not job:
        raise _fail("CreateJobObject")
    info = _EXTENDED_LIMITS()
    info.BasicLimitInformation.LimitFlags = (
        _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | _JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS | _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION)
    info.BasicLimitInformation.ActiveProcessLimit = process_limit
    info.ProcessMemoryLimit = memory_limit
    if cpu_seconds:
        info.BasicLimitInformation.LimitFlags |= _JOB_OBJECT_LIMIT_PROCESS_TIME
        info.BasicLimitInformation.PerProcessUserTimeLimit = int(cpu_seconds) * 10_000_000  # 100 ns units
    if not k32.SetInformationJobObject(job, _JobObjectExtendedLimitInformation,
                                       ctypes.byref(info), ctypes.sizeof(info)):
        exc = _fail("SetInformationJobObject")
        k32.CloseHandle(job)
        raise exc
    return job


def contain(process_handle: int, memory_limit: int = MEMORY_LIMIT, cpu_seconds: int = 0) -> int:
    """Put a process created with CREATE_SUSPENDED into a new job, then resume it.
    Returns the job handle. On any failure the process is terminated and ContainmentError raised."""
    k32, nt = _load()
    job = None
    try:
        job = create_job(memory_limit, ACTIVE_PROCESS_LIMIT, cpu_seconds)
        if not k32.AssignProcessToJobObject(job, process_handle):
            raise _fail("AssignProcessToJobObject")
        status = nt.NtResumeProcess(process_handle)
        if status != 0:
            raise ContainmentError(0, f"NtResumeProcess failed (status 0x{status & 0xFFFFFFFF:08X})")
        return job
    except Exception:
        k32.TerminateProcess(process_handle, 1)
        if job:
            k32.CloseHandle(job)
        raise


def terminate(job: int) -> None:
    """Kill every process in the job."""
    if job:
        k32, _nt = _load()
        k32.TerminateJobObject(job, 1)


def close(job: int) -> None:
    """Close the job handle; KILL_ON_JOB_CLOSE ends anything still running in it."""
    if job:
        k32, _nt = _load()
        k32.CloseHandle(job)


def available() -> bool:
    return os.name == "nt"
