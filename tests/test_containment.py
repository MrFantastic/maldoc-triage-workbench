"""Process-tree cleanup: timeouts, Stop and normal exits must not leave anything a tool
started running (Linux/macOS: run.py --contain; Windows: a Job Object per tool)."""
from __future__ import annotations

import os
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.adapters import scripts  # noqa: E402
from app.contain import CONTAIN_FAILED  # noqa: E402

HELPER = textwrap.dedent('''
    import os, subprocess, sys, time
    pidfile, mode = sys.argv[1], sys.argv[2]

    def note(pid):
        with open(pidfile + ".tmp", "w") as fh:
            fh.write(str(pid))
        os.replace(pidfile + ".tmp", pidfile)

    if mode in ("grandchild", "leave"):
        g = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        note(g.pid)
        if mode == "leave":
            sys.exit(0)                     # exit at once, leaving the grandchild running
        time.sleep(60)                      # hang until killed
    elif mode == "escape":                  # POSIX: double fork + setsid, out of the process group
        if os.fork() == 0:
            os.setsid()
            if os.fork() == 0:
                note(os.getpid())
                time.sleep(60)
                os._exit(0)
            os._exit(0)
        os.wait()
        time.sleep(60)
    elif mode == "alloc":                   # try to commit 4 GB
        try:
            block = bytearray(4 * 1024 ** 3)
            print("allocated", len(block))
        except MemoryError:
            print("MemoryError")
            sys.exit(3)
''')


def alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32")
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        h = k32.OpenProcess(0x1000, False, pid)      # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        code = wintypes.DWORD()
        k32.GetExitCodeProcess(wintypes.HANDLE(h), ctypes.byref(code))
        k32.CloseHandle(wintypes.HANDLE(h))
        return code.value == 259                    # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:                                            # a zombie is already dead
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return True


def wait_for(predicate, timeout=10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.1)
    return predicate()


class ContainmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.helper = os.path.join(self.tmp.name, "helper.py")
        with open(self.helper, "w") as fh:
            fh.write(HELPER)
        self.pidfile = os.path.join(self.tmp.name, "pid")
        self.pids = []

    def tearDown(self):
        for pid in self.pids:                       # never leave a stray process behind
            if alive(pid):
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
        self.tmp.cleanup()

    def run_helper(self, mode, timeout=60):
        return scripts.run_cmd([sys.executable, self.helper, self.pidfile, mode], f"helper {mode}", timeout)

    def grandchild(self):
        self.assertTrue(wait_for(lambda: os.path.exists(self.pidfile), 10), "helper never started its child")
        with open(self.pidfile) as fh:
            pid = int(fh.read())
        self.pids.append(pid)
        return pid

    def test_timeout_kills_grandchild(self):
        r = self.run_helper("grandchild", timeout=3)
        self.assertTrue(r.timed_out)
        pid = self.grandchild()
        self.assertTrue(wait_for(lambda: not alive(pid)), f"grandchild {pid} survived the timeout")

    def test_stop_kills_grandchild(self):
        result = {}

        def job():
            scripts.set_job_generation(4242)
            result["r"] = self.run_helper("grandchild")
        t = threading.Thread(target=job)
        t.start()
        pid = self.grandchild()
        self.assertTrue(alive(pid))
        self.assertEqual(scripts.kill_generation(lambda g: g == 4242), 1)
        t.join(20)
        self.assertFalse(t.is_alive())
        self.assertTrue(result["r"].stopped)
        self.assertTrue(wait_for(lambda: not alive(pid)), f"grandchild {pid} survived Stop")

    def test_normal_exit_cleans_up_leftovers(self):
        start = time.monotonic()
        r = self.run_helper("leave")
        self.assertEqual(r.returncode, 0)
        self.assertLess(time.monotonic() - start, 20)   # didn't wait for the 60 s grandchild
        pid = self.grandchild()
        self.assertTrue(wait_for(lambda: not alive(pid)), f"leftover {pid} kept running")

    @unittest.skipUnless(sys.platform.startswith("linux"), "subreaper sweep is Linux-only")
    def test_timeout_kills_a_grandchild_that_left_the_session(self):
        r = self.run_helper("escape", timeout=3)
        self.assertTrue(r.timed_out)
        pid = self.grandchild()
        self.assertTrue(wait_for(lambda: not alive(pid)), f"escaped grandchild {pid} survived")

    def test_exit_code_stdin_and_missing_tool(self):
        r = scripts.run_cmd([sys.executable, "-c", "import sys; sys.exit(5)"], "exit5", 30)
        self.assertEqual(r.returncode, 5)
        r = scripts.run_cmd([sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read().upper())"],
                            "echo", 30, input_bytes=b"payload")
        self.assertEqual(r.stdout, b"PAYLOAD")
        r = scripts.run_cmd([os.path.join(self.tmp.name, "no-such-tool")], "missing", 30)
        self.assertEqual(r.returncode, 127)

    @unittest.skipUnless(os.name == "nt", "Windows Job Object memory cap")
    def test_windows_memory_cap(self):
        r = self.run_helper("alloc")
        self.assertNotIn(b"allocated", r.stdout)
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipUnless(os.name == "nt", "Windows Job Object")
    def test_windows_fails_closed_without_a_job(self):
        from app.adapters import winjob
        with mock.patch.object(winjob, "create_job", side_effect=winjob.ContainmentError(5, "denied")):
            r = scripts.run_cmd([sys.executable, "-c", "print('ran')"], "nojob", 30)
        self.assertEqual(r.returncode, CONTAIN_FAILED)
        self.assertIn("Not run", r.stderr)
        self.assertNotIn(b"ran", r.stdout)


if __name__ == "__main__":
    unittest.main()
