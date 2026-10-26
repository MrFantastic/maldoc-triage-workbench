"""REMnux's own copies: installed scripts run with the Python on their #! line, and worker
tasks that need oletools / msoffcrypto / jsbeautifier run under REMnux's environment for it
(REMnux edition), falling back to the app's own copy when REMnux's doesn't work."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.adapters import isolated, scripts, toolenv  # noqa: E402

POSIX = os.name != "nt"


def _write(path: str, text: str, executable: bool = False) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    if executable:
        os.chmod(path, 0o755)
    return path


def _env(**values):
    """Patch os.environ: a value of None removes the variable."""
    patch = mock.patch.dict(os.environ)
    patch.start()
    for k, v in values.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    return patch


class _TempDir(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mtw-toolenv-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        toolenv.clear()
        self.addCleanup(toolenv.clear)

    def fake_env(self) -> str:
        """A stand-in for a REMnux tool environment: <tmp>/env/bin/python3 -> this Python."""
        interp = os.path.join(self.tmp, "env", "bin", "python3")
        os.makedirs(os.path.dirname(interp))
        os.symlink(sys.executable, interp)
        return interp


class ShebangTests(_TempDir):
    @unittest.skipUnless(POSIX, "#! lines are a POSIX feature")
    def test_absolute_python_interpreter(self):
        interp = _write(os.path.join(self.tmp, "opt", "bin", "python3"), "", executable=True)
        tool = _write(os.path.join(self.tmp, "tool.py"), f"#!{interp} -u\nprint(1)\n")
        self.assertEqual(scripts.shebang_python(tool), interp)

    def test_lines_that_name_no_usable_interpreter(self):
        sh = _write(os.path.join(self.tmp, "bin", "sh"), "", executable=True)
        for first in ("#!/usr/bin/env python3", f"#!{sh}", "#!/no/such/dir/python3", "print(1)", "#!"):
            tool = _write(os.path.join(self.tmp, "tool.py"), first + "\nprint(1)\n")
            self.assertIsNone(scripts.shebang_python(tool), first)
        self.assertIsNone(scripts.shebang_python(os.path.join(self.tmp, "missing.py")))
        self.assertIsNone(scripts.shebang_python(None))

    @unittest.skipUnless(POSIX, "#! lines are a POSIX feature")
    def test_vendored_copy_runs_with_the_app_python(self):
        interp = _write(os.path.join(self.tmp, "opt", "bin", "python3"), "", executable=True)
        vendor = os.path.join(self.tmp, "vendor")
        inside = _write(os.path.join(vendor, "pdfid.py"), f"#!{interp}\n")
        outside = _write(os.path.join(self.tmp, "installed", "pdfid.py"), f"#!{interp}\n")
        with mock.patch.object(scripts, "VENDOR_DIR", vendor):
            self.assertEqual(scripts.script_python(inside), scripts.python_exe())
            self.assertEqual(scripts.script_python(outside), interp)

    @unittest.skipUnless(POSIX, "#! lines are a POSIX feature")
    def test_installed_script_runs_with_its_own_interpreter(self):
        interp = self.fake_env()
        tool = _write(os.path.join(self.tmp, "installed", "tool.py"),
                      f"#!{interp}\nimport sys\nsys.stdout.write(sys.executable)\n")
        r = scripts.run_script(tool, [], timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.decode(), interp)


@unittest.skipUnless(POSIX, "REMnux tool environments are Linux-only")
class RemnuxEnvironmentTests(_TempDir):
    def setUp(self):
        super().setUp()
        self.interp = self.fake_env()
        bindir = os.path.join(self.tmp, "launchers")
        _write(os.path.join(bindir, "fake-tool"), f"#!{self.interp}\nprint('the tool')\n", executable=True)
        self.addCleanup(_env(MTW_EDITION="remnux", MTW_IN_WORKER=None, MTW_FAKE_PYTHON=None,
                             PATH=bindir + os.pathsep + os.environ.get("PATH", "")).stop)
        libs = dict(toolenv.LIBRARIES, fake=toolenv.Library("fake", ("json",), "", ("fake-tool",), ()))
        p1 = mock.patch.object(toolenv, "LIBRARIES", libs)
        p2 = mock.patch.dict(toolenv.TASK_LIBRARY, {"selftest.python": "fake"})
        for p in (p1, p2):
            p.start()
            self.addCleanup(p.stop)

    def test_found_from_the_launchers_interpreter(self):
        prov = toolenv.provider("fake")
        self.assertTrue(prov.available)
        self.assertEqual(prov.python, self.interp)
        self.assertEqual(prov.source, f"REMnux ({os.path.join(self.tmp, 'env')})")
        self.assertEqual(toolenv.worker_command("selftest.python"), [self.interp, scripts.RUN_PY, "--worker"])
        self.assertEqual(toolenv.worker_command("selftest.echo"), scripts.self_command("--worker"))

    def test_worker_task_runs_under_that_interpreter(self):
        self.assertEqual(isolated.call("selftest.python"), self.interp)
        with mock.patch.dict(toolenv.TASK_LIBRARY, clear=True):
            toolenv.clear()
            self.assertEqual(isolated.call("selftest.python"), sys.executable)

    def test_broken_copy_falls_back_with_a_reason(self):
        broken = toolenv.Library("fake", ("no_such_module_mtw",), "", ("fake-tool",), ())
        with mock.patch.dict(toolenv.LIBRARIES, {"fake": broken}):
            prov = toolenv.provider("fake")
        self.assertFalse(prov.external)
        self.assertFalse(prov.available)            # and the app has no copy either
        self.assertIn("didn't work", prov.note)
        self.assertIn("no_such_module_mtw", prov.note)
        self.assertEqual(toolenv.worker_command("selftest.python"), scripts.self_command("--worker"))

    def test_environment_override(self):
        other = os.path.join(self.tmp, "other", "bin", "python3")
        os.makedirs(os.path.dirname(other))
        os.symlink(sys.executable, other)
        os.environ["MTW_FAKE_PYTHON"] = other
        self.assertEqual(toolenv.provider("fake").python, other)

    def test_standard_edition_and_workers_never_look(self):
        for env in ({"MTW_EDITION": "standard"}, {"MTW_IN_WORKER": "1"}):
            toolenv.clear()
            with mock.patch.dict(os.environ, env):
                prov = toolenv.provider("fake")
            self.assertFalse(prov.external, env)
            self.assertTrue(prov.available)          # json: this app's own copy
            self.assertTrue(prov.source.startswith("this app's Python"))


class StandardEditionTests(_TempDir):
    def test_tasks_use_the_app_worker(self):
        self.addCleanup(_env(MTW_EDITION="standard").stop)
        for task in toolenv.TASK_LIBRARY:
            self.assertEqual(toolenv.worker_command(task), scripts.self_command("--worker"))


if __name__ == "__main__":
    unittest.main()
