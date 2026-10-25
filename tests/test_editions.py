"""Standard vs REMnux edition: where tools are looked up, and what each package contains."""
import importlib.util
import os
import stat
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import edition  # noqa: E402
from app.adapters import pdfid_adapter, scripts  # noqa: E402


class _Env:
    def __init__(self, **values):
        self.values = values

    def __enter__(self):
        self.old = {k: os.environ.get(k) for k in self.values}
        os.environ.update({k: v for k, v in self.values.items() if v is not None})
        for k, v in self.values.items():
            if v is None:
                os.environ.pop(k, None)

    def __exit__(self, *exc):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class EditionTests(unittest.TestCase):
    def test_default_and_override(self):
        expected = "standard"
        if os.path.isfile(edition.EDITION_FILE):
            with open(edition.EDITION_FILE, encoding="utf-8") as fh:
                expected = fh.read().strip()
        with _Env(MTW_EDITION=None):
            self.assertEqual(edition.edition(), expected)
        with _Env(MTW_EDITION="remnux"):
            self.assertTrue(edition.is_remnux())
            self.assertFalse(scripts.vendor_enabled())
        with _Env(MTW_EDITION="bogus"):
            self.assertIn(edition.edition(), edition.EDITIONS)

    def test_remnux_edition_ignores_vendor_copies(self):
        vendor, sysbin = tempfile.mkdtemp(), tempfile.mkdtemp()
        for d in (vendor, sysbin):
            for name in ("pdf-parser.py", "pdfid.py"):
                with open(os.path.join(d, name), "w") as fh:
                    fh.write("#!/usr/bin/env python3\n")
                os.chmod(os.path.join(d, name), 0o755)
        old = scripts.VENDOR_DIR, pdfid_adapter.VENDOR_DIR
        scripts.VENDOR_DIR = pdfid_adapter.VENDOR_DIR = vendor
        try:
            path = sysbin + os.pathsep + os.environ.get("PATH", "")
            with _Env(MTW_EDITION="standard", PATH=path, MTW_PDF_PARSER=None, MTW_PDFID=None):
                self.assertTrue(scripts.locate("pdf-parser.py").startswith(os.path.realpath(vendor)))
                self.assertTrue(pdfid_adapter.locate_pdfid().startswith(os.path.realpath(vendor)))
            with _Env(MTW_EDITION="remnux", PATH=path, MTW_PDF_PARSER=None, MTW_PDFID=None):
                self.assertTrue(scripts.locate("pdf-parser.py").startswith(os.path.realpath(sysbin)))
                self.assertTrue(pdfid_adapter.locate_pdfid().startswith(os.path.realpath(sysbin)))
        finally:
            scripts.VENDOR_DIR, pdfid_adapter.VENDOR_DIR = old


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(os.path.join(ROOT, "package.py")):
            raise unittest.SkipTest("package.py is in the source repository only, not in release zips")
        spec = importlib.util.spec_from_file_location("mtw_package", os.path.join(ROOT, "package.py"))
        cls.pkg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.pkg)
        cls.out = tempfile.mkdtemp()
        cls.zips = {}
        for ed in ("standard", "remnux"):
            dest = os.path.join(cls.out, f"{ed}.zip")
            cls.pkg.build(ed, dest)
            cls.zips[ed] = zipfile.ZipFile(dest)

    def _names(self, ed):
        return {n.split("/", 1)[1] for n in self.zips[ed].namelist()}

    def _read(self, ed, name):
        return self.zips[ed].read(f"{self.pkg.TOP}/{name}").decode()

    def test_standard_package(self):
        names = self._names("standard")
        for f in ("install.bat", "start.bat", "install.sh", "start.sh", "setup_vendor.py", "run.py",
                  "requirements.txt", "app/edition.py", "vendor/.gitkeep"):
            self.assertIn(f, names)
        self.assertEqual(self._read("standard", "EDITION").strip(), "standard")
        self.assertFalse([n for n in names if n.startswith("vendor/") and n != "vendor/.gitkeep"])
        self.assertNotIn("package.py", names)
        self.assertFalse(any(n.startswith("packaging/") for n in names))

    def test_remnux_package(self):
        names = self._names("remnux")
        for f in ("install.bat", "start.bat", "setup_vendor.py", "build.py", "requirements.txt"):
            self.assertNotIn(f, names)
        self.assertFalse(any(n.startswith("vendor/") for n in names))
        for f in ("install.sh", "start.sh", "run.py", "README.md", "app/edition.py", "app/adapters/nojs/STPyV8.py"):
            self.assertIn(f, names)
        self.assertEqual(self._read("remnux", "EDITION").strip(), "remnux")
        self.assertIn("REMnux edition", self._read("remnux", "install.sh"))
        self.assertIn("REMnux edition", self._read("remnux", "README.md"))
        info = self.zips["remnux"].getinfo(f"{self.pkg.TOP}/install.sh")
        self.assertTrue((info.external_attr >> 16) & stat.S_IXUSR)

    def test_license_shipped_repo_files_not(self):
        for ed in ("standard", "remnux"):
            names = self._names(ed)
            self.assertIn("LICENSE", names)
            self.assertIn("MIT License", self._read(ed, "LICENSE"))
            self.assertIn("CHANGELOG.md", names)
            self.assertFalse(any(n.startswith(".github/") or n in (".gitignore", "pyproject.toml") for n in names))

    def test_no_encoded_script_generator_shipped(self):
        for ed in ("standard", "remnux"):
            self.assertFalse(any("encoded" in n for n in self._names(ed)))


class ProjectFileTests(unittest.TestCase):
    """pyproject.toml repeats the version and dependencies; keep them in step."""

    def setUp(self):
        try:
            import tomllib
        except ImportError:                     # Python < 3.11
            self.skipTest("tomllib needs Python 3.11+")
        if not os.path.isfile(os.path.join(ROOT, "pyproject.toml")):
            self.skipTest("pyproject.toml is in the source repository only, not in release zips")
        with open(os.path.join(ROOT, "pyproject.toml"), "rb") as fh:
            self.project = tomllib.load(fh)["project"]

    @staticmethod
    def _requirements(name):
        with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
            lines = (ln.split("#", 1)[0].strip() for ln in fh)
            return [ln for ln in lines if ln]

    def test_version_matches_app(self):
        from app import __version__
        self.assertEqual(self.project["version"], __version__)

    def test_dependencies_match_requirements(self):
        self.assertEqual(self.project["dependencies"], self._requirements("requirements.txt"))
        extras = self.project["optional-dependencies"]
        self.assertEqual(extras["safety"], self._requirements("requirements-safety.txt"))
        self.assertEqual(extras["xlm"], self._requirements("requirements-xlm.txt"))


if __name__ == "__main__":
    unittest.main()
