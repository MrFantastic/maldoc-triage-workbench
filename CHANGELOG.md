# Changelog

All notable changes to Maldoc Triage Workbench. Versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

### Security
- **Pinned, verified tool downloads.** `setup_vendor.py` (and Help → Download / update
  tools) now fetches Didier Stevens' tools only from one pinned DidierStevensSuite commit
  and only if every file matches a SHA-256 recorded in `app/core/vendor_pins.py`. Those
  hashes were computed when the pin was made and cross-checked against a git clone,
  GitHub's raw-file service, the GitHub API and REMnux's own copies, not taken from
  whatever downloads at install time. Any mismatch or missing required tool installs
  nothing (fail closed). Previously the default was the moving `master` branch, with
  hashes recorded after download (trust on first use).
- Other revisions need `--ref <commit> --allow-unverified` and show as UNVERIFIED in
  Help → Tool status. Pinned files are checked against the pins themselves, so
  re-recording the manifest can't hide a changed tool.
- `setup_vendor.py --update-pin <commit>` (maintainers) moves the pin only if the raw
  files match the commit's tree from the GitHub API.
- `constraints.txt`: exact versions of every Python package for Python 3.9-3.13 on
  Windows and Linux; all installers and CI use it. (Linux now needs glibc 2.34+, e.g.
  Ubuntu 22.04 or newer, for the pinned GUI library.)
- Release zips carry signed build provenance (`gh attestation verify`).
- CI installs the pinned tools for real on Linux and Windows and checks the
  fail-closed paths.
- **Timeouts and Stop now end everything a tool started**, not just the tool. On
  Linux/macOS every tool starts through a small launcher (`run.py --contain`) in its
  own session; on Linux it is also a child subreaper, so a descendant that detaches
  (double fork / `setsid`) is still found and killed. On Windows every tool runs in its
  own Job Object, assigned before the process can run (it starts suspended); closing
  the job kills anything left. Previously only the direct child was killed.
- Windows now has a memory cap too: 3 GB per tool process (Job Object), plus at most
  32 processes per tool and no crash-reporting dialogs. If a tool can't be put in its
  job it isn't run (fail closed).
- **Resource limits on Linux/macOS.** The launcher also caps each tool at 3 GB of
  memory, CPU time of twice its timeout plus 30 s, and 1 GB per written file, and
  turns off core dumps. A tool that hits a limit is stopped and reported as failed.
- **ZIP packages are checked before they are opened.** `.docx`/`.xlsx`/`.pptx`
  and other ZIP files go through a structure check (`app/core/zipcheck.py`) before
  Python's `zipfile` reads them: the end-of-archive record must be consistent, ZIP64
  records must be present when used, multi-disk archives are refused, and the central
  directory may hold at most 20,000 entries and 32 MB. A package that fails is never
  parsed: it is identified by its signature only, gets a Medium "ZIP structure
  rejected before parsing" finding, and can't be rated clean (the Parts, preview and
  metadata views say why instead of reading it).

### Changed
- **Python 3.10 or newer is now required** (3.12+ still recommended). Python 3.9 reached
  end of life in October 2025, gets no security fixes, and current CI runners no longer
  provide it. REMnux (Python 3.12) and every supported Windows Python are unaffected;
  the installers say so if an older Python is found.

## 1.4.2 (2026-10-25)

### Added
- README screenshots, badges and a "Why use it" section; CONTRIBUTING.md and issue
  templates (bug report; false positive / negative, asking for a SHA-256, never a sample).
- `tests/samples/make_test_office.py`: harmless .docx / .rtf files for the Office tabs.

### Fixed
- Investigate panel: the previous finding's text could briefly paint under the new one
  (old widgets are now hidden before they're deleted).
- The pdf-parser tab "Triggers & actions" showed as "Triggers _actions" (the `&` was
  taken as a keyboard-shortcut marker).

## 1.4.1 (2026-10-25)

### Added
- Releases: each version is published on GitHub Releases with the REMnux and
  standard zips and a `SHA256SUMS.txt`, built and tested by `.github/workflows/release.yml`.
- `install.sh` in a git clone detects REMnux and offers the REMnux edition
  (`--remnux` / `--standard` to choose without the question).

### Changed
- Windows setup now matches Linux: `install.bat` creates a private `.venv`, and
  `start.bat` uses it (falling back to the Python on PATH).
- One stated Python requirement everywhere: 3.9 or newer, 3.12+ recommended.
- Report and session timestamps include the UTC offset, so shared reports are
  unambiguous.
- Ruff rules are listed explicitly in `pyproject.toml`; CI pins ruff, runs a
  lint job, and runs the unit tests on Windows as well as Linux.

### Fixed
- Tested on REMnux (noble, 2026-10 release) with its real tools; these came out of it:
  - A `.docx` with an ordinary hyperlink was rated HIGH because oleid rates any
    external relationship High. When the Parts analysis has read every external
    relationship and all are hyperlinks, oleid's finding is now lowered to Low
    (remote templates, frames, OLE objects and sub-documents keep it High).
  - msodde lists every field in an RTF; a HYPERLINK field was reported as a High
    "DDE field". It is now a Low "Hyperlink field"; DDE/DDEAUTO stay High.
  - mraptor was run on RTF files (which cannot contain macros) and reported an error.
  - Tool status showed no version for peepdf and XLMMacroDeobfuscator on REMnux,
    which installs them in their own environments; their launcher's Python is asked.
  - The repository-only tests (`package.py`, `pyproject.toml`) failed when run from
    a release zip; they are now skipped there.
- On Windows, analysis scripts on PATH (such as `pdf-parser.py`) were not found,
  because `shutil.which` only matches PATHEXT extensions and `.py` is not one.
- `install.bat` had Unix line endings, which can break `goto` in cmd.
- A stray `EDITION` file can no longer be committed by accident.

## 1.4.0 (2026-10-14)

First public release, under the MIT License.

### Added
- Two editions built from the same code: **standard** (Windows / Linux; fetches
  its own tools) and **REMnux** (uses the tools REMnux installs, never downloads
  any, and ignores any `vendor/` folder). Help → Tool status shows the edition.
- REMnux edition installer (`install.sh`) that reuses REMnux's own Python
  packages and lists which tools it found.
- Tools are also looked up in `/usr/local/bin`, `/usr/bin` and `/opt/remnux-didier`.
- `LICENSE`, `SECURITY.md`, `CHANGELOG.md`, `pyproject.toml` (metadata and ruff
  settings) and a GitHub Actions workflow that runs the unit tests on
  Python 3.9 to 3.13.

### Changed
- The version number lives in one place (`app/__init__.py`).
- Code tidy-up for release: crash logging and the tool-status table moved out
  of the main window, long lines wrapped, imports ordered, test files named
  by topic.

## 1.3 (pre-release builds)

### Added
- Tool versions in Help → Tool status, the startup log, the HTML report, the
  phishing summary and the session export.
- Unrecognized tool output is reported instead of ignored. When none of a
  tool's output is recognized, the tool counts as failed and the verdict says
  INCOMPLETE. When only part of it is, an Info finding gives the tool version
  and the first unrecognized lines, a Low verdict becomes "(UNVERIFIED)", and
  the form-script downgrade is switched off.
- pdfid plugins: their scores and messages become findings. Plugins that don't
  work with the installed pdfid are detected and shown greyed out.
- Harmless test PDF generators in `tests/samples/`.

### Fixed
- peepdf failed to start while its JavaScript engine was blocked.
- Ciphertext and placeholder strings in encrypted PDFs no longer show up as IOCs.
- Inline actions read "Inline action." instead of "Action obj None".
- `/SubmitForm` and `/GoToR` actions are reported.
- Clearer wording when a finding's severity was lowered by correlation.
- The artifacts list is kept when the same file is reopened.

## 1.2 (pre-release builds)

### Added
- Every parser that reads the sample runs in its own worker process, with a
  time limit, an output cap and (on Linux) a memory cap.
- **Stop** in the status bar ends the current file's tools.
- pdfid and pdf-parser results are correlated, so standard Acrobat form
  scripts don't raise a High finding on their own.
- Encrypted PDFs are flagged, and **Decrypt PDF** opens a readable copy as a
  new sample.
- Hex view: save or analyze a selection, and jump to data after `%%EOF`.
- File → Export artifacts: one zip encrypted with the password `infected`,
  plus a manifest of SHA-256 hashes.
- Vendored tools are hash-checked at startup (`vendor/manifest.json`).

### Security
- Decompression budgets for OOXML packages; parts with DTD or entity
  declarations are flagged and not parsed.
- The JavaScript engines peepdf can use are made unimportable for every tool
  the app starts, and peepdf console commands that run code are refused.
- Untrusted text is escaped everywhere it is shown; CSV exports are guarded
  against formula injection.
- App errors are logged to `~/MTW_output/logs/`.

### Fixed
- Results from a previous file can no longer land on the next one.
- A failed tool makes the verdict INCOMPLETE instead of "nothing found".

## 1.1 (pre-release builds)

### Added
- Investigate panel: what each finding means, why attackers use it, when it's
  harmless, and next steps with **Go** buttons and the equivalent command line.
- PDF trigger and action chains (`/OpenAction`, `/AA`, `/Next`) traced to the
  JavaScript, Launch or URI they run.
- Command builder generated from each tool's own `-h`, in every tool tab.
- Severity that depends on context, such as `/AA` and `/OpenAction` without
  JavaScript.

## 1.0 (pre-release builds)

### Added
- Desktop GUI (PySide6) with a type-aware set of tabs for PDF, OLE2, OOXML, RTF,
  MHT, Word XML and SLK files.
- pdfid, pdf-parser and peepdf tabs; Office triage (oleid, mraptor); Macros
  (olevba, XLM emulation, VBA stomping, msoffcrypto decryption); Streams
  (oledump); Parts; Objects & links (oleobj, rtfobj, msodde, rtfdump);
  Metadata; Report (HTML report, phishing summary, IOC CSV, JSON); Hex.
- `setup_vendor.py` fetches Didier Stevens' tools into `vendor/`.

