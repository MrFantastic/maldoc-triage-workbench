# Maldoc Triage Workbench

[![tests](https://github.com/MrFantastic/maldoc-triage-workbench/actions/workflows/tests.yml/badge.svg)](https://github.com/MrFantastic/maldoc-triage-workbench/actions/workflows/tests.yml)
[![latest release](https://img.shields.io/github/v/release/MrFantastic/maldoc-triage-workbench)](https://github.com/MrFantastic/maldoc-triage-workbench/releases/latest)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A guided, safety-hardened desktop front-end for the REMnux maldoc tools, for
deciding whether a single PDF or Office document is malicious. It drives Didier
Stevens' pdfid, pdf-parser, oledump, zipdump and rtfdump; Decalage's oletools;
XLMMacroDeobfuscator; msoffcrypto-tool; and peepdf. You drop in a file, the app
identifies its type from its bytes, runs the read-only analyses in isolated
background processes, and collects every finding and IOC in one place, with an
explanation and next steps for each one.

> **Warning: this tool handles live malware.** Run it only inside an isolated
> analysis VM (REMnux or similar), never on a production machine. It is provided
> as-is, with no warranty (see [LICENSE](LICENSE)).

![Maldoc Triage Workbench on REMnux with a harmless test PDF: findings, the Investigate panel and pdf-parser's trigger trace](docs/screenshots/pdf-triggers.png)

<details>
<summary><b>More screenshots</b></summary>

**Report tab:** verdict, a phishing summary to paste into a ticket, and every IOC, defanged.

![Report tab with verdict, phishing summary and IOCs](docs/screenshots/report.png)

**Office:** remote template injection found in a harmless `.docx` (Parts → Relationships).

![Parts tab showing a remote attachedTemplate relationship](docs/screenshots/office-template-injection.png)

</details>

<sub>Screenshots: REMnux edition on REMnux, using the harmless files from `tests/samples/`.</sub>

### Why use it instead of running the tools yourself?

- **One place, one verdict.** Every relevant tool runs on load; findings from all of them are
  rated, correlated (e.g. standard Acrobat form scripts aren't flagged as malicious) and
  rolled into a risk verdict, with the IOCs collected and defanged.
- **It teaches the workflow.** Each finding explains what it is, when it's harmless, and the
  next steps, each with a button that does it and the equivalent command line to copy.
- **Built to be safe with hostile files.** Every parser runs in its own time- and memory-limited
  process (on Linux, without network access), nothing from the sample is executed (apart from
  XLM emulation, which you start yourself), and a tool that can't run makes the verdict
  INCOMPLETE rather than "clean". It is not a sandbox: run it in an analysis VM. See
  [Safety model](#safety-model).

**Status: beta.** Developed and tested by one person, with harmless test files, on Windows
and on REMnux (noble, October 2026 release) with REMnux's own tools. Real-world use is
still limited, so treat its verdict as triage, not a final answer, and please report
false positives and negatives (see [Contributing](#contributing)).

## Download

Get the latest version from the **[Releases page](https://github.com/MrFantastic/maldoc-triage-workbench/releases/latest)**.
No git needed; pick the file for your machine:

| Your machine | Download | Then |
|---|---|---|
| **REMnux VM** | `maldoc-triage-workbench-<version>-remnux.zip` | `unzip` it, `cd maldoc-triage-workbench`, then `./install.sh` and `./start.sh` |
| **Windows** | `maldoc-triage-workbench-<version>-standard.zip` | Extract it, open the `windows` folder, double-click `install.bat`, then `start.bat` |
| **Other Linux** (no REMnux tools) | `maldoc-triage-workbench-<version>-standard.zip` | `linux/install.sh`, then `linux/start.sh` |

The standard zip serves both Windows and Linux: the Windows scripts are in its `windows`
folder and the Linux scripts in its `linux` folder; use the one for your system.

`SHA256SUMS.txt` on the same page lists each zip's SHA-256. Check it before copying a
download into your analysis VM: `sha256sum -c SHA256SUMS.txt --ignore-missing`. Each zip
also carries signed build provenance, so you can confirm it was built by this repository's
release workflow from a specific commit:
`gh attestation verify maldoc-triage-workbench-<version>-remnux.zip --repo MrFantastic/maldoc-triage-workbench`.

Cloned the repository instead? Use the same `windows` / `linux` scripts. On REMnux,
`linux/install.sh` notices and offers to set up the REMnux edition.

## Design philosophy

The Workbench is for **one-off analysis: deciding whether a single file is
malicious**. It is not a case-triage or record-management system, so there are
no case trees, saved cases or case folders. It favors getting a trustworthy
answer about one file quickly and safely: every parser that reads the sample runs
in its own limited process, nothing from the sample is executed (apart from XLM
emulation, which you start yourself and which evaluates the macro formulas), and
when a tool can't run the verdict says INCOMPLETE instead of "clean".

## Tabs by file type

| File type | Tabs |
|---|---|
| **PDF** | pdfid · pdf-parser · peepdf (+ JS workbench) · YARA · Report · Hex |
| **OLE2** (doc/xls/ppt/msg) | Office triage · Macros · Streams · Objects & links · Metadata · YARA · Report · Hex |
| **OOXML** (docx/docm/xlsx/xlsm/xlsb/pptx…) | Office triage · Macros · Parts · Streams · Objects & links · Metadata · YARA · Report · Hex |
| **RTF** | Office triage · Objects & links (rtfobj, rtfdump) · YARA · Report · Hex |
| **MHT / Word XML / SLK** | Office triage · Macros · YARA · Report · Hex |
| **Anything else** | YARA · Report · Hex |

| Tab | Tools | What you get |
|---|---|---|
| pdfid | pdfid.py | Keyword triage, every option, plugins, disarmed copy |
| pdf-parser | pdf-parser.py | Object explorer with suspicious-name flags, references both ways, stream decoding (filters applied by pdf-parser), save / analyze stream, search presets, free-form console, trailers |
| peepdf | peepdf | JSON overview (versions, suspicious elements, CVE hits), scripted console (`info ; tree ; object 5`) |
| JS workbench | built-in | Beautify, decode `%u`/`\x`/`fromCharCode` payloads, URL extraction, analyze decoded bytes. Never executes JS |
| Office triage | oleid, mraptor | Indicator table, A/W/X verdict |
| Macros | olevba, pcodedmp, XLMMacroDeobfuscator, msoffcrypto-tool | Module browser with highlighting, analysis table, IOCs, revealed source, XLM emulation, VBA stomping and p-code, decryption |
| Parts | zipfile, zipdump.py | Every package part, external relationships (template injection), part content, analyze part as new sample |
| Streams | oledump.py, olemap, oledir | Stream list with M/O flags, raw / VBA / strings / hexdump / plugin views, analyze stream as new sample |
| Objects & links | oleobj, rtfobj, msodde, rtfdump.py | Extract embedded objects (renamed `.bin`), flag executables, DDE fields |
| Metadata | olefile (olemeta/oletimes), docProps | Author, last saved by, timestamps, tampering hints |
| YARA | yara-python, oledump.py, pdf-parser.py, rtfdump.py | Your own rules over the whole file, each ZIP part, each OLE stream and all VBA code, each decoded PDF stream and each RTF object; where each rule matched and the matched text |
| Report | built-in | Notes, verdict and recommended action, phishing summary to paste into a ticket, HTML report, IOC CSV, JSON |

### YARA

The app doesn't ship rules: point it at your own with **File → YARA rules…** (one rules
file, or a folder whose `.yar` / `.yara` files, in any sub-folder, are all used; other
files are ignored). Every sample is then scanned automatically:

- the whole file, and each part of a ZIP-based file (decompressed), in the app;
- inside the format, by Didier Stevens' tools' own YARA option, which decode first: each
  OLE stream and all VBA code together (oledump), each PDF object's decoded stream
  (pdf-parser), each RTF object (rtfdump).

Each rule that matches is a Medium finding, so the verdict is at least Suspicious. Rules
can use oledump's external variables `streamname` and `VBA`; pdf-parser doesn't define
them, so it reports such rules as not compiling. On REMnux nothing needs installing (its
Python for Didier Stevens' tools has YARA); the standard edition installs yara-python.

## Guided investigation

The app is built to teach the workflow, not just print a verdict.

- **Investigate panel.** Select any finding to see what it is, why attackers use
  it, when it's usually harmless, and numbered next steps. Each step has a **Go**
  button that does it in the GUI and the equivalent command line, with a **Copy**
  button. Double-click a finding to run its first step.
- **Triggers & actions (PDF).** Every `/OpenAction`, `/AA` event and link
  action is traced to what it does: "page obj 3 → when the page is opened →
  JavaScript in obj 5 → then Launch cmd.exe". Standard Acrobat form scripts
  (AFNumber_Format, AFSimple_Calculate…) are recognized as benign. Double-click
  a row to open the payload, decoded.
- **Clickable references.** In the PDF dictionary view, every `N 0 R` is a link.
  "Referenced by" shows who triggers an object.
- **All options (command builder) in every tool tab.** The form is generated
  from the installed tool's own `-h`, so every flag is there, with plain-English
  explanations for the common ones, a live command preview, recipes, the tool's
  manual, and output in the GUI.
- **Context-aware severity.** `/AA`, `/OpenAction` and `/AcroForm` alone are
  common in legitimate forms. They're only rated High when the PDF also contains
  JavaScript or `/Launch`.

Any stream, part, object or decoded payload can be opened as a child sample,
with its parent recorded.

## Editions

There are two packages, built from the same code:

- **Standard edition** (`…-standard.zip`), for Windows or Linux machines that don't have
  the tools: its installer downloads Didier Stevens' tools into `vendor/` and installs
  oletools, peepdf and the rest. Instructions below.
- **REMnux edition** (`…-remnux.zip`), for a REMnux VM: it uses the tools REMnux already
  has (PATH, `/usr/local/bin`), never downloads any, and ignores any `vendor/` folder.
  Python tools and libraries (Didier Stevens' scripts, oletools, msoffcrypto) run in
  REMnux's own environments for them, with REMnux's copies.
  Its own README explains the two commands it needs (`./install.sh`, `./start.sh`).

Help → Tool status shows which edition is running and where each tool was found.

## Install (standard edition)

### Windows, quick way

1. Install Python from python.org (3.12 or newer recommended; 3.10 is the minimum). On the
   first installer screen, tick **"Add python.exe to PATH"**.
2. Extract this folder somewhere permanent, e.g. `C:\Tools\maldoc-triage-workbench`.
3. Open the **`windows`** folder and double-click **`install.bat`** (one time, needs internet
   access to github.com and pypi.org). It creates a private Python environment (`.venv`) in
   the app folder, the same as the Linux installer.
4. Double-click **`start.bat`** (also in `windows`) to run the app. You can also drag a sample
   onto `start.bat`, or put a shortcut to it on your desktop.

### Linux, quick way

```bash
linux/install.sh     # one time: creates .venv, downloads the tools, installs the packages
linux/start.sh       # or: linux/start.sh suspicious.pdf
```

If the window doesn't open under an X11 session, install Qt's missing library:
`sudo apt install libxcb-cursor0` (Wayland desktops don't need it).

### Manual

Python 3.10 or newer (3.12+ recommended) on Windows or Linux.

```bash
pip install -r requirements.txt          # PySide6, oletools, msoffcrypto-tool
python setup_vendor.py                   # Didier Stevens' tools + plugins -> ./vendor
python run.py                            # or: python run.py suspicious.pdf
```

Optional extras:

```bash
pip install -r requirements-xlm.txt      # Excel 4.0 macro emulation
python setup_vendor.py --peepdf         # peepdf overview + console (GPLv3), skips its JS engine
pip install -r requirements-safety.txt   # pikepdf (Decrypt PDF) and defusedxml
```

**Pinned, verified tools.** `setup_vendor.py` installs Didier Stevens' tools from one
pinned DidierStevensSuite commit, and only if every file matches the SHA-256 recorded in
[`app/core/vendor_pins.py`](app/core/vendor_pins.py). Those hashes were computed when the pin
was made and cross-checked against independent copies (a git clone, GitHub's raw-file
service, and the copies REMnux ships), never from whatever happens to download at
install time. If any file differs, **nothing is installed**. The app re-checks the
hashes at startup and **Help → Tool status** shows `[verified]`, `[CHANGED]` or
`[UNVERIFIED]` per tool.

```bash
python setup_vendor.py --ref <commit> --allow-unverified   # a different commit: installed, shown as UNVERIFIED
python setup_vendor.py --update-pin <commit>               # maintainers: move the pin, then review the diff
```

Python packages are installed at the exact versions in `constraints.txt` (the versions CI tests).

- **REMnux:** use the REMnux edition instead: it uses REMnux's own tools and downloads nothing.
- **Offline:** `python setup_vendor.py --copy-from C:\path\to\DidierStevensSuite`
- **Custom locations:** set `MTW_PDFID`, `MTW_PDF_PARSER`, `MTW_OLEDUMP`, `MTW_ZIPDUMP`,
  `MTW_RTFDUMP`, or `MTW_PEEPDF` to a script path.
- **Help → Tool status** shows what was found.

If you're updating from an earlier version, re-run `python setup_vendor.py`.
[CHANGELOG.md](CHANGELOG.md) lists what changed in each version.

## Typical phishing workflow

1. Drop the attachment on the window. Triage, macro analysis, streams, parts,
   DDE and metadata run automatically.
2. Read the risk badge and the findings list. Double-click to see evidence.
3. If it's encrypted, use Macros → Decrypt (Excel's default password is tried first),
   or for a PDF, **Decrypt PDF** in the pdf-parser tab. The readable copy opens as a
   new sample and every tool re-runs on it.
4. If there are embedded objects, use Objects & links → Extract, then double-click
   one to analyze it.
5. Go to Report: add notes, then **Copy phishing summary** into the ticket. Save the
   HTML report and the IOC CSV for blocking (EDR, mail gateway, proxy).
6. To keep what you extracted, use **File → Export artifacts**: one zip encrypted
   with the password `infected`, plus a manifest of SHA-256 hashes. The app can then
   delete the loose `.bin` copies.

## Safety model

The app is built for one situation: you open a file that was made to attack whoever
looks at it. Its job is to show what's inside without running it, and to stop a file
that attacks the *parsers* from taking the app down, tying up the machine, or reaching
further than it has to. **The analysis VM is the security boundary**; the app adds
layers inside it.

### What the app protects against

- **Sample content running.** Samples are opened read-only and never rendered or
  executed; macro and JavaScript code is shown as text. The JavaScript engines peepdf
  can use (STPyV8 / PyV8) are made unimportable for every tool the app starts, so even
  where one is installed (as on some REMnux builds) no tool evaluates the sample's
  JavaScript, and peepdf console commands that run or emulate code (`js_eval`,
  `js_analyse`, `js_vars`, `sctest`) are refused. One exception, which you start
  yourself: **Emulate** in the Macros tab runs XLMMacroDeobfuscator, which interprets
  the sample's Excel 4.0 formulas in Python. It doesn't call Windows or run native code,
  but it does evaluate the sample's logic, so treat it like running the sample.
- **A file that hangs, crashes or exhausts a parser.** Every parser that reads the
  sample runs in its own process: the external tools, and also the in-app parsers
  (oletools, olefile, msoffcrypto, pdfid, zip/XML parsing, PDF decryption, the JS
  beautifier). Each has a time limit, an output cap, a 3 GB memory cap and a CPU-time
  limit; on Linux/macOS also a 1 GB limit on any file it writes and no core dumps, on
  Windows at most 32 processes and no crash dialogs. A timeout, **Stop** (status bar) or
  opening another file kills the tool *and everything it started* (Linux/macOS: its
  own session, with the launcher as subreaper; Windows: a Job Object), and drops any
  pending results so they can't land on the wrong sample. A failure is reported as
  suspicious, and a file whose analysis didn't finish can't be rated clean.
- **Archive tricks.** ZIP-based files get a structure check before Python's `zipfile`
  reads them (end records, ZIP64 records, entry and directory budgets); a package that
  fails it is never parsed. OOXML parts are read within a 512 MB total / 64 MB per-part
  budget (20,000 parts max); zip bombs and parts with DTD or entity declarations are
  flagged and not parsed.
- **Tools reaching the network.** The app itself sends nothing. On Linux every tool runs
  in its own empty network namespace (no network at all, not even localhost) where the
  system allows unprivileged user namespaces, as REMnux and Ubuntu do; Help → Tool status
  shows whether it's active. The exceptions are a tool download you start and a peepdf
  `vtcheck` you type (it sends the file's hash to VirusTotal). On Windows and macOS the
  app doesn't restrict the tools' network access.
- **Leaking the app's environment.** Tools get only an allowlist of environment
  variables (what Python needs to start, the locale, and the app's `MTW_*` settings), so
  tokens, proxy settings, `PYTHONPATH` and the like never reach them.
- **Injection through the output.** URLs and IPs are defanged in tables, findings and
  reports; text from the sample is HTML-escaped wherever it's shown, and CSV exports are
  guarded against spreadsheet formula injection. Everything written out (streams, parts,
  objects, decrypted copies, carved bytes, payloads) gets a `.bin` suffix in the output
  folder (default `~/MTW_output`). File → Export artifacts packs them into a zip
  encrypted with the password `infected` (ZipCrypto, which every unzip tool and sandbox
  reads; its job is to keep AV and double-clicks away, not secrecy).
- **Tampered tool downloads** (standard edition). Didier Stevens' tools are downloaded
  only from one pinned commit and installed only if every file matches its pinned
  SHA-256, and they are hash-checked again at startup (see Install). Release zips carry
  signed build provenance.
- Every tool reads a private copy of exactly the bytes that were loaded and hashed, so the
  results always match the hashes shown. The original is re-hashed on close, and the app
  warns if it changed. App errors
  are written to `~/MTW_output/logs/` and shown in the log panel.

### What it doesn't protect against

- **A parser exploit that gets code execution.** A file that exploits a memory-safety
  bug in a parser (for example in qpdf under pikepdf, in lxml, or in Python itself), or
  a logic bug in a Python tool, runs code as your user. The layers above contain
  resources and processes, not privileges: that code can read and write your files,
  and on Windows and macOS use the network. This is why the app belongs in a
  disposable analysis VM: REMnux or similar, a snapshot taken before you start, no
  folders shared with the host, and a host-only or disconnected network.
- **Mistakes in the tools' judgement.** The verdict is a triage aid built from the
  tools' output. "No indicators found" means the tools found none, not that the file is
  safe.
- **The host.** Nothing here protects a machine that isn't isolated. On Windows, add a
  Defender exclusion for the analysis folder only inside the analysis VM, or it will
  quarantine samples.

## When the tools are updated

The app reads several tools by parsing their printed output, so a new tool version
that changes its format must not quietly hide findings:

- **Tool versions** are shown in Help → Tool status (with where each tool was found
  and its hash status), logged at startup, and recorded in the report, the phishing
  summary and the session export, so you know which versions produced a result.
- **Nothing recognized:** if a tool ran but none of its output was in a shape the app
  knows (pdfid, pdf-parser, oledump, msodde, peepdf), the tool is treated as failed and
  the verdict says INCOMPLETE rather than "nothing found".
- **Part not recognized:** if some of the output wasn't recognized (an unknown line or
  header field, a keyword pdfid reports that the app has no rating for), an Info finding
  says so, with the tool version and the first unrecognized lines, even when other
  findings exist. The verdict notes it, and a Low verdict becomes "(UNVERIFIED)". The
  form-script downgrade is also switched off while pdf-parser's output is partial.
- Python-version notices that Didier Stevens' tools print are recognized and ignored.

If an update causes these notes, pin the previous version with
`python setup_vendor.py --ref <commit>` until the app is updated.

## Standalone build

```bash
pip install pyinstaller
python setup_vendor.py
python build.py        # -> dist/MaldocTriageWorkbench/
```

Build on each OS you need. The executable re-launches itself as the isolated
worker and to run the bundled tools, so timeouts and process isolation work
without Python installed.

## Contributing

Bug reports, false positives / negatives and pull requests are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) for how to report a result without sharing malware, the code
layout, running the tests and making a release. Security issues: [SECURITY.md](SECURITY.md).

## License

Maldoc Triage Workbench is released under the [MIT License](LICENSE).

It doesn't include any of the analysis tools: they are downloaded or found at
install time and run as separate programs, each under its own license.

| Tool | License | How the app gets it |
|---|---|---|
| Didier Stevens' pdfid, pdf-parser, oledump, zipdump, rtfdump | Public domain | Downloaded by `setup_vendor.py` (standard edition), or REMnux's copies |
| oletools | BSD-2-Clause | pip |
| msoffcrypto-tool | MIT | pip |
| XLMMacroDeobfuscator | Apache-2.0 | pip (optional) |
| peepdf-3 | GPLv3 | pip, optional, installed separately; never bundled or imported |
| PySide6 (Qt) | LGPLv3 | pip |
| pikepdf / defusedxml | MPL-2.0 / PSF | pip (optional) |
