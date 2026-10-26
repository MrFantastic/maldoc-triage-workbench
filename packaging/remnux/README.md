# Maldoc Triage Workbench (REMnux edition)

A desktop GUI for deciding whether a single PDF or Office document is malicious.
It drives the analysis tools **REMnux already has**: Didier Stevens' pdfid,
pdf-parser, oledump, zipdump and rtfdump; oletools; peepdf; XLMMacroDeobfuscator;
msoffcrypto-tool. This edition never downloads or bundles tools: REMnux keeps them
up to date (`sudo remnux upgrade`), and Help → Tool status shows the path and
version of each one the app found.

For Windows, or a Linux machine without REMnux, use the standard edition instead.

## Install

```bash
unzip maldoc-triage-workbench-*-remnux.zip
cd maldoc-triage-workbench
./install.sh        # one time: sets up the GUI's Python environment (.venv)
./start.sh          # or: ./start.sh suspicious.pdf
```

`install.sh` only installs what REMnux lacks (the GUI library PySide6, plus pikepdf
and defusedxml), so it needs internet access once, then lists which REMnux tools it
found. REMnux's default Wayland desktop needs nothing more. Under an X11 session, if the window
doesn't open, install Qt's missing library: `sudo apt install libxcb-cursor0`.

Python 3.10 or newer is required (3.12+ recommended). If REMnux's `python3` is
older, install a newer one and run `PYTHON=python3.10 ./install.sh`.

## Where the tools come from

The app looks for each tool in this order: an `MTW_*` environment variable (for
example `MTW_PDFID=/path/to/pdfid.py`), then PATH, then `/usr/local/bin`,
`/usr/bin` and `/opt/remnux-didier`. Any `vendor` folder is ignored in this edition.

Every tool and library is REMnux's own copy where REMnux has one. REMnux installs
each tool in its own Python environment under `/opt`, so the app runs each with the
interpreter REMnux gave it:

- Didier Stevens' scripts run with the Python on their `#!` line
  (`/opt/didier-stevens/bin/python3`), which has the libraries they use.
- oletools (olevba, oleid, mraptor) runs under `/opt/oletools`, msoffcrypto under
  `/opt/msoffcrypto-tool` and jsbeautifier under `/opt/peepdf-3`: the app runs its
  parsing step for those with that environment's interpreter.
- olevba, msodde, oleobj, rtfobj, peepdf and xlmdeobfuscator run as REMnux's commands.

If REMnux's copy of a library is missing or broken, `install.sh` installs one for the
app and the app uses that. Help → Tool status shows which copy and which Python each
tool uses.

## Safety

- Run it inside the REMnux VM, not on a production machine.
- Samples are opened read-only and never rendered or executed. Nothing from the
  sample runs: the JavaScript engines peepdf can use (STPyV8 / PyV8) are blocked
  for every tool the app starts, even though REMnux may have one installed.
- Every parser runs in its own process with a time limit; Stop (status bar) ends them.
- Extracted files get a `.bin` suffix; File → Export artifacts zips them with the
  password `infected`. Links and IPs are defanged everywhere.
- Nothing goes over the network, except peepdf's `vtcheck` if you type it (hash only).

Help → Safety notes and the Investigate panel explain the rest. CHANGELOG.md lists
what changed in each version.

## License

MIT (see LICENSE). The analysis tools are REMnux's own copies, each under its own license.
