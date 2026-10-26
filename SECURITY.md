# Security policy

Maldoc Triage Workbench is built to open hostile files, so security bugs in it
matter. Please report them privately, not in a public issue.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** button on this repository's Security tab
(private vulnerability reporting). Include the version (Help → About), the OS,
the steps or a description of the file that triggers the problem, and what
happened.

Please don't attach live malware. Describe the sample, give its SHA-256, or send
a harmless file that reproduces the issue.

## In scope

Anything that breaks the app's safety model (see "Safety model" in the README):

- sample content being executed or rendered (other than XLM emulation, which the user starts)
- a tool reaching the network on Linux while Help → Tool status says it's blocked
- a crafted file escaping a parser's process, timeout, output or resource limits, or a
  process a tool started surviving a timeout, Stop, or closing the sample
- a tool seeing environment variables outside the allowlist (`app/adapters/scripts.py`)
- extracted files written without the `.bin` suffix, or outside the output folder
- untrusted text from a sample interpreted as HTML or as a spreadsheet formula
- a JavaScript engine becoming usable by any tool the app starts

Bugs in the underlying tools (pdfid, pdf-parser, oledump, oletools, peepdf, ...)
and libraries (pikepdf / qpdf, lxml, Python) belong with their own projects. A file
that gets code execution through one of them is outside what the app can prevent
(see "What it doesn't protect against" in the README), but tell us if the app makes
it easier or its limits fail to contain it.

## Supported versions

Only the latest release gets fixes.
