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

- sample content being executed, rendered, or reaching the network
- a crafted file escaping a parser's isolated process, timeout or output limit
- extracted files written without the `.bin` suffix, or outside the output folder
- untrusted text from a sample interpreted as HTML or as a spreadsheet formula
- a JavaScript engine becoming usable by any tool the app starts

Bugs in the underlying tools (pdfid, pdf-parser, oledump, oletools, peepdf, ...)
belong with their own projects.

## Supported versions

Only the latest release gets fixes.
