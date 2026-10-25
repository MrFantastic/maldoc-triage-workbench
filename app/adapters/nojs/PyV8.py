"""Placeholder put first on PYTHONPATH for every tool this app runs.

Maldoc Triage Workbench never executes a sample's JavaScript. Tools such as
peepdf evaluate PDF JavaScript in V8 when PyV8 imports, so this module makes
that import fail and those tools fall back to static analysis.

It raises ModuleNotFoundError (not just ImportError) because that is what
tools check for: peepdf-3 catches only ModuleNotFoundError, exactly as if the
engine were not installed.
"""
raise ModuleNotFoundError("PyV8 is disabled by Maldoc Triage Workbench: sample JavaScript is never executed",
                          name="PyV8")
