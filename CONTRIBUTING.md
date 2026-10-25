# Contributing

Thanks for helping. This tool handles live malware, so a few rules come first.

## Reporting a wrong result (false positive or negative)

Use the **False positive / negative** issue template. **Do not attach malware or post
download links to it.** Instead give:

- the file's **SHA-256** (Report tab or Sample panel), so it can be looked up on VirusTotal,
  MalwareBazaar or similar if it's already public
- what the app said (verdict, the finding titles) and what you expected
- the app version and Help → Tool status (tool versions differ between installs)

If you can, reproduce the problem with a harmless file you make yourself and attach that.

## Reporting a bug

Use the **Bug report** template, with the steps, what happened, and the error from the
log panel or `~/MTW_output/logs/`. Security problems (anything that breaks the
[safety model](README.md#safety-model)) go privately through
[SECURITY.md](SECURITY.md), not a public issue.

## Development

```
app/core/        Qt-free: router, session, correlation, safety, report (unit tested)
app/adapters/    one adapter per tool; parse output into data + findings
app/adapters/isolated.py  GUI-side calls that run a parser in a worker process
app/worker.py    the worker entry point (run.py --worker)
app/gui/         one view per tab; views talk to the window via Context
tests/           unit tests; tests/samples/ builds harmless test PDFs and Office files
packaging/       the REMnux edition's install.sh and README
vendor/          third-party scripts fetched by setup_vendor.py, unmodified (not committed)
```

```bash
python -m unittest discover -s tests     # no GUI or analysis tools needed
ruff check .                             # settings in pyproject.toml
python package.py                        # builds the standard and REMnux zips into dist/
```

The version number is in `app/__init__.py`; `pyproject.toml` repeats it, and the
tests check the two agree. Record changes in [CHANGELOG.md](CHANGELOG.md).

To release: set the new version in both files, give it a `## <version> (<date>)` section
in the changelog, commit, then push an annotated tag `v<version>`. The release workflow
runs the tests, checks the tag matches the version, builds both zips with `package.py`,
and publishes them with `SHA256SUMS.txt` and that changelog section as the release notes.

Pull requests: keep changes focused, add or update tests in `tests/`, run the tests and
`ruff check .` before pushing (CI runs both, on Linux and Windows), and add a line to the
changelog. Never commit samples, extracted files or the `vendor/` tools.
