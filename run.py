#!/usr/bin/env python3
"""Launch Maldoc Triage Workbench:  python run.py [sample]

Also the entry point for the helper processes that parse hostile files
(run.py --worker / --run-script / --run-module / --run-callable).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _main() -> int:
    from app.worker import dispatch
    code = dispatch(sys.argv)          # helper modes never import Qt
    if code is not None:
        return code
    try:
        from app.gui.main_window import main
    except ImportError as exc:  # most likely PySide6 missing
        sys.stderr.write(f"Could not start the GUI: {exc}\n"
                         "Install dependencies first:  pip install -r requirements.txt\n")
        return 1
    return main()


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(_main())
