"""Main window: load a sample, route it, and host the tool modules."""
from __future__ import annotations

import datetime as _dt
import html
import os
import sys

from PySide6.QtCore import QSettings, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (QApplication, QDockWidget, QFileDialog, QInputDialog, QLabel, QLineEdit,
                               QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QSplitter,
                               QStackedWidget, QTabWidget, QVBoxLayout, QWidget)

from .. import APP_NAME, __version__, edition
from ..adapters import isolated, pdf_crypto, pdfid_adapter, scripts, versions
from ..core import safezip, vendor_manifest
from ..core.models import Family, Finding, Severity
from ..core.router import data_after_eof
from ..core.safety import default_output_dir, safe_output_path
from ..core.session import Sample, Session
from . import tool_status
from .crashlog import install_crash_logging
from .hex_view import HexPanel
from .investigate_panel import InvestigatePanel
from .macro_view import MacroView
from .metadata_view import MetadataView
from .objects_view import ObjectsView
from .office_view import OfficeTriageView
from .parts_view import PartsView
from .pdfid_view import PdfidView
from .pdfparser_view import PdfParserView
from .peepdf_view import PeepdfView
from .report_view import ReportView
from .side_panels import FindingsPanel, SamplePanel
from .streams_view import StreamsView
from .theme import apply_font, apply_mono, apply_theme
from .workers import JobRunner

APP_VERSION = __version__          # kept for callers that read it from here

MACRO_FAMILIES = (Family.OLE, Family.OOXML, Family.OFFICE_TEXT)

SAFETY_TEXT = (
    "<p><b>This tool handles live malware.</b> It is built for one-off analysis: deciding whether a "
    "single file is malicious, not managing cases.</p>"
    "<ul>"
    "<li>Run it inside REMnux or an isolated analysis VM, not on a production workstation.</li>"
    "<li>Samples are never rendered, opened in Office/Acrobat, or executed. JavaScript and macros are "
    "shown as text only; nothing is emulated except XLM formulas, by XLMMacroDeobfuscator, on request.</li>"
    "<li>Every parser that reads the sample runs in a separate process with a time limit, so a file "
    "crafted to hang or crash a parser can't take the app down. <b>Stop</b> (status bar) ends them.</li>"
    "<li>The original file is opened read-only and re-hashed when you close it.</li>"
    "<li>Extracted, decrypted and carved files are written with a <code>.bin</code> suffix to the output "
    "folder. File → Export artifacts packs them into a zip encrypted with the password "
    "<code>infected</code>.</li>"
    "<li>URLs and IPs are defanged in findings and tables. Nothing is sent over the network, except a "
    "tool download you start, or a peepdf <code>vtcheck</code> you type (it sends the hash only).</li>"
    "<li>On Windows, Defender may quarantine samples. Use an excluded analysis folder on the VM.</li>"
    "</ul>"
)


class MainWindow(QMainWindow):
    """The main window: loading samples, the tool tabs, findings, the log and the action dispatcher."""
    internal_error = Signal(str, str)     # traceback text, log file (emitted from any thread)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.resize(1400, 880)
        self.setAcceptDrops(True)
        self.settings = QSettings()
        self.runner = JobRunner(self)
        self._error_shown = False
        self.internal_error.connect(self._show_internal_error)
        self._session: Session | None = None
        self._tool_views: dict[str, QWidget] = {}
        self._pending_parent: str = ""
        self._artifacts: list[str] = []        # files written while investigating this file and its children
        self._root_path = ""                   # the file the current investigation started from

        # ---- central --------------------------------------------------------
        self.stack = QStackedWidget()
        drop = QLabel("Drop a PDF or Office document here\n\nor use File → Open (Ctrl+O)\n\n"
                      "PDF · DOC/XLS/PPT · DOCX/DOCM/XLSX/XLSM/XLSB/PPTX · RTF · MHT · SLK")
        drop.setObjectName("DropZone")
        drop.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome = QWidget()
        wl = QVBoxLayout(welcome)
        wl.addStretch(1)
        wl.addWidget(drop, 0, Qt.AlignmentFlag.AlignCenter)
        wl.addStretch(1)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.hex_panel = HexPanel(carve=True)
        self.hex_panel.save_requested.connect(self._save_selection)
        self.hex_panel.analyze_requested.connect(self._analyze_selection)
        self.stack.addWidget(welcome)
        self.stack.addWidget(self.tabs)
        self.setCentralWidget(self.stack)

        # ---- left dock: sample + findings ---------------------------------
        self.sample_panel = SamplePanel()
        self.findings_panel = FindingsPanel()
        self.investigate = InvestigatePanel()
        left = QSplitter(Qt.Orientation.Vertical)
        left.addWidget(self.sample_panel)
        left.addWidget(self.findings_panel)
        left.addWidget(self.investigate)
        left.setStretchFactor(0, 0)
        left.setStretchFactor(1, 2)
        left.setStretchFactor(2, 3)
        left.setSizes([90, 330, 460])
        self.left_split = left
        self.left_dock = QDockWidget("Sample", self)
        self.left_dock.setObjectName("SampleDock")
        self.left_dock.setWidget(left)
        self.left_dock.setMinimumWidth(340)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self.left_dock)
        self.findings_panel.activated.connect(self._on_finding_activated)
        self.findings_panel.selected.connect(self.investigate.show_finding)
        self.investigate.action_requested.connect(self.run_action)

        # ---- bottom dock: log / CLI-equivalent commands ---------------------
        self.log_view = QPlainTextEdit(readOnly=True)
        self.log_view.setMaximumBlockCount(5000)
        apply_mono(self.log_view)
        self.log_dock = QDockWidget("Log · CLI-equivalent commands", self)
        self.log_dock.setObjectName("LogDock")
        self.log_dock.setWidget(self.log_view)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.log_dock)
        self.resizeDocks([self.log_dock], [110], Qt.Orientation.Vertical)
        self.resizeDocks([self.left_dock], [470], Qt.Orientation.Horizontal)
        self._default_state = self.saveState()

        self._build_menus()
        version = QLabel(f"{APP_NAME} <b>v{APP_VERSION}</b> · {edition.label()}  ")
        version.setObjectName("Muted")
        version.setToolTip("Help → About for details")
        self.menuBar().setCornerWidget(version, Qt.Corner.TopRightCorner)
        self.busy = QLabel("")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setToolTip("Stop the analysis tools running on this sample. A tool that never "
                                 "finishes on a file is itself a warning sign.")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_tools)
        self.statusBar().addPermanentWidget(self.busy)
        self.statusBar().addPermanentWidget(self.stop_btn)
        self.runner.busy_changed.connect(self._on_busy)
        self._update_status()
        self.log(f"{APP_NAME} {APP_VERSION} ({edition.label()}) · Python {sys.version.split()[0]}")
        self._log_tool_status()
        self._check_vendor_manifest()

        geo = self.settings.value("geometry")
        if geo is not None:
            self.restoreGeometry(geo)
        state = self.settings.value("window_state")
        if state is not None:
            self.restoreState(state)
        split = self.settings.value("left_split")
        if split is not None:
            self.left_split.restoreState(split)
        self._fit_to_screen()

    def _fit_to_screen(self) -> None:
        """Keep the window fully on its screen (saved geometry can be off-screen
        after a monitor or scaling change)."""
        screen = self.screen() or QApplication.primaryScreen()
        if screen is None:
            return
        avail = screen.availableGeometry()
        frame = self.frameGeometry()
        if avail.contains(frame):
            return
        w = min(self.width(), avail.width() - 40)
        h = min(self.height(), avail.height() - 60)
        self.resize(w, h)
        self.move(avail.x() + (avail.width() - w) // 2, avail.y() + (avail.height() - h) // 2)

    # ================================================================ Context API
    def session(self) -> Session | None:
        return self._session

    def log(self, message: str, command: bool = False) -> None:
        if command and self._session is not None:
            self._session.commands.append(message)
        ts = _dt.datetime.now().strftime("%H:%M:%S")
        prefix = "$ " if command else ""
        for i, line in enumerate(message.splitlines() or [""]):
            self.log_view.appendPlainText(f"[{ts}] {prefix}{line}" if i == 0 else f"           {line}")

    def set_findings(self, source: str, findings: list[Finding]) -> None:
        if self._session is None:
            return
        self._session.replace_findings(source, findings)
        self._refresh_status()

    def report_failure(self, source: str, error: str) -> None:
        if self._session is None:
            return
        error = isolated.tidy(error)
        self._session.mark_failed(source, error)
        self.log(f"⚠ {source} failed: {error}")
        self._refresh_status()

    def set_facts(self, source: str, facts: dict) -> None:
        if self._session is None:
            return
        self._session.set_facts(source, facts)
        self._refresh_status()

    def add_artifact(self, path: str) -> None:
        if path and os.path.isfile(path) and path not in self._artifacts:
            self._artifacts.append(path)
        if self._session is not None:
            self._session.add_artifact(path)

    def _refresh_status(self) -> None:
        s = self._session
        if s is None:
            return
        self.findings_panel.set_findings(s.findings, s.tools_run, s.tool_errors)
        self.sample_panel.update_risk(s.risk, s.incomplete)

    def output_dir(self) -> str:
        path = self.settings.value("output_dir", default_output_dir())
        os.makedirs(path, exist_ok=True)
        return path

    def show_in_hex(self, offset: int | None = None, needle: bytes | None = None) -> None:
        self.tabs.setCurrentWidget(self.hex_panel)
        if needle:
            if self.hex_panel.find_bytes(needle) == -1:
                self.log(f"Not found in raw bytes: {needle!r} (it may be inside a compressed stream)")
        elif offset is not None:
            self.hex_panel.goto(offset)

    def set_iocs(self, source: str, values: list[str]) -> None:
        if self._session is not None:
            self._session.set_iocs(source, values)

    def analyze_child_bytes(self, name: str, data: bytes, note: str) -> None:
        if not data:
            QMessageBox.information(self, "Nothing to analyze", "No data was extracted.")
            return
        dest = safe_output_path(self.output_dir(), name)
        with open(dest, "wb") as fh:
            fh.write(data)
        self.add_artifact(dest)
        self.log(f"Wrote {len(data):,} bytes to {dest}")
        self.load_child(dest, note)

    def send_to_js(self, code: str, origin: str) -> None:
        view = self._tool_views.get("peepdf")
        if isinstance(view, PeepdfView):
            self.tabs.setCurrentWidget(view)
            view.load_js(code, origin)

    # ================================================================ menus
    def _build_menus(self) -> None:
        mb = self.menuBar()
        m_file = mb.addMenu("&File")
        self._add(m_file, "&Open sample…", self.open_dialog, QKeySequence.StandardKey.Open)
        self._add(m_file, "&Close sample", self.close_sample, QKeySequence.StandardKey.Close)
        m_file.addSeparator()
        self._add(m_file, "&Export session (JSON)…", self.export_session, "Ctrl+E")
        self._add(m_file, "Export &artifacts (zip, password 'infected')…", self.export_artifacts)
        self._add(m_file, "Set &output folder…", self.choose_output_dir)
        m_file.addSeparator()
        self._add(m_file, "&Quit", self.close, QKeySequence.StandardKey.Quit)

        m_view = mb.addMenu("&View")
        m_view.addAction(self.left_dock.toggleViewAction())
        m_view.addAction(self.log_dock.toggleViewAction())
        m_view.addSeparator()
        self.dark_action = self._add(m_view, "&Dark theme", self._toggle_theme)
        self.dark_action.setCheckable(True)
        self.dark_action.setChecked(self.settings.value("dark", True, type=bool))
        m_view.addSeparator()
        self._add(m_view, "&Larger text", lambda: self._font_step(+1), QKeySequence.StandardKey.ZoomIn)
        self._add(m_view, "&Smaller text", lambda: self._font_step(-1), QKeySequence.StandardKey.ZoomOut)
        self._add(m_view, "Reset text size", lambda: self._font_step(0), "Ctrl+0")
        m_view.addSeparator()
        self._add(m_view, "Show &hashes", lambda: self.sample_panel.set_hashes_visible(
            not self.sample_panel.hash_box.isVisible()), "Ctrl+H")
        self._add(m_view, "&Reset layout", self.reset_layout)

        m_help = mb.addMenu("&Help")
        self._add(m_help, "&Safety notes", self.show_safety)
        self._add(m_help, "&Tool status", self.show_tool_status)
        if not edition.is_remnux():     # the REMnux edition uses the VM's tools; REMnux updates them
            self._add(m_help, "&Download / update tools…", lambda: self.offer_tool_download(force=True))
        self._add(m_help, "&About", lambda: QMessageBox.about(
            self, APP_NAME, f"<b>{APP_NAME}</b> {APP_VERSION} ({edition.label()})<br><br>"
            "GUI front-end for Didier Stevens' pdfid, pdf-parser, oledump, zipdump and rtfdump, "
            "Decalage's oletools, XLMMacroDeobfuscator, msoffcrypto-tool and peepdf.<br>"
            "The underlying tools are used unmodified."))

    def _add(self, menu, text, slot, shortcut=None) -> QAction:
        act = QAction(text, self)
        if shortcut is not None:
            act.setShortcut(QKeySequence(shortcut))
        act.triggered.connect(slot)
        menu.addAction(act)
        return act

    def _font_step(self, step: int) -> None:
        delta = 0 if step == 0 else int(self.settings.value("font_delta", 0, type=int)) + step
        delta = max(-4, min(8, delta))
        self.settings.setValue("font_delta", delta)
        apply_font(QApplication.instance(), delta)
        self.log(f"Text size {'reset' if delta == 0 else f'{delta:+d} pt'}")

    def reset_layout(self) -> None:
        self.restoreState(self._default_state)
        self.left_split.setSizes([90, 330, 460])
        self.resizeDocks([self.log_dock], [110], Qt.Orientation.Vertical)
        self.resizeDocks([self.left_dock], [470], Qt.Orientation.Horizontal)

    def _toggle_theme(self, checked: bool) -> None:
        self.settings.setValue("dark", checked)
        apply_theme(QApplication.instance(), dark=checked)

    def _update_status(self) -> None:
        self.statusBar().showMessage(f"Output folder: {self.output_dir()}")

    # ================================================================ loading
    def dragEnterEvent(self, e) -> None:
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e) -> None:
        urls = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        if urls:
            self.load(urls[0])

    def open_dialog(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        path, _ = QFileDialog.getOpenFileName(self, "Open sample", start, "All files (*)")
        if path:
            self.settings.setValue("last_dir", os.path.dirname(path))
            self.load(path)

    def load_child(self, path: str, note: str) -> None:
        """Open a derived file (decrypted copy, extracted object, carved bytes) as a new sample."""
        self.add_artifact(path)
        self.load(path, parent_note=note)

    def load(self, path: str, parent_note: str = "") -> None:
        if self._session is not None:
            self.close_sample()
        # A new generation: results still coming from the previous file are dropped and its
        # tool processes killed, so they can never be attributed to this one.
        self.runner.new_generation()
        if not parent_note and os.path.abspath(path) != self._root_path:
            self._artifacts = []                # a different file: a new investigation
            self._root_path = os.path.abspath(path)
        self._pending_parent = parent_note
        self.log(f"Loading {path}")
        self.runner.submit(Sample.load, self._on_loaded,
                           lambda msg: self._load_failed(path, msg), path)

    def _on_busy(self, busy: bool) -> None:
        self.busy.setText("Working…" if busy else "")
        self.stop_btn.setEnabled(busy)

    def stop_tools(self) -> None:
        n = self.runner.stop_current()
        self.log(f"Stopped {n} running tool process(es)." if n else
                 "Nothing to stop (the remaining work is in-app and finishes on its own).")

    def _load_failed(self, path: str, message: str) -> None:
        self.log(message)
        QMessageBox.critical(self, "Could not load sample", f"{path}\n\n{message.splitlines()[0]}")

    def _on_loaded(self, sample: Sample) -> None:
        self._session = Session(sample, parent_note=self._pending_parent)
        self._session.tool_versions = versions.all_versions()
        if self._pending_parent:
            self._session.findings.append(Finding(
                "session", Severity.INFO, "Derived sample", self._pending_parent))
            self._pending_parent = ""
        self.setWindowTitle(f"{sample.name} — {APP_NAME} {APP_VERSION}")
        self.sample_panel.show_session(self._session)
        self.findings_panel.set_findings(self._session.findings)
        self.hex_panel.set_data(sample.data)
        self.log(f"Loaded {sample.name}: {sample.size:,} bytes, {sample.family.value} "
                 f"({sample.route.subtype}), SHA256 {sample.sha256}")
        self._build_tabs(sample.family)
        self.stack.setCurrentIndex(1)

    def _add_view(self, view: QWidget, title: str, keys: tuple[str, ...], auto: bool) -> QWidget:
        self.tabs.addTab(view, title.replace("&", "&&"))
        for k in keys:
            self._tool_views[k] = view
        if auto:
            self._auto.append(view)
        return view

    def _build_tabs(self, family: Family) -> None:
        self.tabs.clear()
        self._tool_views.clear()
        self._auto: list[QWidget] = []
        first: QWidget | None = None
        if family == Family.PDF:
            first = self._add_view(PdfidView(self), "pdfid", ("pdfid",), True)
            self._add_view(PdfParserView(self), "pdf-parser", ("pdf-parser",), True)
            self._add_view(PeepdfView(self), "peepdf", ("peepdf", "js-workbench"), False)
        elif family in (Family.OLE, Family.OOXML, Family.RTF, Family.OFFICE_TEXT):
            first = self._add_view(OfficeTriageView(self), "Office triage", OfficeTriageView.SOURCES, True)
            if family in MACRO_FAMILIES:
                self._add_view(MacroView(self), "Macros", MacroView.SOURCES + ("macros",), True)
            if family == Family.OOXML:
                self._add_view(PartsView(self), "Parts", ("parts",), True)
            if family in (Family.OLE, Family.OOXML):
                self._add_view(StreamsView(self), "Streams", ("oledump", "streams"), True)
            if family in (Family.OLE, Family.OOXML, Family.RTF):
                self._add_view(ObjectsView(self, family), "Objects & links",
                               ObjectsView.SOURCES + ("objects",), True)
            if family in (Family.OLE, Family.OOXML):
                self._add_view(MetadataView(self, family), "Metadata", ("metadata",), True)
        self._add_view(ReportView(self), "Report", ("report",), False)
        self.tabs.addTab(self.hex_panel, "Hex")
        if first is not None:
            self.tabs.setCurrentWidget(first)
        else:
            self.tabs.setCurrentWidget(self.hex_panel)
            self.log("No triage tool applies to this file type; showing raw bytes and the report.")
        for view in self._auto:   # all cheap, read-only analyses run on load in the background
            view.run()

    def close_sample(self) -> None:
        if self._session is None:
            return
        s = self._session.sample
        if not s.verify_unchanged():
            QMessageBox.warning(self, "Sample changed on disk",
                                f"{s.path}\n\nThe file's SHA256 no longer matches what was loaded. "
                                "Something modified or removed the original during analysis.")
            self.log(f"WARNING: {s.name} changed on disk during analysis")
        self._session = None
        self.runner.new_generation()
        # Detach the shared hex panel before clearing so it isn't deleted with the tabs
        idx = self.tabs.indexOf(self.hex_panel)
        if idx != -1:
            self.tabs.removeTab(idx)
        old = [self.tabs.widget(i) for i in range(self.tabs.count())]
        self.tabs.clear()
        for w in old:
            w.deleteLater()
        self._tool_views.clear()
        self.hex_panel.set_data(b"")
        self.sample_panel.clear()
        self.findings_panel.set_findings([])
        self.stack.setCurrentIndex(0)
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.log(f"Closed {s.name}")

    # ================================================================ actions
    def _on_finding_activated(self, f: Finding | None) -> None:
        """Double-click: run the first investigation step for this finding."""
        if f is None:
            return
        self.investigate.show_finding(f)
        action = self.investigate.first_action(f)
        if action:
            self.run_action(action)
            return
        tab = f.ref.get("tab")
        if "object" in f.ref and "pdf-parser" in self._tool_views:
            self.run_action(f"pdf.object:{f.ref['object']}")
        elif tab and tab in self._tool_views:
            self.tabs.setCurrentWidget(self._tool_views[tab])
        elif "offset" in f.ref:
            self.show_in_hex(offset=int(f.ref["offset"]))

    def run_action(self, action: str) -> None:
        """Dispatch an investigation step, e.g. 'pdf.search:/AA', 'macros.tab:pcode'."""
        name, _, arg = action.partition(":")
        v = self._tool_views
        self.log(f"Investigate → {action}")

        def need(key: str):
            view = v.get(key)
            if view is None:
                self.log(f"(that step needs the {key} tab, which doesn't apply to this file type or isn't installed)")
                return None
            self.tabs.setCurrentWidget(view)
            return view

        if name == "pdf.triggers" and (view := need("pdf-parser")):
            view.show_triggers()
        elif name == "pdf.search" and (view := need("pdf-parser")):
            view.search_and_show(arg)
        elif name == "pdf.object" and (view := need("pdf-parser")):
            if arg.isdigit():
                view.open_and_decode(int(arg))
        elif name == "pdf.builder" and (view := need("pdf-parser")):
            view.open_builder(arg)
        elif name == "pdfid.builder" and (view := need("pdfid")):
            view.open_builder(arg)
        elif name == "pdfid.disarm" and (view := need("pdfid")):
            view.disarm()
        elif name == "pdf.js" and (view := need("pdf-parser")):
            if arg.isdigit():
                view.send_object_js(int(arg))
        elif name == "js.workbench":
            parser = v.get("pdf-parser")
            oid = parser.current_object_id() if parser is not None else None
            if parser is not None and oid is not None:
                parser.send_object_js(oid)      # send the code of the object being inspected
            elif (view := need("peepdf")):
                view.tabs.setCurrentWidget(view.workbench)
                view.js_origin.setText("Select an object with JavaScript in pdf-parser (or a Triggers row) "
                                       "and use <b>Send to JS workbench</b>, or paste code here.")
        elif name == "peepdf.run" and (view := need("peepdf")):
            view.show_overview()
        elif name == "peepdf.console" and (view := need("peepdf")):
            view.console_command(arg)
        elif name == "macros.view" and (view := need("macros")):
            view.set_view(arg)
        elif name == "macros.tab" and (view := need("macros")):
            view.show_lower(arg)
        elif name == "macros.keyword" and (view := need("macros")):
            view.focus_keyword(arg)
        elif name == "macros.emulate" and (view := need("macros")):
            view.show_lower("xlm")
            if view.xlm_btn.isEnabled():
                view.emulate_xlm()
            else:
                self.log("XLM emulation isn't available: install XLMMacroDeobfuscator "
                         f"({edition.hint('xlm')}), or no XLM was detected.")
        elif name == "macros.decrypt" and (view := need("macros")):
            view.decrypt()
        elif name == "pdf.decrypt":
            self.decrypt_pdf()
        elif name == "streams.builder" and (view := need("streams")):
            view.open_builder(arg)
        elif name == "streams.list" and (view := need("streams")):
            view.show_streams()
        elif name == "parts.rels" and (view := need("parts")):
            view.show_rels()
        elif name == "parts.select" and (view := need("parts")):
            view.select_part(arg)
        elif name == "objects.extract" and (view := need("objects")):
            view.show_files()
            view.extract()
        elif name == "objects.dde" and (view := need("objects")):
            view.show_dde()
        elif name == "objects.list" and (view := need("objects")):
            view.show_files()
        elif name == "report":
            need("report")
        elif name == "tool.status":
            self.show_tool_status()
        elif name == "tab":
            need(arg)
        elif name == "hex":
            sess = self._session
            if arg == "end" and sess is not None:
                self.show_in_hex(offset=max(0, sess.sample.size - 256))
            elif arg == "after_eof" and sess is not None:
                self.select_after_eof()
            elif arg.isdigit():
                self.show_in_hex(offset=int(arg))
        else:
            self.log(f"Unknown investigation step: {action}")

    # ================================================================ carving / decrypting
    def select_after_eof(self) -> None:
        sess = self._session
        if sess is None:
            return
        span = data_after_eof(sess.sample.data)
        self.tabs.setCurrentWidget(self.hex_panel)
        if span is None:
            self.log("Nothing follows the last %%EOF except line endings or padding.")
            self.show_in_hex(offset=max(0, sess.sample.size - 256))
            return
        start, length = span
        self.hex_panel.goto(start, length)
        self.log(f"Selected {length:,} byte(s) after the last %%EOF (offset 0x{start:X}). Use "
                 "'Analyze selection as new sample' to identify them, or 'Save selection…'.")

    def _carve_name(self, offset: int) -> str:
        base = os.path.splitext(self._session.sample.name)[0] if self._session else "sample"
        return f"{base}_carved_0x{offset:X}"

    def _save_selection(self, offset: int, data: bytes) -> None:
        if self._session is None:
            return
        default = safe_output_path(self.output_dir(), self._carve_name(offset))
        path, _ = QFileDialog.getSaveFileName(self, "Save selected bytes", default, "Binary (*.bin)")
        if not path:
            return
        with open(path, "wb") as fh:
            fh.write(data)
        self.add_artifact(path)
        self.log(f"Saved {len(data):,} selected byte(s) from offset 0x{offset:X} to {path}")

    def _analyze_selection(self, offset: int, data: bytes) -> None:
        sess = self._session
        if sess is None:
            return
        self.analyze_child_bytes(self._carve_name(offset), bytes(data),
                                 f"{len(data):,} bytes carved at offset 0x{offset:X} from {sess.sample.name} "
                                 f"(SHA256 {sess.sample.sha256})")

    def decrypt_pdf(self, password: str = "") -> None:
        sess = self._session
        if sess is None or sess.sample.family != Family.PDF:
            self.log("Decrypt PDF needs a PDF to be open.")
            return
        if pdf_crypto.available() is None:
            QMessageBox.information(self, "Decrypt PDF", "Decrypting a PDF needs pikepdf or pypdf:\n\n"
                                    "    pip install pikepdf\n\nthen restart the app.")
            return
        self.log("Decrypting the PDF in a worker process…")
        self.runner.submit(isolated.pdf_decrypt, lambda r: self._on_pdf_decrypted(r, sess),
                           self._on_pdf_decrypt_failed, sess.sample.path, self.output_dir(), password)

    def _on_pdf_decrypted(self, result, sess: Session) -> None:
        dest, lib = result
        self.log(f"{lib}: decrypted {sess.sample.name} → {dest}", command=True)
        self.load_child(dest, f"decrypted (with {lib}) from {sess.sample.name} (SHA256 {sess.sample.sha256})")

    def _on_pdf_decrypt_failed(self, message: str) -> None:
        first = (message.splitlines() or [""])[0]
        if first.startswith("PdfPasswordRequired"):
            pw, ok = QInputDialog.getText(self, "PDF password",
                                          "This PDF needs a password to open (the empty password failed).\n"
                                          "Password, e.g. from the email that delivered it:",
                                          QLineEdit.EchoMode.Password)
            if ok and pw:
                self.decrypt_pdf(pw)
            else:
                self.log("PDF decryption cancelled: a password is required.")
            return
        self.log(message)
        QMessageBox.warning(self, "Decrypt PDF", isolated.tidy(message)[:400])

    def export_artifacts(self) -> None:
        paths = [p for p in self._artifacts if os.path.isfile(p)]
        if not paths:
            QMessageBox.information(self, "Export artifacts", "No files have been extracted, decrypted or "
                                    "carved while investigating this file.")
            return
        sess = self._session
        base = os.path.splitext(sess.sample.name)[0] if sess else "artifacts"
        default = os.path.join(self.output_dir(), f"{base}_artifacts.zip")
        path, _ = QFileDialog.getSaveFileName(self, "Export artifacts (password: infected)", default,
                                              "Zip (*.zip)")
        if not path:
            return
        import hashlib
        lines = [f"Artifacts exported by {APP_NAME} {APP_VERSION}", "Zip password: infected", ""]
        if sess is not None:
            lines.append(f"Open sample: {sess.sample.name}  SHA256 {sess.sample.sha256}")
            if sess.parent_note:
                lines.append(f"  derived: {sess.parent_note}")
            lines.append("")
        for p in paths:
            with open(p, "rb") as fh:
                lines.append(f"{hashlib.sha256(fh.read()).hexdigest()}  {os.path.basename(p)}")
        manifest = "\n".join(lines) + "\n"
        self.log(f"Writing {len(paths)} artifact(s) to {path} (password: infected)…")
        self.runner.submit_persistent(safezip.write_files, lambda _n: self._on_artifacts_exported(path, paths),
                                      lambda m: QMessageBox.warning(self, "Export failed", m.splitlines()[0]),
                                      path, paths, manifest)

    def _on_artifacts_exported(self, zip_path: str, paths: list[str]) -> None:
        self.log(f"Exported {len(paths)} artifact(s) to {zip_path}")
        answer = QMessageBox.question(
            self, "Artifacts exported",
            f"{len(paths)} file(s) are now in\n{zip_path}\n(password: infected)\n\n"
            "Delete the loose .bin copies from the output folder? Files still open as a sample are kept.")
        if answer != QMessageBox.StandardButton.Yes:
            return
        keep = self._session.sample.path if self._session else ""
        removed = 0
        for p in paths:
            if os.path.abspath(p) == os.path.abspath(keep):
                continue
            try:
                os.remove(p)
                removed += 1
            except OSError as exc:
                self.log(f"Could not delete {p}: {exc}")
        self._artifacts = [p for p in self._artifacts if os.path.isfile(p)]
        self.log(f"Deleted {removed} loose artifact file(s).")

    def export_session(self) -> None:
        if self._session is None:
            QMessageBox.information(self, "Export", "Open a sample first.")
            return
        s = self._session.sample
        default = os.path.join(self.output_dir(), f"{s.sha256[:12]}_{os.path.splitext(s.name)[0]}.json")
        path, _ = QFileDialog.getSaveFileName(self, "Export session", default, "JSON (*.json)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self._session.export_json())
        self.log(f"Session exported to {path}")

    def choose_output_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Output folder", self.output_dir())
        if path:
            self.settings.setValue("output_dir", path)
            self._update_status()

    def show_safety(self) -> None:
        QMessageBox.information(self, "Safety notes", SAFETY_TEXT)

    def missing_core_tools(self) -> list[str]:
        missing = []
        if not pdfid_adapter.locate_pdfid():
            missing.append("pdfid.py")
        for name in ("pdf-parser.py", "oledump.py"):
            if not scripts.locate(name):
                missing.append(name)
        return missing

    def offer_tool_download(self, force: bool = False) -> None:
        """If Didier Stevens' tools are missing, offer to fetch them with setup_vendor.py."""
        missing = self.missing_core_tools()
        if not missing and not force:
            return
        if edition.is_remnux():
            if missing:
                self.log("⚠ Not found on this VM: " + ", ".join(missing))
                QMessageBox.warning(
                    self, "Analysis tools not found",
                    "These tools weren't found on this VM:\n\n  " + "\n  ".join(missing) + "\n\n"
                    "The REMnux edition uses the tools REMnux installs (on PATH or in /usr/local/bin) and "
                    "never downloads its own. Check with  which pdfid.py  in a terminal, or update REMnux "
                    "with  sudo remnux upgrade. On a machine that isn't REMnux, use the standard edition.")
            return
        setup = os.path.join(scripts.APP_ROOT, "setup_vendor.py")
        py = scripts.python_exe()
        if not os.path.isfile(setup) or py is None:
            if missing:
                QMessageBox.warning(self, "Analysis tools missing",
                                    "Missing: " + ", ".join(missing) + "\n\nCopy a working 'vendor' folder "
                                    "into this app's folder, or run setup_vendor.py from the source package.")
            return
        text = ("These analysis tools are missing, so files can't be analyzed yet:\n\n  "
                + "\n  ".join(missing) + "\n\n" if missing else
                "Re-download Didier Stevens' tools (pdfid, pdf-parser, oledump, zipdump, rtfdump and plugins) "
                "into the vendor folder?\n\n")
        text += "Download them now from github.com/DidierStevens? (Needs internet access.)"
        if QMessageBox.question(self, "Analysis tools", text) != QMessageBox.StandardButton.Yes:
            if missing:
                self.log("⚠ Analysis tools missing: " + ", ".join(missing) + ". Help → Download / update tools.")
            return
        self.log(f"Downloading tools: {py} {setup}")
        self.runner.submit_persistent(scripts.run_cmd, self._on_tools_downloaded,
                                      lambda m: QMessageBox.warning(self, "Download failed", m.splitlines()[0]),
                                      [py, setup], "setup_vendor.py", 300)

    def _on_tools_downloaded(self, r) -> None:
        self.log(r.text)
        pdfid_adapter.clear_cache()
        versions.clear()
        self._check_vendor_manifest()
        changed = [ln.strip()[2:] for ln in r.text.splitlines() if ln.strip().startswith("! ") and "hash changed" in ln]
        if changed:
            QMessageBox.warning(self, "Tool scripts changed upstream",
                                "These tools differ from the copies fetched last time:\n\n" + "\n".join(changed[:12])
                                + "\n\nThat's normal after an upstream release, but review the change (or pin a "
                                "known commit with setup_vendor.py --ref) before relying on the results.")
        still = self.missing_core_tools()
        if still:
            QMessageBox.warning(self, "Some tools are still missing",
                                "Still missing: " + ", ".join(still) + "\n\nSee the log for details. If "
                                "github.com is blocked, copy a working 'vendor' folder from another machine.")
            return
        msg = "Tools installed."
        if self._session is not None:
            msg += " Reloading the current file so every tool runs."
            self.load(self._session.sample.path, parent_note=self._session.parent_note)
        QMessageBox.information(self, "Analysis tools", msg)
        self._log_tool_status()

    def _tool_status_lines(self) -> list[str]:
        return tool_status.status_lines()

    def _check_vendor_manifest(self) -> None:
        if not scripts.vendor_enabled():        # REMnux edition: REMnux owns its tools
            return
        status, problems = vendor_manifest.verify(scripts.VENDOR_DIR)
        if status == "MODIFIED":
            self.log("⚠ Vendored tool scripts changed since they were fetched: " + "; ".join(problems))
            self.statusBar().showMessage("⚠ A vendored tool changed since it was fetched: see Help → Tool status",
                                         0)
            QTimer.singleShot(0, lambda: QMessageBox.warning(
                self, "Tool scripts changed",
                "These tool scripts no longer match the hashes recorded when they were fetched:\n\n"
                + "\n".join(problems[:12]) + "\n\nThey run against every sample. If you didn't change them, "
                "re-fetch them (Help → Download / update tools) before analyzing anything."))

    def _log_tool_status(self) -> None:
        for line in self._tool_status_lines():
            self.log(line)

    def show_tool_status(self) -> None:
        QMessageBox.information(self, "Tool status",
                                "<pre>" + html.escape("\n".join(self._tool_status_lines())) + "</pre>")

    def _show_internal_error(self, text: str, log_path: str) -> None:
        lines = text.strip().splitlines()
        self.log("⚠ Internal error (a bug in this app, not a finding): " + (lines[-1] if lines else "unknown"))
        self.log(text.strip())
        self.statusBar().showMessage(f"⚠ Internal error, details in {log_path}", 15000)
        if not self._error_shown:
            self._error_shown = True
            QMessageBox.warning(self, "Internal error",
                                "Something in the app failed (this is a bug, not a property of the sample):\n\n"
                                f"{lines[-1] if lines else ''}\n\nThe full traceback is in the log panel and in\n"
                                f"{log_path}\n\nResults shown for the current step may be incomplete.")

    def closeEvent(self, e) -> None:
        self.close_sample()
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("window_state", self.saveState())
        self.settings.setValue("left_split", self.left_split.saveState())
        super().closeEvent(e)


def main(argv: list[str] | None = None) -> int:
    """Start the GUI; argv[1], if given, is a sample to open."""
    argv = sys.argv if argv is None else argv
    app = QApplication(argv)
    app.setOrganizationName("MTW")
    app.setApplicationName(APP_NAME)
    settings = QSettings()
    window_ref: list = []
    install_crash_logging(os.path.join(settings.value("output_dir", default_output_dir()), "logs"), window_ref)
    apply_theme(app, dark=settings.value("dark", True, type=bool))
    apply_font(app, int(settings.value("font_delta", 0, type=int)))
    win = MainWindow()
    window_ref.append(win)
    win.show()
    if not settings.value("safety_ack", False, type=bool):
        win.show_safety()
        settings.setValue("safety_ack", True)
    QTimer.singleShot(300, win.offer_tool_download)
    files = [a for a in argv[1:] if os.path.isfile(a)]
    if files:
        win.load(files[0])
    return app.exec()
