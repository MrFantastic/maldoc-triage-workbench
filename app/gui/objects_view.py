"""Objects & links tab: oleobj / rtfobj extraction, msodde, rtfdump."""
from __future__ import annotations

import html

from PySide6.QtWidgets import QLabel, QMessageBox, QPushButton, QTabWidget, QVBoxLayout, QWidget

from ..adapters import isolated
from ..adapters import objects_adapter as oa
from ..core.models import Family, Severity, ToolResult
from ..core.safety import defang
from .command_builder import CommandBuilder
from .common import banner, fill, hbox, row_data, table, text_view, vbox_widget
from .context import Context


class ObjectsView(QWidget):
    """The Objects & links tab: embedded objects (oleobj or rtfobj), DDE fields and rtfdump."""
    SOURCES = ("oleobj", "rtfobj", "msodde")

    def __init__(self, ctx: Context, family: Family, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.family = family
        tool = "rtfobj" if family == Family.RTF else "oleobj"

        self.info = banner(f"<b>{tool}</b> extracts embedded objects to the output folder (each file "
                           "gets a .bin suffix). Nothing is opened or executed.")
        extract = QPushButton(f"Extract objects ({tool})")
        dde = QPushButton("Check DDE (msodde)")
        self.files = table(["Original name", "Type", "Size", "SHA256", "Saved as"], 3)
        analyze = QPushButton("Analyze as new sample")
        self.extract_raw = text_view()
        self.dde_list = table(["DDE field (defanged)"], 0)
        self.dde_raw = text_view()
        self.rtf_raw = text_view()

        files_page = vbox_widget(hbox(None, analyze), (self.files, 1))
        tabs = QTabWidget()
        tabs.addTab(files_page, "Extracted files")
        tabs.addTab(self.extract_raw, f"{tool} output")
        tabs.addTab(vbox_widget((self.dde_list, 1), QLabel("msodde output:"), (self.dde_raw, 1)), "DDE")
        if family == Family.RTF:
            rtf_btns = hbox(QPushButton("rtfdump: full structure"), QPushButton("rtfdump: objects only (-f O)"), None)
            full_btn = rtf_btns.itemAt(0).widget()
            obj_btn = rtf_btns.itemAt(1).widget()
            tabs.addTab(vbox_widget(rtf_btns, (self.rtf_raw, 1)), "rtfdump")
            full_btn.clicked.connect(lambda: self._rtfdump(False))
            obj_btn.clicked.connect(lambda: self._rtfdump(True))
        tools = ["rtfobj", "rtfdump", "msodde"] if family == Family.RTF else ["oleobj", "msodde"]
        self.builder = CommandBuilder(ctx, tools, [
            ("All fields, not just DDE", "msodde", "-a")] + ([
            ("List RTF objects", "rtfobj", ""), ("RTF structure: objects only", "rtfdump", "-f O"),
            ("Hex-decode RTF group N (edit)", "rtfdump", "-s 5 -H")] if family == Family.RTF else []))
        tabs.addTab(self.builder, "All options (command builder)")
        self.tabs = tabs

        root = QVBoxLayout(self)
        root.addLayout(hbox(self.info, extract, dde))
        root.addWidget(tabs, 1)

        extract.clicked.connect(self.extract)
        dde.clicked.connect(self.run_dde)
        analyze.clicked.connect(self.analyze_selected)
        self.files.cellDoubleClicked.connect(lambda *_: self.analyze_selected())

    def show_files(self) -> None:
        self.tabs.setCurrentIndex(0)

    def show_dde(self) -> None:
        self.tabs.setCurrentIndex(2)

    def run(self) -> None:
        """Auto-run: DDE check only (no files written until the analyst asks)."""
        self.run_dde()

    def _err(self, msg: str) -> None:
        self.ctx.log(msg)
        self.info.setText(f"<b>Failed:</b> {html.escape(isolated.tidy(msg))}")

    def _extract_err(self, msg: str) -> None:
        self._err(msg)
        self.ctx.report_failure("rtfobj" if self.family == Family.RTF else "oleobj", msg)

    def _dde_err(self, msg: str) -> None:
        self._err(msg)
        self.ctx.report_failure("msodde", msg)

    # ------------------------------------------------------------ extraction
    def extract(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        self.info.setText("Extracting…")
        self.ctx.runner.submit(oa.extract, self._on_extract, self._extract_err, sess.sample.work_path,
                               sess.sample.sha256, "RTF" if self.family == Family.RTF else "OLE",
                               self.ctx.output_dir())

    def _on_extract(self, res: ToolResult) -> None:
        self.ctx.log(res.command, command=True)
        self.extract_raw.setPlainText(res.raw_output or res.error)
        d: oa.ObjectsData = res.data
        for f in d.files:
            self.ctx.add_artifact(f.path)
        if not res.ok and not d.files:
            self.info.setText(f"<b>{d.tool} failed:</b> {html.escape(res.error[:300])}")
            self.ctx.report_failure(d.tool, res.error or f"{d.tool} failed")
            return
        rows = [[f.original_name, f.kind, f"{f.size:,}", f.sha256, f.path] for f in d.files]
        colors = [Severity.HIGH if f.dangerous else Severity.MEDIUM for f in d.files]
        fill(self.files, rows, data=d.files, colors=colors)
        if d.files:
            self.info.setText(f"<b>{len(d.files)} object(s) extracted</b> to {html.escape(d.out_dir)}. "
                              "Double-click one to analyze it as a new sample.")
            self.tabs.setTabText(0, f"Extracted files ({len(d.files)})")
        else:
            self.info.setText(f"No embedded objects found by {d.tool}.")
        self.ctx.set_findings(d.tool, res.findings)

    def analyze_selected(self) -> None:
        f = row_data(self.files)
        sess = self.ctx.session()
        if not isinstance(f, oa.Extracted) or sess is None:
            return
        if f.dangerous:
            QMessageBox.information(self, "Analyzing extracted object",
                                    f"{f.original_name} is a {f.kind}. It will be opened for static "
                                    "analysis only; it is never executed.")
        self.ctx.load_child(f.path, f"object '{f.original_name}' extracted from {sess.sample.name} "
                                    f"(SHA256 {sess.sample.sha256})")

    # ------------------------------------------------------------ DDE / rtfdump
    def run_dde(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        self.ctx.runner.submit(oa.msodde, self._on_dde, self._dde_err, sess.sample.work_path)

    def _on_dde(self, res: ToolResult) -> None:
        self.ctx.log(res.command, command=True)
        self.dde_raw.setPlainText(res.raw_output)
        if not res.ok:
            self.ctx.report_failure("msodde", res.error or "msodde failed")
            fill(self.dde_list, [[f"msodde failed: {res.error}"]])
            return
        links = res.data or []
        fill(self.dde_list, [[defang(link)] for link in links] or [["No DDE links found."]],
             colors=[Severity.HIGH] * len(links) if links else None)
        if links:
            self.tabs.setTabText(2, f"DDE ({len(links)})")
        self.ctx.set_findings("msodde", res.findings)

    def _rtfdump(self, objects_only: bool) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        self.rtf_raw.setPlainText("Running…")
        self.ctx.runner.submit(oa.rtfdump, self._on_rtfdump, self._err, sess.sample.work_path, objects_only)

    def _on_rtfdump(self, r) -> None:
        if r.returncode != 127:
            self.ctx.log(r.command, command=True)
        self.rtf_raw.setPlainText(defang(r.text))
