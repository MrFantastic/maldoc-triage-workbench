"""pdfid module: keyword triage dashboard with every pdfid option exposed."""
from __future__ import annotations

import csv
import html
import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (QCheckBox, QDoubleSpinBox, QFileDialog, QGroupBox, QHBoxLayout,
                               QHeaderView, QLabel, QListWidget, QListWidgetItem, QMessageBox,
                               QPlainTextEdit, QPushButton, QTableWidget, QTableWidgetItem,
                               QTabWidget, QVBoxLayout, QWidget)

from .. import edition
from ..adapters import isolated
from ..adapters import pdfid_adapter as pa
from ..core.models import Severity, ToolResult
from ..core.safety import csv_safe
from .command_builder import CommandBuilder
from .common import plain_tip
from .context import Context
from .theme import SEVERITY_COLOR, apply_mono

_FRIENDLY_EXTRA = {
    "TotalEntropy": "Entropy (whole file)",
    "TotalCount": "Bytes (whole file)",
    "StreamEntropy": "Entropy inside streams",
    "StreamCount": "Bytes inside streams",
    "NonStreamEntropy": "Entropy outside streams",
    "NonStreamCount": "Bytes outside streams",
    "CountEOF": "%%EOF markers",
    "CountCharsAfterLastEOF": "Bytes after last %%EOF",
}


class PdfidView(QWidget):
    """The pdfid tab: keyword triage, options, plugins and the disarmed copy."""
    TOOL = "pdfid"

    def __init__(self, ctx: Context, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.result: pa.PdfidData | None = None
        self.pdfid_path = pa.locate_pdfid()

        # ---- options ------------------------------------------------------
        self.opt_all = QCheckBox("All names (-a)")
        self.opt_all.setToolTip("List every /Name found, not just the suspicious keyword set.")
        self.opt_extra = QCheckBox("Extra data (-e)")
        self.opt_extra.setChecked(True)
        self.opt_extra.setToolTip("Dates, entropy inside/outside streams, data after %%EOF.")
        self.opt_force = QCheckBox("Force (-f)")
        self.opt_force.setToolTip("Scan even if no %PDF header is found.")
        self.opt_nozero = QCheckBox("Hide zero counts (-n)")
        self.opt_csv = QCheckBox("CSV output (-c)")

        self.plugin_list = QListWidget()
        self.plugin_list.setMaximumHeight(90)
        for p in pa.list_plugins(self.pdfid_path):
            ok, name, reason = pa.plugin_status(self.pdfid_path, p)
            item = QListWidgetItem(os.path.basename(p) + ("" if ok else "  (incompatible)"))
            item.setData(Qt.ItemDataRole.UserRole, p)
            if ok:
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(Qt.CheckState.Unchecked)
                item.setToolTip(name)
            else:   # pdfid would stop at it and skip every plugin after it
                item.setFlags(Qt.ItemFlag.NoItemFlags)
                item.setToolTip(plain_tip(f"{name}: {reason}. The app checks for embedded files and "
                                          "obfuscated names itself (findings, Obfuscated column)."))
            self.plugin_list.addItem(item)
        self.min_score = QDoubleSpinBox()
        self.min_score.setRange(0.0, 100.0)
        self.min_score.setDecimals(2)
        self.min_score.setToolTip("Minimum plugin score to report (-m).")

        run_btn = QPushButton("Run pdfid")
        run_btn.setDefault(True)
        self.disarm_btn = QPushButton("Create disarmed copy (-d)…")
        self.disarm_btn.setToolTip("Writes a copy with /JavaScript, /OpenAction etc. neutralised. "
                                   "The original sample is never modified.")
        export_btn = QPushButton("Export table CSV…")

        opts = QGroupBox("Options")
        ol = QHBoxLayout(opts)
        col1 = QVBoxLayout()
        for w in (self.opt_all, self.opt_extra, self.opt_force, self.opt_nozero, self.opt_csv):
            col1.addWidget(w)
        col2 = QVBoxLayout()
        col2.addWidget(QLabel("Plugins (-p)" if self.plugin_list.count() else
                              "Plugins (-p): none found next to pdfid.py"))
        col2.addWidget(self.plugin_list)
        row = QHBoxLayout()
        row.addWidget(QLabel("Minimum score (-m)"))
        row.addWidget(self.min_score)
        row.addStretch(1)
        col2.addLayout(row)
        col3 = QVBoxLayout()
        for w in (run_btn, self.disarm_btn, export_btn):
            col3.addWidget(w)
        col3.addStretch(1)
        ol.addLayout(col1)
        ol.addLayout(col2, 1)
        ol.addLayout(col3)

        self.summary = QLabel("Not run yet.")
        self.summary.setWordWrap(True)

        # ---- results ------------------------------------------------------
        self.only_present = QCheckBox("Show only keywords that are present")
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Keyword", "Count", "Obfuscated", "Severity", "What it means"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        h = self.table.horizontalHeader()
        for c in range(4):
            h.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.setToolTip("Double-click a keyword to list the objects that contain it (pdf-parser).")

        kw_page = QWidget()
        kl = QVBoxLayout(kw_page)
        kl.setContentsMargins(0, 4, 0, 0)
        kl.addWidget(self.only_present)
        kl.addWidget(self.table, 1)

        self.extra_table = QTableWidget(0, 2)
        self.extra_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.extra_table.verticalHeader().setVisible(False)
        self.extra_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.extra_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        self.raw = QPlainTextEdit(readOnly=True)
        self.raw.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        apply_mono(self.raw)

        self.tabs = QTabWidget()
        self.tabs.addTab(kw_page, "Keywords")
        self.tabs.addTab(self.extra_table, "Extra (-e)")
        self.tabs.addTab(self.raw, "Raw pdfid output")
        self.builder = CommandBuilder(ctx, ["pdfid"], [
            ("Standard scan with extra data", "pdfid", "-e"),
            ("All names in the file", "pdfid", "-a -e"),
            ("Force scan (no %PDF header)", "pdfid", "-f -e"),
            ("Triage plugin score", "pdfid", "-p plugin_triage.py"),
            ("Hide zero counts", "pdfid", "-n -e"),
        ])
        self.tabs.addTab(self.builder, "All options (command builder)")

        lay = QVBoxLayout(self)
        lay.addWidget(opts)
        lay.addWidget(self.summary)
        lay.addWidget(self.tabs, 1)

        run_btn.clicked.connect(self.run)
        self.disarm_btn.clicked.connect(self.disarm)
        export_btn.clicked.connect(self.export_csv)
        self.only_present.toggled.connect(lambda _: self._fill_table())
        self.table.cellDoubleClicked.connect(self._pivot)

        if not self.pdfid_path:
            self.summary.setText(f"<b>pdfid.py was not found</b> ({html.escape(edition.hint('tools'))}, "
                                 "or set the MTW_PDFID environment variable).")

    # ---------------------------------------------------------------- actions
    def options(self) -> pa.PdfidOptions:
        plugins = []
        for i in range(self.plugin_list.count()):
            item = self.plugin_list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                plugins.append(item.data(Qt.ItemDataRole.UserRole))
        return pa.PdfidOptions(
            all_names=self.opt_all.isChecked(), extra=self.opt_extra.isChecked(),
            force=self.opt_force.isChecked(), nozero=self.opt_nozero.isChecked(),
            plugins=plugins, minimum_score=self.min_score.value(), csv=self.opt_csv.isChecked())

    def run(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        opts = self.options()
        self.summary.setText("Running pdfid…")
        self.ctx.runner.submit(isolated.pdfid_run, self._on_result, self._on_error, sess.sample.path, opts)

    def _on_error(self, message: str) -> None:
        self.summary.setText(f"<b>pdfid failed:</b> {html.escape(isolated.tidy(message))}")
        self.ctx.log(message)
        self.ctx.report_failure("pdfid", message)

    def _on_result(self, res: ToolResult) -> None:
        self.ctx.log(res.command, command=True)
        self.raw.setPlainText(res.raw_output or res.error)
        if not res.ok:
            self.summary.setText(f"<b>pdfid failed:</b> {html.escape(res.error)}")
            self.ctx.log(res.error)
            self.ctx.report_failure("pdfid", res.error)
            return
        data: pa.PdfidData = res.data
        self.result = data
        present = [r for r in data.keywords if r.count]
        worst = max((r.severity for r in present), default=Severity.INFO)
        color = SEVERITY_COLOR[worst]
        self.summary.setText(
            f"Header <b>{html.escape(data.header or '—')}</b> &nbsp;·&nbsp; "
            f"{'Valid PDF' if data.is_pdf else '<b>No PDF header</b>'} &nbsp;·&nbsp; "
            f"{len(present)} of {len(data.keywords)} keywords present &nbsp;·&nbsp; "
            f"highest keyword severity <b style='color:{color}'>{worst.label}</b>")
        self._fill_table()
        self._fill_extra(data)
        self.ctx.set_findings(self.TOOL, res.findings)

    def _fill_table(self) -> None:
        self.table.setRowCount(0)
        if not self.result:
            return
        rows = [r for r in self.result.keywords
                if not self.only_present.isChecked() or r.count or r.hex_count]
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            sev = r.severity if (r.count or r.hex_count) else Severity.INFO
            cells = [r.name, str(r.count), str(r.hex_count) if r.hex_count else "",
                     sev.label if (r.count or r.hex_count) else "", r.explanation]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if c in (1, 2):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                if (r.count or r.hex_count) and sev >= Severity.MEDIUM and c in (0, 3):
                    item.setForeground(QBrush(QColor(SEVERITY_COLOR[sev])))
                if c == 2 and r.hex_count:
                    item.setForeground(QBrush(QColor(SEVERITY_COLOR[Severity.HIGH])))
                if c == 4:
                    item.setToolTip(plain_tip(text))
                self.table.setItem(i, c, item)

    def _fill_extra(self, data: pa.PdfidData) -> None:
        rows = [(_FRIENDLY_EXTRA.get(k, k), v) for k, v in data.extra.items()]
        rows += [(f"Date ({name})", value) for value, name in data.dates]
        if not rows:
            rows = [("—", "Enable 'Extra data (-e)' and run again.")]
        self.extra_table.setRowCount(len(rows))
        for i, (k, v) in enumerate(rows):
            self.extra_table.setItem(i, 0, QTableWidgetItem(k))
            self.extra_table.setItem(i, 1, QTableWidgetItem(v))
        self.extra_table.resizeColumnToContents(0)

    def _pivot(self, row: int, _col: int) -> None:
        name = self.table.item(row, 0).text()
        if name.startswith("/"):
            self.ctx.run_action(f"pdf.search:{name}")

    def open_builder(self, args: str = "", run: bool = False) -> None:
        self.tabs.setCurrentWidget(self.builder)
        if args:
            self.builder.prefill(args, "pdfid", run=run)

    def disarm(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        self.ctx.log("Disarming in a worker process…")
        self.ctx.runner.submit(isolated.pdfid_disarm, self._on_disarmed,
                               lambda m: QMessageBox.warning(self, "Disarm failed", isolated.tidy(m)),
                               sess.sample.path, self.ctx.output_dir())

    def _on_disarmed(self, result) -> None:
        dest, cmd = result
        self.ctx.add_artifact(dest)
        self.ctx.log(cmd, command=True)
        self.ctx.log(f"Disarmed copy written to {dest}")
        QMessageBox.information(self, "Disarmed copy created",
                                f"Written to:\n{dest}\n\nThe original sample was not modified. "
                                "The .bin suffix prevents it from opening on double-click.")

    def export_csv(self) -> None:
        if not self.result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export pdfid table",
                                              os.path.join(self.ctx.output_dir(), "pdfid.csv"),
                                              "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["keyword", "count", "hex_obfuscated", "severity", "meaning"])
            for r in self.result.keywords:
                w.writerow([csv_safe(r.name), r.count, r.hex_count, r.severity.label, r.explanation])
        self.ctx.log(f"pdfid table exported to {path}")
