"""Report tab: notes, phishing summary, HTML report, IOC CSV, JSON."""
from __future__ import annotations

import html
import os

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (QFileDialog, QLineEdit, QPlainTextEdit, QPushButton, QSplitter, QVBoxLayout,
                               QWidget)

from ..core import report
from ..core.safety import defang, safe_output_path
from .common import banner, fill, flow, table, text_view, vbox_widget
from .context import Context


class ReportView(QWidget):
    """The Report tab: notes, verdict, phishing summary and exports."""
    SOURCES: tuple[str, ...] = ()

    def __init__(self, ctx: Context, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.verdict = banner()
        self.analyst = QLineEdit(placeholderText="Analyst name (optional)")
        if hasattr(ctx, "settings"):
            self.analyst.setText(str(ctx.settings.value("analyst", "")))
        refresh = QPushButton("Refresh")
        copy_summary = QPushButton("Copy phishing summary")
        html_btn = QPushButton("Save HTML report…")
        csv_btn = QPushButton("Save IOC CSV…")
        json_btn = QPushButton("Export session JSON…")

        self.notes = QPlainTextEdit()
        self.notes.setPlaceholderText("Analyst notes: context from the reporter, sender, what you checked, "
                                      "decisions. Included in the report and JSON export.")
        self.summary = text_view(wrap=True)
        self.iocs = table(["Indicator (defanged)", "Source"], 0)

        left = vbox_widget(banner("<b>Notes</b>"), (self.notes, 1),
                           banner("<b>IOCs</b> collected from all tools"), (self.iocs, 1))
        right = vbox_widget(banner("<b>Phishing summary</b> (paste into the ticket or reply to the reporter)"),
                            (self.summary, 1))
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([520, 700])

        root = QVBoxLayout(self)
        root.addWidget(self.verdict)
        self.analyst.setMaximumWidth(260)
        root.addWidget(flow(self.analyst, refresh, copy_summary, html_btn, csv_btn, json_btn))
        root.addWidget(split, 1)

        refresh.clicked.connect(self.refresh)
        self.notes.textChanged.connect(self._save_notes)
        self.analyst.editingFinished.connect(self._save_analyst)
        copy_summary.clicked.connect(self.copy_summary)
        html_btn.clicked.connect(self.save_html)
        csv_btn.clicked.connect(self.save_csv)
        json_btn.clicked.connect(lambda: getattr(ctx, "export_session")())

    def run(self) -> None:
        self.refresh()

    def showEvent(self, e) -> None:          # always current when the tab is opened
        super().showEvent(e)
        self.refresh()

    def refresh(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        if self.notes.toPlainText() != sess.notes:
            self.notes.blockSignals(True)
            self.notes.setPlainText(sess.notes)
            self.notes.blockSignals(False)
        title, action = report.verdict(sess)
        from .theme import SEVERITY_COLOR
        color = "#6e56cf" if sess.incomplete else SEVERITY_COLOR[sess.risk]
        self.verdict.setText(f"<span style='font-size:15pt;font-weight:700;color:{color}'>{html.escape(title)}"
                             f"</span><br>{html.escape(action)}<br><span style='color:gray'>Tools run: "
                             f"{', '.join(sorted(sess.tools_run)) or 'none yet'}. Tools you haven't run "
                             "(e.g. object extraction, peepdf) aren't reflected.</span>")
        fill(self.iocs, [[defang(v), s] for v, s in sess.all_iocs] or [["No IOCs collected yet.", ""]])
        self.summary.setPlainText(report.phishing_summary(sess, self.analyst.text().strip()))

    def _save_notes(self) -> None:
        sess = self.ctx.session()
        if sess is not None:
            sess.notes = self.notes.toPlainText()

    def _save_analyst(self) -> None:
        if hasattr(self.ctx, "settings"):
            self.ctx.settings.setValue("analyst", self.analyst.text().strip())
        self.refresh()

    def copy_summary(self) -> None:
        self.refresh()
        QGuiApplication.clipboard().setText(self.summary.toPlainText())
        self.ctx.log("Phishing summary copied to clipboard")

    def _default(self, ext: str) -> str:
        sess = self.ctx.session()
        base = f"{sess.sample.sha256[:12]}_{os.path.splitext(sess.sample.name)[0]}_report"
        return safe_output_path(self.ctx.output_dir(), base, suffix=ext)

    def save_html(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save HTML report", self._default(".html"), "HTML (*.html)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(report.html_report(sess, self.analyst.text().strip()))
        self.ctx.log(f"HTML report saved to {path}")
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))   # our own report, safe to open

    def save_csv(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save IOC CSV", self._default(".csv"), "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(report.ioc_csv(sess))
        self.ctx.log(f"IOC CSV saved to {path}")
