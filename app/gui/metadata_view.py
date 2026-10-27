"""Metadata tab: olemeta / oletimes equivalents and OOXML docProps."""
from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QPushButton, QSplitter, QVBoxLayout, QWidget

from ..adapters import container_adapter as ca
from ..adapters import isolated
from ..core.models import Family, ToolResult
from .command_builder import CommandBuilder
from .common import banner, fill, hbox, table, vbox_widget
from .context import Context


class MetadataView(QWidget):
    """The Metadata tab: document properties, timestamps and tampering hints."""
    SOURCES = ("metadata",)

    def __init__(self, ctx: Context, family: Family, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.family = family
        self.info = banner()
        rerun = QPushButton("Reload")
        self.props = table(["Group", "Property", "Value"], 2)
        self.times = table(["Entry", "Created", "Modified"], 0)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(vbox_widget(banner("<b>Properties</b>"), (self.props, 1)))
        split.addWidget(vbox_widget(banner("<b>Timestamps</b> (OLE directory entries / zip members)"),
                                    (self.times, 1)))
        root = QVBoxLayout(self)
        root.addLayout(hbox(self.info, rerun))
        if family == Family.OLE:
            from PySide6.QtWidgets import QTabWidget
            tabs = QTabWidget()
            tabs.addTab(split, "Metadata")
            tabs.addTab(CommandBuilder(ctx, ["olemeta", "oletimes"]), "All options (command builder)")
            root.addWidget(tabs, 1)
        else:
            root.addWidget(split, 1)
        rerun.clicked.connect(self.run)

    def run(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        fam = "OLE" if self.family == Family.OLE else "OOXML"
        self.ctx.runner.submit(isolated.read_metadata, self._on_result, self._on_error, sess.sample.work_path, fam)

    def _on_error(self, message: str) -> None:
        self.info.setText(f"<b>Metadata unavailable:</b> {html.escape(isolated.tidy(message))}")
        self.ctx.log(message)
        self.ctx.report_failure("metadata", message)

    def _on_result(self, res: ToolResult) -> None:
        if res.command:
            self.ctx.log(res.command, command=True)
        md: ca.MetaData = res.data
        if not res.ok:
            self.info.setText(f"<b>Metadata unavailable:</b> {html.escape(res.error)}")
            self.ctx.report_failure("metadata", res.error)
            return
        fill(self.props, [list(p) for p in md.properties] or [["", "No metadata properties found.", ""]])
        fill(self.times, [list(t) for t in md.timestamps])
        self.info.setText(f"{len(md.properties)} properties · {len(md.timestamps)} timestamped entries. "
                          "Authors and timestamps help cluster phishing campaigns."
                          + (f"<br>{html.escape(md.error)}" if md.error else ""))
        self.ctx.set_findings("metadata", res.findings)
