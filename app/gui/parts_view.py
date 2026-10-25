"""Parts tab: OOXML package browser with relationships and zipdump output."""
from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QMessageBox, QPushButton, QSplitter, QTabWidget, QVBoxLayout, QWidget

from ..adapters import container_adapter as ca
from ..adapters import isolated
from ..core.models import Severity, ToolResult
from ..core.safety import defang
from .command_builder import CommandBuilder
from .common import banner, fill, hbox, row_data, table, text_view, vbox_widget
from .context import Context
from .hex_view import HexPanel


class PartsView(QWidget):
    """The Parts tab: package parts, external relationships and part contents."""
    SOURCES = ("parts",)

    def __init__(self, ctx: Context, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.data: ca.PartsData | None = None
        self._preview_for = ""

        self.info = banner()
        rerun = QPushButton("Reload")
        self.only_interesting = QCheckBox("Only parts with notes")
        self.parts = table(["#", "Part", "Size", "Packed", "Modified", "Type", "Note"], 1)
        self.rels = table(["Source part", "Id", "Type", "Target (defanged)", "External"], 3)
        self.zipdump = text_view()

        self.content = text_view()
        self.hex = HexPanel()
        view_tabs = QTabWidget()
        view_tabs.addTab(self.content, "Content")
        view_tabs.addTab(self.hex, "Hex")
        self.view_tabs = view_tabs
        save = QPushButton("Save part (.bin)")
        save.setToolTip("Write the full part to the output folder with a .bin suffix.")
        analyze = QPushButton("Analyze as new sample")

        parts_page = QSplitter(Qt.Orientation.Horizontal)
        parts_page.addWidget(vbox_widget(self.only_interesting, (self.parts, 1)))
        parts_page.addWidget(vbox_widget(hbox(None, save, analyze), (view_tabs, 1)))
        parts_page.setSizes([620, 600])

        tabs = QTabWidget()
        tabs.addTab(parts_page, "Parts")
        tabs.addTab(self.rels, "Relationships")
        tabs.addTab(self.zipdump, "zipdump.py output")
        self.builder = CommandBuilder(ctx, ["zipdump"], [
            ("List files with details", "zipdump", "-e"), ("Dump file N (edit)", "zipdump", "-s 1 -d"),
            ("Hex dump of file N (edit)", "zipdump", "-s 1 -a")])
        tabs.addTab(self.builder, "All options (command builder)")
        self.tabs = tabs

        root = QVBoxLayout(self)
        root.addLayout(hbox(self.info, rerun))
        root.addWidget(tabs, 1)

        rerun.clicked.connect(self.run)
        self.only_interesting.toggled.connect(lambda *_: self._fill_parts())
        self.parts.currentCellChanged.connect(lambda *_: self.show_part())
        save.clicked.connect(self.save_part)
        analyze.clicked.connect(self.analyze_part)

    def run(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        self.info.setText("Reading package…")
        self.ctx.runner.submit(isolated.read_parts, self._on_parts, self._parts_err, sess.sample.path)
        self.ctx.runner.submit(ca.run_zipdump, self._on_zipdump, self._err, sess.sample.path)

    def _err(self, msg: str) -> None:
        self.info.setText(f"<b>Failed:</b> {html.escape(isolated.tidy(msg))}")
        self.ctx.log(msg)

    def _parts_err(self, msg: str) -> None:
        self._err(msg)
        self.ctx.report_failure("parts", msg)

    def show_rels(self) -> None:
        self.tabs.setCurrentIndex(1)

    def select_part(self, name: str) -> None:
        self.tabs.setCurrentIndex(0)
        self.only_interesting.setChecked(False)
        for r in range(self.parts.rowCount()):
            p = row_data(self.parts, r)
            if isinstance(p, ca.Part) and p.name == name:
                self.parts.selectRow(r)
                return

    def _on_zipdump(self, r) -> None:
        if r.returncode != 127:
            self.ctx.log(r.command, command=True)
        self.zipdump.setPlainText(defang(r.text))

    def _on_parts(self, res: ToolResult) -> None:
        if not res.ok:
            self.info.setText(f"<b>Could not read package:</b> {html.escape(res.error)}")
            self.ctx.report_failure("parts", res.error)
            return
        self.data = res.data
        d = self.data
        ext = d.external
        self.info.setText(f"{len(d.parts)} parts · {len(d.relationships)} relationships "
                          f"({len(ext)} external)" + (" · <b>check the Relationships tab</b>" if ext else ""))
        self._fill_parts()
        rows, colors = [], []
        for r in sorted(d.relationships, key=lambda r: not r.external):
            rows.append([r.source_part, r.rel_id, r.rel_type, defang(r.target), "yes" if r.external else ""])
            colors.append(Severity.HIGH if r.external and r.rel_type in ca.TEMPLATE_TYPES
                          else Severity.MEDIUM if r.external else None)
        fill(self.rels, rows, colors=colors)
        if ext:
            self.tabs.setTabText(1, f"Relationships ({len(ext)} external)")
        self.ctx.set_findings("parts", res.findings)
        self.ctx.set_iocs("parts", [r.target for r in ext if r.rel_type != "hyperlink"])

    def _fill_parts(self) -> None:
        if not self.data:
            return
        parts = [p for p in self.data.parts if p.note or not self.only_interesting.isChecked()]
        rows, colors = [], []
        for p in parts:
            rows.append([p.index, p.name, f"{p.size:,}", f"{p.compressed:,}", p.modified, p.kind, p.note])
            colors.append(Severity.HIGH if "executable" in p.note.lower() else
                          Severity.MEDIUM if p.note in ("VBA project (macros)", "Embedded object",
                                                        "ActiveX control") else None)
        fill(self.parts, rows, data=parts, colors=colors)

    def _selected(self) -> ca.Part | None:
        p = row_data(self.parts)
        return p if isinstance(p, ca.Part) and self.ctx.session() is not None else None

    def show_part(self) -> None:
        """Preview the first few MB of the part (decompressed in a worker process)."""
        p = self._selected()
        if p is None:
            return
        self._preview_for = p.name
        self.content.setPlainText("Reading part…")
        self.hex.set_data(b"")
        self.ctx.runner.submit(isolated.preview_part, lambda r: self._on_preview(p, r),
                               lambda m: self._on_preview_err(p, m), self.ctx.session().sample.path, p.name)

    def _on_preview_err(self, p: ca.Part, msg: str) -> None:
        if p.name == self._preview_for:
            self.content.setPlainText(f"Could not read part: {(msg.splitlines() or [''])[0]}")

    def _on_preview(self, p: ca.Part, result) -> None:
        if p.name != self._preview_for:        # the selection moved on
            return
        data, size = result
        self.hex.set_data(data)
        text = data[:2_000_000].decode("utf-8", "replace")
        printable = sum(c.isprintable() or c in "\r\n\t" for c in text[:4000])
        if data and printable / max(1, min(len(text), 4000)) > 0.85:
            if text.lstrip().startswith("<"):
                text = text.replace("><", ">\n<")   # readable XML without parsing it
            if size > len(data):
                text += f"\n\n[preview: first {len(data):,} of {size:,} bytes. Save or analyze the part for all of it]"
            self.content.setPlainText(defang(text))
            self.view_tabs.setCurrentWidget(self.content)
        else:
            self.content.setPlainText(f"{len(data):,} bytes, {p.kind or 'binary'}. See the Hex tab, or "
                                      "'Analyze as new sample' for OLE parts such as vbaProject.bin.")
            self.view_tabs.setCurrentWidget(self.hex)

    def _extract(self, then) -> None:
        p = self._selected()
        sess = self.ctx.session()
        if p is None or sess is None:
            return
        self.ctx.runner.submit(isolated.extract_part, lambda r: then(p, sess, r),
                               lambda m: QMessageBox.warning(self, "Could not extract part",
                                                             isolated.tidy(m)),
                               sess.sample.path, p.name, self.ctx.output_dir())

    def save_part(self) -> None:
        def done(p, _sess, result):
            dest, size, sha = result
            self.ctx.add_artifact(dest)
            self.ctx.log(f"Part {p.name} ({size:,} bytes, SHA256 {sha}) saved to {dest}")
            QMessageBox.information(self, "Part saved", f"Written to:\n{dest}\n\nThe .bin suffix stops it "
                                    "opening on double-click.")
        self._extract(done)

    def analyze_part(self) -> None:
        def done(p, sess, result):
            dest, size, sha = result
            self.ctx.log(f"Part {p.name} ({size:,} bytes, SHA256 {sha}) written to {dest}")
            self.ctx.load_child(dest, f"part {p.name} of {sess.sample.name} (SHA256 {sess.sample.sha256})")
        self._extract(done)
