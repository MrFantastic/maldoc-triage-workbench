"""Office triage module: mraptor verdict + oleid indicators + macro inventory."""
from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QGroupBox, QHBoxLayout, QHeaderView,
                               QLabel, QPlainTextEdit, QPushButton, QSplitter, QTableWidget,
                               QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)

from .. import edition
from ..adapters import isolated, toolenv
from ..adapters import office_adapter as oa
from ..core.models import Severity, ToolResult
from ..core.safety import defang
from .command_builder import CommandBuilder
from .common import plain_tip
from .context import Context
from .theme import SEVERITY_COLOR, VERDICT_COLOR, apply_mono, badge_style

_FLAG_HELP = {
    "A": ("AutoExec", "Code runs automatically (AutoOpen, Document_Open, Workbook_Open, …)."),
    "W": ("Write", "Code can write to the file system or memory (Open … For Output, SaveToFile, …)."),
    "X": ("Execute", "Code can run programs or commands (Shell, CreateObject, WScript, …)."),
}


def _mono(widget: QWidget) -> None:
    apply_mono(widget)


class CodeDialog(QDialog):
    """Read-only macro source viewer. Code is displayed, never executed."""

    def __init__(self, title: str, code: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(900, 650)
        edit = QPlainTextEdit(readOnly=True)
        edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        _mono(edit)
        edit.setPlainText(code)
        note = QLabel("Read-only view. Full macro analysis (deobfuscation, IOCs, XLM emulation) "
                      "arrives with the Macros module.")
        note.setObjectName("Muted")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(note)
        lay.addWidget(edit, 1)
        lay.addWidget(buttons)


class OfficeTriageView(QWidget):
    """The Office triage tab: oleid's indicators and mraptor's verdict."""
    SOURCES = ("oleid", "mraptor")

    def __init__(self, ctx: Context, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.data: oa.OfficeTriageData | None = None

        # ---- header: verdict card ---------------------------------------
        ole = toolenv.provider("oletools")
        ver = ole.version if ole.available else None
        self.version_lbl = QLabel(f"oletools {ver}" if ver else
                                  f"<b>oletools is not installed</b> ({html.escape(edition.hint('oletools'))}).")
        self.version_lbl.setObjectName("Muted")
        run_btn = QPushButton("Run oleid + mraptor")

        self.verdict = QLabel("—")
        self.verdict.setObjectName("Verdict")
        self.verdict.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.verdict.setMinimumWidth(220)
        self.verdict.setStyleSheet(badge_style(SEVERITY_COLOR[Severity.INFO]))
        self.chips: dict[str, QLabel] = {}
        chip_row = QHBoxLayout()
        for key, (name, help_text) in _FLAG_HELP.items():
            chip = QLabel(f"{key}  {name}")
            chip.setObjectName("Chip")
            chip.setToolTip(help_text)
            chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.chips[key] = chip
            chip_row.addWidget(chip)
        self.matches_lbl = QLabel("")
        self.matches_lbl.setWordWrap(True)
        self.matches_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._set_chips("")

        card = QGroupBox("mraptor verdict")
        cl = QHBoxLayout(card)
        cl.addWidget(self.verdict)
        right = QVBoxLayout()
        right.addLayout(chip_row)
        right.addWidget(self.matches_lbl)
        cl.addLayout(right, 1)

        top = QHBoxLayout()
        top.addWidget(self.version_lbl, 1)
        top.addWidget(run_btn)

        # ---- oleid indicators --------------------------------------------
        self.ind_table = QTableWidget(0, 4)
        self.ind_table.setHorizontalHeaderLabels(["Indicator", "Value", "Risk", "Description"])
        self._table_defaults(self.ind_table, stretch=3)

        # ---- VBA modules ---------------------------------------------------
        self.mod_table = QTableWidget(0, 3)
        self.mod_table.setHorizontalHeaderLabels(["Stream path", "Module file", "Lines"])
        self._table_defaults(self.mod_table, stretch=0)
        self.mod_table.setToolTip("Double-click to view the macro source (read-only).")
        self.mod_hint = QLabel("")
        self.mod_hint.setObjectName("Muted")
        mod_box = QWidget()
        ml = QVBoxLayout(mod_box)
        ml.setContentsMargins(0, 0, 0, 0)
        ml.addWidget(QLabel("<b>Macro modules (olevba)</b>"))
        ml.addWidget(self.mod_table, 1)
        ml.addWidget(self.mod_hint)

        ind_box = QWidget()
        il = QVBoxLayout(ind_box)
        il.setContentsMargins(0, 0, 0, 0)
        il.addWidget(QLabel("<b>Indicators (oleid)</b>"))
        il.addWidget(self.ind_table, 1)

        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(ind_box)
        split.addWidget(mod_box)
        split.setSizes([300, 200])
        split.setCollapsible(1, False)
        self.split = split

        self.raw = QPlainTextEdit(readOnly=True)
        self.raw.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        _mono(self.raw)

        tabs = QTabWidget()
        tabs.addTab(split, "Dashboard")
        tabs.addTab(self.raw, "Raw output")
        self.builder = CommandBuilder(ctx, ["oleid", "mraptor"], [
            ("oleid indicators", "oleid", ""), ("mraptor verdict", "mraptor", ""),
            ("mraptor matched keywords", "mraptor", "-m")])
        tabs.addTab(self.builder, "All options (command builder)")

        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(card)
        lay.addWidget(tabs, 1)

        run_btn.clicked.connect(self.run)
        self.mod_table.cellDoubleClicked.connect(self._show_code)

    @staticmethod
    def _table_defaults(t: QTableWidget, stretch: int) -> None:
        t.verticalHeader().setVisible(False)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.setAlternatingRowColors(True)
        t.setWordWrap(True)
        h = t.horizontalHeader()
        for c in range(t.columnCount()):
            h.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(stretch, QHeaderView.ResizeMode.Stretch)

    def _set_chips(self, flags: str) -> None:
        for key, chip in self.chips.items():
            lit = key in (flags or "")
            color = SEVERITY_COLOR[Severity.HIGH] if lit else "transparent"
            fg = "white" if lit else "palette(mid)"
            chip.setStyleSheet(f"background-color: {color}; color: {fg}; "
                               f"border: 1px solid {'transparent' if lit else 'palette(mid)'};")

    # ---------------------------------------------------------------- run
    def run(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        self.verdict.setText("Running…")
        self.ctx.runner.submit(isolated.office_run, self._on_result, self._on_error, sess.sample.path)

    def _on_error(self, message: str) -> None:
        self.verdict.setText("ERROR")
        self.verdict.setStyleSheet(badge_style(VERDICT_COLOR["ERROR"]))
        self.matches_lbl.setText(html.escape(isolated.tidy(message)))
        self.ctx.log(message)
        self.ctx.report_failure("oleid", message)
        self.ctx.report_failure("mraptor", message)

    def _on_result(self, res: ToolResult) -> None:
        self.ctx.log(res.command, command=True)
        if res.error:
            self.ctx.log(res.error)
        d: oa.OfficeTriageData = res.data
        self.data = d
        self.raw.setPlainText(res.raw_output)
        if d.oleid_error and d.verdict == "ERROR":
            self.ctx.report_failure("oleid", d.oleid_error)
            self.ctx.report_failure("mraptor", d.vba_error or d.oleid_error)

        verdict = d.verdict or "ERROR"
        self.verdict.setText(verdict)
        self.verdict.setStyleSheet(badge_style(VERDICT_COLOR.get(verdict, VERDICT_COLOR["ERROR"])))
        self._set_chips(d.flags if verdict in ("SUSPICIOUS", "MACRO OK") else "")
        parts = []
        if d.matches:
            parts.append("Matched keywords: " + html.escape(defang(", ".join(d.matches))))
        if d.has_xlm:
            parts.append(f"<b style='color:{SEVERITY_COLOR[Severity.HIGH]}'>Excel 4.0 (XLM) macros "
                         "detected.</b> mraptor's rules target VBA; review the XLM separately.")
        if d.vba_error:
            parts.append(f"Macro scan error: {html.escape(d.vba_error)}")
        if verdict == "NO MACRO" and not d.has_xlm:
            parts.append("No VBA or XLM macros found. Check oleid indicators below for external "
                         "relationships, embedded objects and other non-macro techniques.")
        self.matches_lbl.setText("<br>".join(parts))

        self.ind_table.setRowCount(len(d.indicators))
        for i, ind in enumerate(d.indicators):
            cells = [ind.name, defang(ind.value), ind.risk_text, defang(ind.description)]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setToolTip(plain_tip(text))
                if c in (0, 2) and ind.risk >= Severity.MEDIUM and oa.truthy(ind.value):
                    item.setForeground(QBrush(QColor(SEVERITY_COLOR[ind.risk])))
                self.ind_table.setItem(i, c, item)
        self.ind_table.resizeRowsToContents()
        if d.oleid_error:
            self.ind_table.setRowCount(1)
            self.ind_table.setItem(0, 0, QTableWidgetItem("oleid error"))
            self.ind_table.setItem(0, 3, QTableWidgetItem(d.oleid_error))

        self.mod_table.setRowCount(len(d.modules))
        for i, m in enumerate(d.modules):
            for c, text in enumerate([m.stream_path, m.vba_filename, str(m.lines)]):
                self.mod_table.setItem(i, c, QTableWidgetItem(text))
        self.mod_table.setVisible(bool(d.modules))
        self.mod_hint.setText(f"{len(d.modules)} module(s). Double-click to view source, or use "
                              "the Macros tab for full analysis."
                              if d.modules else "No macro modules.")
        self.split.setSizes([10_000, 1] if not d.modules else [300, 200])

        # split findings by source so re-running one tool replaces only its own
        by_src: dict[str, list] = {s: [] for s in self.SOURCES}
        for f in res.findings:
            by_src.setdefault(f.source, []).append(f)
        for src, items in by_src.items():
            if src == "oleid" and d.oleid_error:
                self.ctx.report_failure("oleid", d.oleid_error)
            elif src == "mraptor" and d.verdict == "ERROR":
                self.ctx.report_failure("mraptor", d.vba_error or "macro scan failed")
            else:
                self.ctx.set_findings(src, items)

    def _show_code(self, row: int, _col: int) -> None:
        if not self.data or row >= len(self.data.modules):
            return
        m = self.data.modules[row]
        CodeDialog(f"{m.vba_filename} — {m.stream_path}", m.code, self).exec()
