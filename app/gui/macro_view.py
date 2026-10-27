"""Macros module: olevba analysis, XLM emulation, VBA stomping, decryption."""
from __future__ import annotations

import html
import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QGuiApplication, QTextCursor
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QHeaderView,
                               QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                               QMessageBox, QPlainTextEdit, QPushButton, QSplitter, QTableWidget,
                               QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)

from .. import edition
from ..adapters import isolated, toolenv
from ..adapters import macro_adapter as ma
from ..core.models import Severity, ToolResult
from ..core.safety import defang, safe_output_path
from .command_builder import CommandBuilder
from .common import flow, plain_tip
from .context import Context
from .theme import SEVERITY_COLOR, apply_mono
from .vba_highlighter import VbaHighlighter

ALL = "__all__"


def _text_view() -> QPlainTextEdit:
    t = QPlainTextEdit(readOnly=True)
    t.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    apply_mono(t)
    return t


def _table(headers: list[str], stretch: int) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    t.setAlternatingRowColors(True)
    h = t.horizontalHeader()
    for c in range(len(headers)):
        h.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
    h.setSectionResizeMode(stretch, QHeaderView.ResizeMode.Stretch)
    return t


class MacroView(QWidget):
    """The Macros tab: olevba analysis, XLM emulation, VBA stomping and decryption."""
    SOURCES = ("olevba", "xlmdeobfuscator")

    def __init__(self, ctx: Context, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.data: ma.MacroData | None = None
        self.encrypted = False

        # ---- options / actions ---------------------------------------------
        self.opt_decode = QCheckBox("Decode strings (--decode)")
        self.opt_decode.setChecked(True)
        self.opt_decode.setToolTip("Show decoded Hex / Base64 / Dridex / StrReverse strings in the analysis.")
        self.opt_reveal = QCheckBox("Reveal (--reveal)")
        self.opt_reveal.setChecked(True)
        self.opt_reveal.setToolTip("Produce a copy of the source with obfuscated strings replaced by their values.")
        self.opt_deobf = QCheckBox("Deobfuscate expressions (--deobf, slow)")
        self.opt_pcode = QCheckBox("P-code + stomping check")
        self.opt_pcode.setChecked(True)
        run_btn = QPushButton("Run olevba")
        self.xlm_btn = QPushButton("Emulate XLM…")
        self.xlm_btn.setEnabled(False)
        self.decrypt_btn = QPushButton("Decrypt…")
        self.decrypt_btn.setEnabled(False)
        export_btn = QPushButton("Export source…")

        top = flow(self.opt_decode, self.opt_reveal, self.opt_deobf, self.opt_pcode,
                   run_btn, self.xlm_btn, self.decrypt_btn, export_btn)

        self.banner = QLabel("")
        self.banner.setWordWrap(True)
        self.banner.setTextFormat(Qt.TextFormat.RichText)

        # ---- module list + code ---------------------------------------------
        self.modules = QListWidget()
        self.modules.setMinimumWidth(220)
        self.view_mode = QComboBox()
        self.view_mode.addItems(["Source", "Revealed (decoded strings inline)"])
        self.code_find = QLineEdit(placeholderText="Find in code…")
        self.code = _text_view()
        self.highlighter = VbaHighlighter(self.code.document(),
                                          dark=ctx.settings.value("dark", True, type=bool)
                                          if hasattr(ctx, "settings") else True)
        code_bar = QHBoxLayout()
        code_bar.addWidget(QLabel("View"))
        code_bar.addWidget(self.view_mode)
        code_bar.addStretch(1)
        code_bar.addWidget(self.code_find)
        code_box = QWidget()
        cl = QVBoxLayout(code_box)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.addLayout(code_bar)
        cl.addWidget(self.code, 1)
        upper = QSplitter(Qt.Orientation.Horizontal)
        upper.addWidget(self.modules)
        upper.addWidget(code_box)
        upper.setSizes([260, 900])

        # ---- lower tabs -------------------------------------------------------
        self.type_filter = QComboBox()
        self.type_filter.addItem("All types")
        self.analysis = _table(["Type", "Keyword", "Description"], 2)
        self.analysis.setToolTip("Double-click to find the keyword in the code.")
        an_page = QWidget()
        al = QVBoxLayout(an_page)
        al.setContentsMargins(0, 4, 0, 0)
        fr = QHBoxLayout()
        fr.addWidget(QLabel("Show"))
        fr.addWidget(self.type_filter)
        fr.addStretch(1)
        al.addLayout(fr)
        al.addWidget(self.analysis, 1)

        self.ioc_table = _table(["Indicator (defanged)"], 0)
        copy_iocs = QPushButton("Copy all (defanged)")
        ioc_page = QWidget()
        il = QVBoxLayout(ioc_page)
        il.setContentsMargins(0, 4, 0, 0)
        il.addWidget(self.ioc_table, 1)
        il.addWidget(copy_iocs, 0, Qt.AlignmentFlag.AlignRight)

        self.xlm_text = _text_view()
        self.pcode_banner = QLabel("")
        self.pcode_banner.setWordWrap(True)
        self.pcode_text = _text_view()
        pc_page = QWidget()
        pl = QVBoxLayout(pc_page)
        pl.setContentsMargins(0, 4, 0, 0)
        pl.addWidget(self.pcode_banner)
        pl.addWidget(self.pcode_text, 1)
        self.raw = _text_view()

        self.lower = QTabWidget()
        self.lower.addTab(an_page, "Analysis")
        self.lower.addTab(ioc_page, "IOCs")
        self.lower.addTab(self.xlm_text, "XLM / Excel 4.0")
        self.lower.addTab(pc_page, "P-code / stomping")
        self.lower.addTab(self.raw, "Raw olevba output")
        self.builder = CommandBuilder(ctx, ["olevba", "mraptor"], [
            ("Full analysis with decoding", "olevba", "--decode"),
            ("Only the keyword table", "olevba", "-a --decode"),
            ("Only the code", "olevba", "-c"),
            ("Reveal deobfuscated source", "olevba", "--reveal --decode"),
            ("Deobfuscate expressions (slow)", "olevba", "--deobf --decode"),
            ("P-code disassembly (stomping)", "olevba", "--show-pcode"),
            ("JSON output", "olevba", "-j"),
            ("Triage one-liner", "olevba", "-t"),
            ("mraptor verdict", "mraptor", ""),
        ])
        self.lower.addTab(self.builder, "All options (command builder)")

        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(upper)
        split.addWidget(self.lower)
        split.setSizes([520, 300])

        lay = QVBoxLayout(self)
        lay.addWidget(top)
        lay.addWidget(self.banner)
        lay.addWidget(split, 1)

        run_btn.clicked.connect(self.run)
        self.xlm_btn.clicked.connect(self.emulate_xlm)
        self.decrypt_btn.clicked.connect(self.decrypt)
        export_btn.clicked.connect(self.export_source)
        self.modules.currentItemChanged.connect(lambda *_: self._show_code())
        self.view_mode.currentIndexChanged.connect(lambda *_: self._show_code())
        self.type_filter.currentIndexChanged.connect(lambda *_: self._fill_analysis())
        self.analysis.cellDoubleClicked.connect(
            lambda r, _c: self.focus_keyword(self.analysis.item(r, 1).data(Qt.ItemDataRole.UserRole)))
        self.code_find.returnPressed.connect(lambda: self.focus_keyword(self.code_find.text(), cycle=True))
        copy_iocs.clicked.connect(lambda: QGuiApplication.clipboard().setText(
            "\n".join(defang(i) for i in (self.data.iocs if self.data else []))))

    # ================================================================ run
    def options(self) -> ma.MacroOptions:
        return ma.MacroOptions(decode=self.opt_decode.isChecked(), deobfuscate=self.opt_deobf.isChecked(),
                               reveal=self.opt_reveal.isChecked(), pcode=self.opt_pcode.isChecked())

    def run(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        self.banner.setText("Running olevba…")
        self.ctx.runner.submit(_check_and_analyse, self._on_result, self._on_error,
                               sess.sample.work_path, self.options())

    def _on_error(self, message: str) -> None:
        self.banner.setText(f"<b>olevba failed:</b> {html.escape(isolated.tidy(message))}")
        self.ctx.log(message)
        self.ctx.report_failure("olevba", message)

    def _set_encrypted(self, encrypted: bool) -> None:
        self.encrypted = encrypted
        self.decrypt_btn.setEnabled(encrypted and toolenv.provider("msoffcrypto").available)
        if encrypted:
            self.banner.setText(
                f"<b style='color:{SEVERITY_COLOR[Severity.MEDIUM]}'>This document is encrypted.</b> "
                "Click <b>Decrypt…</b>: Excel's default password (VelvetSweatshop) is tried first, "
                "then you're asked for one. The decrypted copy opens as a new sample.")

    def _on_result(self, result) -> None:
        encrypted, res = result
        self._set_encrypted(bool(encrypted))
        self.ctx.log(res.command, command=True)
        if res.error:
            self.ctx.log(res.error)
        self.raw.setPlainText(res.raw_output or res.error)
        if not res.ok:
            if not self.encrypted:
                self.banner.setText(f"<b>olevba failed:</b> {html.escape(res.error)}")
            self.ctx.report_failure("olevba", "document is encrypted: decrypt it first" if self.encrypted
                                    else res.error)
            return
        d: ma.MacroData = res.data
        self.data = d
        self.xlm_btn.setEnabled(d.has_xlm and ma.xlm_deobfuscator_available())
        if d.has_xlm and not ma.xlm_deobfuscator_available():
            self.xlm_btn.setToolTip(edition.hint("xlm"))
        self._fill_modules()
        self._fill_analysis()
        self._fill_iocs()
        self._fill_xlm()
        self._fill_pcode()
        self.highlighter.set_flagged([r.keyword for r in d.analysis
                                      if r.kind in ("AutoExec", "Suspicious")])
        if not self.encrypted:
            auto = sum(1 for r in d.analysis if r.kind == "AutoExec")
            susp = sum(1 for r in d.analysis if r.kind == "Suspicious")
            if not d.modules:
                self.banner.setText("No VBA or XLM macros in this file.")
            else:
                parts = [f"{len(d.modules)} module(s)", f"{auto} AutoExec", f"{susp} suspicious",
                         f"{len(d.iocs)} IOC(s)"]
                if d.has_xlm:
                    parts.append("<b>XLM present</b>")
                if d.stomping:
                    parts.append(f"<b style='color:{SEVERITY_COLOR[Severity.HIGH]}'>VBA STOMPING</b>")
                self.banner.setText(" · ".join(parts) +
                                    "  &nbsp;<span style='color:gray'>Flagged keywords are "
                                    "highlighted red in the code.</span>")
        self.ctx.set_findings("olevba", res.findings)

    # ================================================================ fill
    def _fill_modules(self) -> None:
        self.modules.blockSignals(True)
        self.modules.clear()
        d = self.data
        if d and d.modules:
            all_item = QListWidgetItem(f"All modules ({len(d.modules)})")
            all_item.setData(Qt.ItemDataRole.UserRole, ALL)
            self.modules.addItem(all_item)
            for i, m in enumerate(d.modules):
                item = QListWidgetItem(f"{'[XLM] ' if m.is_xlm else ''}{m.name}  ·  {m.lines} lines")
                item.setToolTip(plain_tip(m.stream_path))
                item.setData(Qt.ItemDataRole.UserRole, i)
                self.modules.addItem(item)
            self.modules.setCurrentRow(0)
        self.modules.blockSignals(False)
        self._show_code()

    def _show_code(self) -> None:
        d = self.data
        if not d or not d.modules:
            self.code.setPlainText("" if d is None else "No macro source in this file.")
            return
        if self.view_mode.currentIndex() == 1:
            self.code.setPlainText(d.revealed or "(Reveal was not run or produced no output. "
                                   "Enable 'Reveal' and run again.)")
            return
        item = self.modules.currentItem()
        key = item.data(Qt.ItemDataRole.UserRole) if item else ALL
        if key == ALL:
            parts = [f"' ===== {m.name}  ({m.stream_path}) =====\n{m.code}" for m in d.modules]
            self.code.setPlainText("\n\n".join(parts))
        else:
            self.code.setPlainText(d.modules[int(key)].code)

    def _fill_analysis(self) -> None:
        d = self.data
        current = self.type_filter.currentText()
        kinds = sorted({r.kind for r in d.analysis}) if d else []
        self.type_filter.blockSignals(True)
        self.type_filter.clear()
        self.type_filter.addItem("All types")
        self.type_filter.addItems(kinds)
        idx = self.type_filter.findText(current)
        self.type_filter.setCurrentIndex(max(0, idx))
        self.type_filter.blockSignals(False)
        want = self.type_filter.currentText()
        rows = [r for r in (d.analysis if d else []) if want == "All types" or r.kind == want]
        self.analysis.setRowCount(len(rows))
        for i, r in enumerate(rows):
            kw = QTableWidgetItem(defang(r.keyword))
            kw.setData(Qt.ItemDataRole.UserRole, r.keyword)
            cells = [QTableWidgetItem(r.kind), kw, QTableWidgetItem(defang(r.description))]
            if r.severity >= Severity.MEDIUM:
                for c in cells[:2]:
                    c.setForeground(QBrush(QColor(SEVERITY_COLOR[r.severity])))
            cells[2].setToolTip(plain_tip(defang(r.description)))
            for c, item in enumerate(cells):
                self.analysis.setItem(i, c, item)

    def _fill_iocs(self) -> None:
        iocs = self.data.iocs if self.data else []
        self.ioc_table.setRowCount(len(iocs))
        for i, ioc in enumerate(iocs):
            self.ioc_table.setItem(i, 0, QTableWidgetItem(defang(ioc)))
        self.lower.setTabText(1, f"IOCs ({len(iocs)})" if iocs else "IOCs")

    def _fill_xlm(self) -> None:
        d = self.data
        xlm = [m for m in (d.modules if d else []) if m.is_xlm]
        if xlm:
            text = "\n\n".join(m.code for m in xlm)
            text += ("\n\n----\nUse 'Emulate XLM…' to recover what the formulas actually do "
                     "(hidden sheets, CHAR()-built strings, EXEC/CALL targets).")
        elif d and d.has_xlm:
            text = "XLM macros were detected but olevba returned no formulas. Try 'Emulate XLM…'."
        else:
            text = "No Excel 4.0 (XLM) macros detected."
        self.xlm_text.setPlainText(text)

    def _fill_pcode(self) -> None:
        d = self.data
        if not d or not d.has_vba:
            self.pcode_banner.setText("No VBA, so no p-code to check.")
            self.pcode_text.clear()
            return
        if d.stomping is None:
            self.pcode_banner.setText("Stomping check unavailable (needs pcodedmp, an oletools dependency).")
        elif d.stomping:
            self.pcode_banner.setText(
                f"<b style='color:{SEVERITY_COLOR[Severity.HIGH]}'>VBA STOMPING DETECTED.</b> The compiled "
                "p-code differs from the source. Office runs the p-code, so the source shown above may "
                "be a decoy. Read the disassembly below.")
        else:
            self.pcode_banner.setText("No VBA stomping detected: p-code matches the source.")
        self.pcode_text.setPlainText(d.pcode or "(No p-code disassembly returned.)")

    # ================================================================ actions
    def focus_keyword(self, keyword: str | None, cycle: bool = False) -> None:
        if not keyword:
            return
        if self.modules.count() and not cycle:
            self.modules.setCurrentRow(0)          # search across all modules
        doc = self.code.document()
        start = self.code.textCursor() if cycle else QTextCursor(doc)
        hit = doc.find(keyword, start)
        if hit.isNull() and cycle:
            hit = doc.find(keyword, QTextCursor(doc))
        if hit.isNull():
            self.ctx.log(f"'{defang(keyword)}' not found in the source view (it may only appear "
                         "after decoding; try View → Revealed).")
            return
        self.code.setTextCursor(hit)
        self.code.centerCursor()
        self.code.setFocus()

    # ---- methods used by Investigate steps
    def show_lower(self, name: str) -> None:
        tabs = {"analysis": 0, "iocs": 1, "xlm": 2, "pcode": 3, "raw": 4, "builder": 5}
        self.lower.setCurrentIndex(tabs.get(name, 0))

    def set_view(self, mode: str) -> None:
        self.view_mode.setCurrentIndex(1 if mode == "revealed" else 0)
        if mode != "revealed" and self.modules.count():
            self.modules.setCurrentRow(0)

    def open_builder(self, args: str = "", run: bool = False, tool: str = "olevba") -> None:
        self.lower.setCurrentWidget(self.builder)
        if args:
            self.builder.prefill(args, tool, run=run)

    def emulate_xlm(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        self.xlm_text.setPlainText("Emulating XLM macros… (stops automatically after 5 minutes)")
        self.lower.setCurrentWidget(self.xlm_text)
        self.ctx.runner.submit(ma.emulate_xlm, self._on_xlm, self._on_xlm_error, sess.sample.work_path)

    def _on_xlm_error(self, message: str) -> None:
        self.xlm_text.setPlainText(f"XLM emulation failed: {message}")
        self.ctx.log(message)
        self.ctx.report_failure("xlmdeobfuscator", message)

    def _on_xlm(self, res: ToolResult) -> None:
        if res.command:
            self.ctx.log(res.command, command=True)
        body = res.raw_output or ""
        if res.error:
            body += f"\n\nERROR: {res.error}"
        urls = res.data or []
        header = (f"Recovered {len(urls)} URL(s): " + ", ".join(defang(u) for u in urls) + "\n\n"
                  if urls else "")
        self.xlm_text.setPlainText(header + defang(body))
        self.ctx.set_findings("xlmdeobfuscator", res.findings)

    def decrypt(self, password: str | None = None) -> None:
        """Decrypt in a worker process: the default password first, then ask."""
        sess = self.ctx.session()
        if sess is None:
            return
        self.ctx.log("Decrypting in a worker process…")
        self.ctx.runner.submit(isolated.macro_decrypt, lambda r: self._on_decrypted(r, sess),
                               lambda m: self._on_decrypt_failed(m, password),
                               sess.sample.work_path, self.ctx.output_dir(), password)

    def _on_decrypt_failed(self, message: str, tried: str | None) -> None:
        first = (message.splitlines() or [""])[0]
        if not first.startswith("WrongPassword"):
            QMessageBox.warning(self, "Decryption failed", isolated.tidy(message)[:400])
            return
        prompt = ("The default password didn't work. Enter the document password\n"
                  "(phishing emails usually include it in the message body):"
                  if tried is None else "Wrong password. Try again:")
        password, ok = QInputDialog.getText(self, "Document password", prompt, QLineEdit.EchoMode.Password)
        if ok and password:
            self.decrypt(password)

    def _on_decrypted(self, result, sess) -> None:
        dest, used, cmd = result
        self.ctx.log(cmd, command=True)
        self.ctx.log(f"Decrypted with {'Excel default password' if used == ma.VELVET else 'supplied password'}"
                     f" → {dest}")
        self.ctx.load_child(dest, f"decrypted from {sess.sample.name} (SHA256 {sess.sample.sha256})")

    def export_source(self) -> None:
        d = self.data
        sess = self.ctx.session()
        if not d or not d.modules or sess is None:
            QMessageBox.information(self, "Export", "No macro source to export.")
            return
        base = os.path.splitext(sess.sample.name)[0]
        default = safe_output_path(self.ctx.output_dir(), base + ".macros", suffix=".txt")
        path, _ = QFileDialog.getSaveFileName(self, "Export macro source", default, "Text (*.txt)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"' Source: {sess.sample.name}  SHA256 {sess.sample.sha256}\n")
            fh.write("' Exported as text for analysis. Do not run.\n\n")
            for m in d.modules:
                fh.write(f"' ===== {m.name}  ({m.stream_path}) =====\n{m.code}\n\n")
            if d.revealed:
                fh.write("' ===== REVEALED (olevba --reveal) =====\n" + d.revealed + "\n")
        self.ctx.log(f"Macro source exported to {path}")


def _check_and_analyse(path: str, opts):
    """Runs in a pool thread: both steps parse the sample, so both run in worker processes."""
    try:
        encrypted = isolated.macro_is_encrypted(path)
    except Exception:
        encrypted = False
    return encrypted, isolated.macro_analyse(path, opts)
