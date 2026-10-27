"""YARA tab: your own rules, run over the whole file and inside its streams, objects and parts."""
from __future__ import annotations

import html
import os

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QMessageBox, QPushButton, QSplitter, QVBoxLayout, QWidget

from .. import edition
from ..adapters import isolated, toolenv, yara_adapter
from ..core.models import ToolResult
from ..core.safety import defang
from .common import banner, fill, row_data, table, text_view, vbox_widget
from .context import Context

SETTING = "yara_rules"


def rules_setting() -> str:
    """The YARA rules file or folder: MTW_YARA_RULES, else the saved setting ("" = none)."""
    return os.environ.get("MTW_YARA_RULES") or str(QSettings().value(SETTING, "") or "")


def choose_rules(parent: QWidget) -> bool:
    """Ask for a rules file or folder (or none) and save it. True if the setting changed."""
    box = QMessageBox(QMessageBox.Icon.Question, "YARA rules",
                      "Scan with your own YARA rules: one rules file, or a folder whose .yar / .yara files "
                      "(in any sub-folder) are all used.\n\nCurrent: " + (rules_setting() or "none"), parent=parent)
    pick_file = box.addButton("A rules file…", QMessageBox.ButtonRole.AcceptRole)
    pick_dir = box.addButton("A rules folder…", QMessageBox.ButtonRole.AcceptRole)
    clear = box.addButton("No rules", QMessageBox.ButtonRole.DestructiveRole)
    box.addButton(QMessageBox.StandardButton.Cancel)
    box.exec()
    start = rules_setting() or os.path.expanduser("~")
    if box.clickedButton() is pick_file:
        path, _ = QFileDialog.getOpenFileName(parent, "YARA rules file", start,
                                              "YARA rules (*.yar *.yara);;All files (*)")
    elif box.clickedButton() is pick_dir:
        path = QFileDialog.getExistingDirectory(parent, "YARA rules folder", start)
    elif box.clickedButton() is clear:
        path = ""
    else:
        return False
    if path is None or (path == "" and box.clickedButton() is not clear):
        return False
    QSettings().setValue(SETTING, path)
    return True


class YaraView(QWidget):
    """The YARA tab: matches of your rules, where each one hit, and the matched text."""
    SOURCES = ("yara",)

    def __init__(self, ctx: Context, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.info = banner()
        choose = QPushButton("Rules…")
        scan = QPushButton("Scan")
        self.table = table(["Rule", "Where", "Found by", "Tags", "Matched text"], 4)
        self.detail = text_view(wrap=True)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.table)
        split.addWidget(vbox_widget(banner("<b>Selected match</b>"), (self.detail, 1)))
        split.setSizes([400, 160])
        top = QHBoxLayout()
        top.addWidget(self.info, 1)
        top.addWidget(choose)
        top.addWidget(scan)
        root = QVBoxLayout(self)
        root.addLayout(top)
        root.addWidget(split, 1)
        choose.clicked.connect(self._choose)
        scan.clicked.connect(self.run)
        self.table.itemSelectionChanged.connect(self._show_selected)

    def _choose(self) -> None:
        if choose_rules(self):
            self.run()

    def run(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        rules = rules_setting()
        if not rules:
            self.info.setText("No YARA rules set. Choose a rules file or folder with <b>Rules…</b> "
                              "(or File → YARA rules…); the app doesn't include any.")
            return
        files = yara_adapter.rule_files(rules)
        if not files:
            self.info.setText(f"No .yar or .yara files found in {html.escape(rules)}.")
            return
        if not toolenv.provider("yara").available:
            self.info.setText(f"YARA isn't installed ({html.escape(edition.hint('yara'))}).")
            return
        self.info.setText(f"Scanning with {len(files)} rule file(s)…")
        self.ctx.runner.submit(yara_adapter.run, self._on_result, self._on_error,
                               sess.sample.work_path, sess.sample.family.name, files)

    def _on_error(self, message: str) -> None:
        self.info.setText(f"<b>YARA scan failed:</b> {html.escape(isolated.tidy(message))}")
        self.ctx.log(message)
        self.ctx.report_failure("yara", message)

    def _on_result(self, res: ToolResult) -> None:
        for cmd in (res.command or "").splitlines():
            self.ctx.log(cmd, command=True)
        d: yara_adapter.YaraData | None = res.data
        if not res.ok:
            self.info.setText(f"<b>YARA scan failed:</b> {html.escape(res.error)}")
            self.ctx.report_failure("yara", res.error)
            return
        rows = [[m.rule, m.where, m.found_by + (f" ({m.decoder})" if m.decoder else ""), " ".join(m.tags),
                 defang(m.strings[0]) if m.strings else ""] for m in d.matches]
        fill(self.table, rows or [["No rule matched.", "", "", "", ""]], data=list(d.matches) or None)
        rules = len({m.rule for m in d.matches})
        text = (f"{rules} rule(s) matched in {len(d.matches)} place(s)" if d.matches else "No rule matched") + \
               f" · {d.rule_files} rule file(s)"
        if d.notes:
            text += "<br>" + "<br>".join("Note: " + html.escape(n) for n in d.notes)
        self.info.setText(text)
        self.detail.clear()
        self.ctx.set_findings("yara", res.findings)

    def _show_selected(self) -> None:
        m = row_data(self.table)
        if not isinstance(m, yara_adapter.YaraMatch):
            return
        lines = [f"Rule: {m.rule}" + (f"   (namespace {m.namespace})" if m.namespace else ""),
                 f"Where: {m.where}", f"Found by: {m.found_by}" + (f", decoder {m.decoder}" if m.decoder else "")]
        if m.tags:
            lines.append("Tags: " + " ".join(m.tags))
        lines += [f"{k}: {v}" for k, v in m.meta.items()]
        if m.strings:
            lines += ["", "Matched text (offset, string id, bytes):"] + [defang(s) for s in m.strings]
        elif m.found_by != "yara":
            lines += ["", f"{m.found_by} reports the rule name only; the whole-file and ZIP-part scans "
                          "show the matched text."]
        self.detail.setPlainText("\n".join(lines))
