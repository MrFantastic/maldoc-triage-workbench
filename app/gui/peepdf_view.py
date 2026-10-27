"""peepdf tab: JSON overview, scripted console, and the JS workbench."""
from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QFileDialog, QLineEdit, QPlainTextEdit, QPushButton, QSplitter,
                               QTabWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from .. import edition
from ..adapters import isolated
from ..adapters import peepdf_adapter as pe
from ..core.models import ToolResult
from ..core.safety import defang, safe_output_path
from .command_builder import CommandBuilder
from .common import banner, flow, hbox, text_view, vbox_widget, plain_tip
from .context import Context
from .hex_view import HexPanel
from .theme import apply_mono

CONSOLE_PRESETS = [
    "info", "tree", "offsets", "metadata", "changelog", "errors", "xref", "references to 1",
    "object 1", "stream 1", "rawstream 1", "js_code 1", "search unescape", "vtcheck",
]


class PeepdfView(QWidget):
    """The peepdf tab: JSON overview, scripted console and the JavaScript workbench."""
    SOURCES = ("peepdf",)

    def __init__(self, ctx: Context, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.available = pe.locate() is not None

        self.info = banner()
        run_btn = QPushButton("Run peepdf overview")

        # overview
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Key", "Value"])
        self.tree.setColumnWidth(0, 340)
        self.overview_raw = text_view()
        overview = QTabWidget()
        overview.addTab(self.tree, "Overview")
        overview.addTab(self.overview_raw, "Raw output")

        # console
        self.preset = QComboBox()
        self.preset.setEditable(False)
        self.preset.addItem("Presets…")
        self.preset.addItems(CONSOLE_PRESETS)
        self.cmd = QLineEdit(placeholderText="peepdf commands; separate several with ;   e.g.  info ; tree ; object 5")
        run_cmd = QPushButton("Run")
        self.console_out = text_view()
        note = banner("<span style='color:gray'>Commands run non-interactively (<code>peepdf -s</code>). "
                      "<code>vtcheck</code> sends only the hash to VirusTotal and needs network access; "
                      "editing commands (modify, save…) write to new files only. Commands that run code "
                      "(js_eval, js_analyse, js_vars, sctest) are disabled.</span>")
        console = vbox_widget(hbox(self.preset, self.cmd, run_cmd), note, (self.console_out, 1))

        # JS workbench
        self.js_in = QPlainTextEdit()
        apply_mono(self.js_in)
        self.js_in.setPlaceholderText("Paste JavaScript here, or use 'Send to JS workbench' in pdf-parser.\n"
                                      "Nothing here is ever executed.")
        self.js_out = text_view()
        self.js_hex = HexPanel()
        self.js_origin = banner("")
        beautify = QPushButton("Beautify")
        unescape = QPushButton("Unescape payload (%u, \\x, fromCharCode)")
        urls = QPushButton("Extract URLs")
        save = QPushButton("Save decoded bytes…")
        analyze = QPushButton("Analyze bytes as new sample")
        out_tabs = QTabWidget()
        out_tabs.addTab(self.js_out, "Result")
        out_tabs.addTab(self.js_hex, "Decoded bytes")
        self.js_tabs = out_tabs
        js_split = QSplitter(Qt.Orientation.Vertical)
        js_split.addWidget(self.js_in)
        js_split.addWidget(out_tabs)
        workbench = vbox_widget(self.js_origin, flow(beautify, unescape, urls, save, analyze), (js_split, 1))
        self.decoded = b""

        tabs = QTabWidget()
        tabs.addTab(overview, "Overview")
        tabs.addTab(console, "Console")
        tabs.addTab(workbench, "JS workbench")
        self.builder = CommandBuilder(ctx, ["peepdf"], [
            ("JSON overview (force + loose)", "peepdf", "-f -l -j"),
            ("Text overview", "peepdf", "-f -l -g")])
        tabs.addTab(self.builder, "All options (command builder)")
        self.tabs = tabs
        self.console_page = console
        self.workbench = workbench

        root = QVBoxLayout(self)
        root.addLayout(hbox(self.info, run_btn))
        root.addWidget(tabs, 1)

        run_btn.clicked.connect(self.run)
        self.preset.activated.connect(self._preset)
        run_cmd.clicked.connect(self.run_console)
        self.cmd.returnPressed.connect(self.run_console)
        beautify.clicked.connect(self._beautify)
        unescape.clicked.connect(self._unescape)
        urls.clicked.connect(self._urls)
        save.clicked.connect(self._save)
        analyze.clicked.connect(self._analyze)

        if not self.available:
            self.info.setText("<b>peepdf is not installed.</b> The JS workbench works without it. To enable "
                              f"the overview and console: {html.escape(edition.hint('peepdf'))} "
                              "(GPLv3), or use REMnux where it's on PATH.")
            run_btn.setEnabled(False)
            run_cmd.setEnabled(False)
            tabs.setCurrentWidget(workbench)
        else:
            self.info.setText("peepdf found. The overview runs on demand because it can be slow on large files.")

    # ------------------------------------------------------------ overview
    def run(self) -> None:
        sess = self.ctx.session()
        if sess is None or not self.available:
            return
        self.info.setText("Running peepdf…")
        self.ctx.runner.submit(pe.overview, self._on_overview, self._overview_err, sess.sample.work_path)

    def _err(self, msg: str) -> None:
        self.info.setText(f"<b>Failed:</b> {html.escape(isolated.tidy(msg))}")
        self.ctx.log(msg)

    def _overview_err(self, msg: str) -> None:
        self._err(msg)
        self.ctx.report_failure("peepdf", msg)

    def _on_overview(self, res: ToolResult) -> None:
        self.ctx.log(res.command, command=True)
        self.overview_raw.setPlainText(defang(res.raw_output))
        self.tree.clear()
        if not res.ok:
            self.info.setText(f"<b>peepdf did not return JSON:</b> see Raw output. "
                              f"{html.escape(defang(res.error[:200]))}")
            self.ctx.report_failure("peepdf", res.error or "peepdf did not return JSON")
            return
        self._add(self.tree.invisibleRootItem(), "peepdf", res.data)
        self.tree.expandToDepth(6)
        self.info.setText(f"peepdf overview loaded · {len(res.findings)} suspicious / vulnerable element(s).")
        self.ctx.set_findings("peepdf", res.findings)
        self.ctx.set_iocs("peepdf", pe.urls_from(res.data))

    def _add(self, parent: QTreeWidgetItem, key: str, value) -> None:
        if isinstance(value, dict):
            item = QTreeWidgetItem([str(key), f"{{{len(value)}}}"])
            parent.addChild(item)
            for k, v in value.items():
                self._add(item, k, v)
        elif isinstance(value, list):
            simple = all(not isinstance(v, (dict, list)) for v in value)
            if simple and len(value) <= 20:
                item = QTreeWidgetItem([str(key), defang(", ".join(map(str, value)))])
                parent.addChild(item)
            else:
                item = QTreeWidgetItem([str(key), f"[{len(value)}]"])
                parent.addChild(item)
                for i, v in enumerate(value):
                    self._add(item, f"[{i}]", v)
        else:
            item = QTreeWidgetItem([str(key), defang(str(value))])
            item.setToolTip(1, plain_tip(defang(str(value))))
            parent.addChild(item)
        low = str(key).lower()
        if any(w in low for w in ("vuln", "suspicious", "js", "url")):
            f = item.font(0)
            f.setBold(True)
            item.setFont(0, f)

    # ------------------------------------------------------------ console
    def console_command(self, cmd: str) -> None:
        self.tabs.setCurrentWidget(self.console_page)
        self.cmd.setText(cmd)
        self.run_console()

    def show_overview(self) -> None:
        self.tabs.setCurrentIndex(0)
        if self.available and self.tree.topLevelItemCount() == 0:
            self.run()

    def _preset(self, idx: int) -> None:
        if idx > 0:
            self.cmd.setText(self.preset.currentText())
            self.run_console()

    def run_console(self) -> None:
        sess = self.ctx.session()
        text = self.cmd.text().strip()
        if sess is None or not text or not self.available:
            return
        commands = [c.strip() for c in text.split(";") if c.strip()]
        self.console_out.setPlainText("Running…")
        self.ctx.runner.submit(pe.console, self._on_console, self._err, sess.sample.work_path, commands)

    def _on_console(self, r) -> None:
        if r.returncode == 126:          # refused before running
            self.console_out.setPlainText(r.stderr)
            return
        self.ctx.log(r.command, command=True)
        self.console_out.setPlainText(defang(r.text))

    # ------------------------------------------------------------ JS workbench
    def load_js(self, code: str, origin: str) -> None:
        self.tabs.setCurrentWidget(self.workbench)
        self.js_in.setPlainText(code)
        self.js_origin.setText(f"Loaded from <b>{html.escape(origin)}</b>. Shown as text only.")
        self._beautify()

    def _beautify(self) -> None:
        """jsbeautifier on hostile code can be slow or blow up, so it runs in a worker process."""
        code = self.js_in.toPlainText()
        if not code.strip():
            return
        self.js_out.setPlainText("Beautifying…")
        self.js_tabs.setCurrentWidget(self.js_out)
        self.ctx.runner.submit(isolated.beautify, self._on_beautified, self._beautify_failed, code)

    def _on_beautified(self, result) -> None:
        code, engine = result
        self.js_out.setPlainText(code)
        self.js_tabs.setCurrentWidget(self.js_out)
        self.ctx.log(f"JS beautified ({engine})")

    def _beautify_failed(self, msg: str) -> None:
        self.js_out.setPlainText(f"Beautify failed: {(msg.splitlines() or [''])[0]}\n\nThe original is unchanged "
                                 "in the editor above.")

    def _unescape(self) -> None:
        cursor = self.js_in.textCursor()
        text = cursor.selectedText() or self.js_in.toPlainText()
        self.decoded = pe.unescape_payload(text)
        self.js_hex.set_data(self.decoded)
        if not self.decoded:
            self.js_out.setPlainText("No %u / \\u / \\x / %HH / fromCharCode payload found "
                                     "(select the encoded string first to decode just that part).")
            self.js_tabs.setCurrentWidget(self.js_out)
            return
        from ..adapters.scripts import magic_type
        kind = magic_type(self.decoded)
        nops = self.decoded.count(b"\x90")
        self.js_out.setPlainText(
            f"Decoded {len(self.decoded):,} bytes · looks like: {kind}"
            + (f" · {nops} NOP (0x90) bytes, typical of a heap spray / shellcode" if nops > 16 else "")
            + "\n\nPrintable preview:\n" + defang(self.decoded[:4000].decode("latin-1")))
        self.js_tabs.setCurrentWidget(self.js_hex)

    def _urls(self) -> None:
        found = pe.urls_in(self.js_in.toPlainText() + "\n" + self.decoded.decode("latin-1"))
        self.js_out.setPlainText("\n".join(defang(u) for u in found) or "No URLs found.")
        self.js_tabs.setCurrentWidget(self.js_out)
        if found:
            self.ctx.set_iocs("js-workbench", found)

    def _save(self) -> None:
        if not self.decoded:
            return
        default = safe_output_path(self.ctx.output_dir(), "js_payload")
        path, _ = QFileDialog.getSaveFileName(self, "Save decoded bytes", default, "Binary (*.bin)")
        if path:
            with open(path, "wb") as fh:
                fh.write(self.decoded)
            self.ctx.add_artifact(path)
            self.ctx.log(f"Decoded JS payload saved to {path}")

    def _analyze(self) -> None:
        sess = self.ctx.session()
        if not self.decoded or sess is None:
            return
        self.ctx.analyze_child_bytes("js_payload", self.decoded,
                                     f"payload decoded from JavaScript in {sess.sample.name} "
                                     f"(SHA256 {sess.sample.sha256})")
