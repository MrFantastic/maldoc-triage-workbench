"""Streams tab: oledump stream browser with plugins, plus olemap/oledir."""
from __future__ import annotations

import html
import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QFileDialog, QLineEdit, QPushButton, QSplitter, QTabWidget,
                               QVBoxLayout, QWidget)

from .. import edition
from ..adapters import isolated
from ..adapters import oledump_adapter as od
from ..core.models import Severity, ToolResult
from ..core.safety import defang, safe_output_path
from .command_builder import CommandBuilder
from .common import banner, fill, flow, hbox, row_data, table, text_view, vbox_widget
from .context import Context
from .hex_view import HexPanel

MODES = [("Raw bytes (-d)", "raw"), ("VBA decompressed (-v)", "vba"), ("Strings (-S)", "strings"),
         ("Hex/ASCII dump (-x)", "hexdump"), ("Stream info (-i)", "info"), ("Plugin (-p)", "plugin")]


class StreamsView(QWidget):
    """The Streams tab: oledump's stream list and views, olemap and oledir."""
    SOURCES = ("oledump",)

    def __init__(self, ctx: Context, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.tool = od.locate()
        self.data: od.StreamList | None = None
        self.current_bytes = b""

        self.info = banner()
        refresh = QPushButton("Run oledump")
        self.table = table(["Index", "Flag", "Size", "Stream", "Meaning"], 3)

        self.mode = QComboBox()
        for label, key in MODES:
            self.mode.addItem(label, key)
        self.plugin = QComboBox()
        for p in od.list_plugins(self.tool):
            self.plugin.addItem(os.path.basename(p), p)
        self.plugin_opts = QLineEdit(placeholderText="--pluginoptions (e.g. -x for plugin_biff)")
        show = QPushButton("Show")
        save = QPushButton("Save stream…")
        analyze = QPushButton("Analyze as new sample")
        analyze.setToolTip("Write the raw stream to the output folder and open it as a child sample.")

        self.output = text_view()
        self.hex = HexPanel()
        self.out_tabs = QTabWidget()
        self.out_tabs.addTab(self.output, "Output")
        self.out_tabs.addTab(self.hex, "Hex (raw bytes)")

        self.adv_text = text_view()
        olemap = QPushButton("olemap")
        oledir = QPushButton("oledir")
        self.cli_args = QLineEdit(placeholderText="Any oledump.py arguments, e.g.  -s a -p plugin_vba_summary.py")
        cli_run = QPushButton("Run")

        right = vbox_widget(flow("View", self.mode, self.plugin, self.plugin_opts, show, save, analyze),
                            (self.out_tabs, 1))
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self.table)
        split.addWidget(right)
        split.setSizes([520, 700])

        adv = vbox_widget(hbox(olemap, oledir, None), hbox(self.cli_args, cli_run), (self.adv_text, 1))
        tabs = QTabWidget()
        tabs.addTab(split, "Streams")
        tabs.addTab(adv, "olemap / oledir")
        self.builder = CommandBuilder(ctx, ["oledump", "olemap", "oledir"], [
            ("List streams", "oledump", ""),
            ("Macro summary of all streams", "oledump", "-p plugin_vba_summary.py"),
            ("Decompress VBA in stream N (edit)", "oledump", "-s 8 -v"),
            ("Strings in stream N (edit)", "oledump", "-s 8 -S"),
            ("Info for stream N (edit)", "oledump", "-s 8 -i"),
            ("Excel 4.0 macros (plugin_biff -x)", "oledump", "-p plugin_biff.py --pluginoptions -x"),
            ("All BIFF records", "oledump", "-p plugin_biff.py"),
            ("Outlook .msg: list parts", "oledump", "-p plugin_msg.py"),
            ("URLs heuristics on all streams", "oledump", "-p plugin_http_heuristics.py"),
            ("Document metadata", "oledump", "-M"),
            ("Sector map", "olemap", ""), ("Directory entries", "oledir", ""),
        ])
        tabs.addTab(self.builder, "All options (command builder)")
        self.tabs = tabs

        root = QVBoxLayout(self)
        root.addLayout(hbox(self.info, refresh))
        root.addWidget(tabs, 1)

        refresh.clicked.connect(self.run)
        show.clicked.connect(self.show_stream)
        self.table.cellDoubleClicked.connect(lambda *_: self.show_stream())
        self.table.currentCellChanged.connect(lambda *_: self._sync_mode())
        self.mode.currentIndexChanged.connect(lambda *_: self._mode_changed())
        save.clicked.connect(self.save_stream)
        analyze.clicked.connect(self.analyze_stream)
        olemap.clicked.connect(lambda: self._advanced(od.run_olemap))
        oledir.clicked.connect(lambda: self._advanced(od.run_oledir))
        cli_run.clicked.connect(self.run_custom)
        self.cli_args.returnPressed.connect(self.run_custom)
        self._mode_changed()
        if not self.tool:
            self.info.setText(f"<b>oledump.py not found</b> ({html.escape(edition.hint('tools'))}, "
                              "or set MTW_OLEDUMP).")

    # ------------------------------------------------------------ run
    def run(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        if not self.tool:
            self.ctx.report_failure("oledump", f"oledump.py not found ({edition.hint('tools')})")
            return
        self.info.setText("Running oledump…")
        self.ctx.runner.submit(od.run_list, self._on_list, self._list_err, sess.sample.path)

    def _err(self, msg: str) -> None:
        self.info.setText(f"<b>Failed:</b> {html.escape(isolated.tidy(msg))}")
        self.ctx.log(msg)

    def _list_err(self, msg: str) -> None:
        self._err(msg)
        self.ctx.report_failure("oledump", msg)

    def _on_list(self, res: ToolResult) -> None:
        self.ctx.log(res.command, command=True)
        sl: od.StreamList = res.data
        self.data = sl
        if not res.ok:
            self.info.setText(f"<b>oledump failed:</b> {html.escape(res.error)}")
            self.ctx.report_failure("oledump", res.error)
            self.output.setPlainText(res.raw_output)
            return
        rows, colors = [], []
        for s in sl.streams:
            rows.append([s.index, s.indicator, f"{s.size:,}", s.name, s.meaning])
            colors.append(Severity.HIGH if s.indicator == "O" else Severity.MEDIUM if s.indicator == "M" else None)
        fill(self.table, rows, data=sl.streams, colors=colors)
        cont = (" · containers: " + html.escape(", ".join(f"{k} = {v}" for k, v in sl.containers.items()))
                if sl.containers else "")
        macros = sum(1 for s in sl.streams if s.indicator == "M")
        self.info.setText(f"{len(sl.streams)} streams · {macros} with VBA code{cont}. "
                          "Select a stream and choose a view.")
        if not sl.streams:
            self.output.setPlainText(res.raw_output or "oledump found no OLE streams in this file.")
        self.ctx.set_findings("oledump", res.findings)

    # ------------------------------------------------------------ stream actions
    def _sync_mode(self) -> None:
        s = row_data(self.table)
        if isinstance(s, od.Stream) and s.indicator in ("M", "m") and self.mode.currentData() == "raw":
            self.mode.setCurrentIndex(1)

    def _mode_changed(self) -> None:
        is_plugin = self.mode.currentData() == "plugin"
        self.plugin.setVisible(is_plugin)
        self.plugin_opts.setVisible(is_plugin)

    def show_stream(self) -> None:
        sess = self.ctx.session()
        s = row_data(self.table)
        if sess is None or not isinstance(s, od.Stream):
            return
        mode = self.mode.currentData()
        plugin = self.plugin.currentData() if mode == "plugin" else None
        if mode == "plugin" and not plugin:
            self.output.setPlainText(f"No oledump plugins found next to oledump.py ({edition.hint('tools')}).")
            return
        self.output.setPlainText("Running…")
        self.ctx.runner.submit(od.dump_stream, lambda r: self._on_dump(r, mode), self._err,
                               sess.sample.path, s.index, mode, plugin, self.plugin_opts.text().strip())

    def _on_dump(self, r, mode: str) -> None:
        self.ctx.log(r.command, command=True)
        if mode == "raw":
            self.current_bytes = r.stdout
            self.hex.set_data(r.stdout)
            self.out_tabs.setCurrentWidget(self.hex)
            text = r.stdout.decode("latin-1", "replace")
            printable = sum(32 <= ord(c) < 127 or c in "\r\n\t" for c in text[:4000])
            self.output.setPlainText(defang(text) if text and printable / max(1, min(len(text), 4000)) > 0.85
                                     else f"{len(r.stdout):,} bytes of binary data: see the Hex tab."
                                     + (f"\n\n{r.stderr}" if r.stderr.strip() else ""))
        else:
            # VBA source is shown exactly; other text output is defanged
            self.output.setPlainText(r.text if mode == "vba" else defang(r.text))
            self.out_tabs.setCurrentWidget(self.output)

    def _with_raw_selected(self, then) -> None:
        """Dump the selected stream with oledump (in the background), then call then(stream, bytes)."""
        s = row_data(self.table)
        sess = self.ctx.session()
        if sess is None or not isinstance(s, od.Stream):
            return

        def done(r):
            self.ctx.log(r.command, command=True)
            if r.timed_out or r.stopped or (r.returncode != 0 and not r.stdout):
                self._err(f"oledump could not dump stream {s.index}: {(r.stderr or 'no output').strip()}")
                return
            if r.truncated:
                self.ctx.log(f"⚠ Stream {s.index} was cut off at {len(r.stdout):,} bytes (output limit): "
                             "the saved copy is incomplete.")
            then(s, sess, r.stdout)
        self.ctx.runner.submit(od.dump_stream, done, self._err, sess.sample.path, s.index, "raw")

    def save_stream(self) -> None:
        def then(s, _sess, data):
            default = safe_output_path(self.ctx.output_dir(), f"{s.index}_{s.name.replace('/', '_')}")
            path, _ = QFileDialog.getSaveFileName(self, "Save stream", default, "Binary (*.bin)")
            if path:
                with open(path, "wb") as fh:
                    fh.write(data)
                self.ctx.add_artifact(path)
                self.ctx.log(f"Stream {s.index} saved to {path} ({len(data):,} bytes)")
        self._with_raw_selected(then)

    def analyze_stream(self) -> None:
        def then(s, sess, data):
            self.ctx.analyze_child_bytes(f"{s.index}_{s.name.split('/')[-1]}", data,
                                         f"stream {s.index} '{s.name}' of {sess.sample.name} "
                                         f"(SHA256 {sess.sample.sha256})")
        self._with_raw_selected(then)

    # ------------------------------------------------------------ Investigate steps
    def open_builder(self, args: str = "", run: bool = False, tool: str = "oledump") -> None:
        self.tabs.setCurrentWidget(self.builder)
        if args:
            self.builder.prefill(args, tool, run=run)

    def show_streams(self) -> None:
        self.tabs.setCurrentIndex(0)

    # ------------------------------------------------------------ advanced
    def _advanced(self, fn) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        self.adv_text.setPlainText("Running…")
        self.ctx.runner.submit(fn, self._on_adv, self._err, sess.sample.path)

    def run_custom(self) -> None:
        sess = self.ctx.session()
        text = self.cli_args.text().strip()
        if sess is None or not text:
            return
        import shlex
        try:
            args = shlex.split(text, posix=(os.name != "nt"))
        except ValueError as exc:
            self.adv_text.setPlainText(f"Could not parse arguments: {exc}")
            return
        self.adv_text.setPlainText("Running…")
        self.ctx.runner.submit(od.run_raw, self._on_adv, self._err, sess.sample.path, args)

    def _on_adv(self, r) -> None:
        self.ctx.log(r.command, command=True)
        self.adv_text.setPlainText(defang(r.text))
