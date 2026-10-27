"""Command builder: every option of a CLI tool as a form, generated from the
installed tool's own -h output, with a live command preview, the tool's manual,
and the output shown in the GUI. This is how the GUI reaches full CLI parity
while teaching the command line."""
from __future__ import annotations

import html
import os
import shlex

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QGridLayout, QGroupBox, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QScrollArea, QSplitter, QTabWidget, QToolButton,
                               QVBoxLayout, QWidget)

from ..adapters import clitools as ct
from ..core.safety import defang, quote_arg
from .common import banner, flow, text_view
from .context import Context
from .theme import apply_mono


class _OptionRow:
    def __init__(self, opt: ct.CliOption, on_change, browse_dir: str):
        self.opt = opt
        flags = ", ".join(f for f in (opt.short, opt.long) if f)
        self.check = QCheckBox(f"{opt.label}   {flags}" if opt.label and opt.label != opt.flag else flags)
        self.check.setToolTip(opt.help)
        self.value: QLineEdit | QComboBox | None = None
        self.browse: QToolButton | None = None
        if opt.takes_value:
            if opt.choices:
                self.value = QComboBox()
                self.value.addItems(opt.choices)
                self.value.currentIndexChanged.connect(lambda *_: self._touch(on_change))
            else:
                self.value = QLineEdit(placeholderText=opt.metavar)
                self.value.textEdited.connect(lambda *_: self._touch(on_change))
            if opt.wants_path:
                self.browse = QToolButton(text="…")
                self.browse.setToolTip("Choose a file or folder")
                self.browse.clicked.connect(lambda: self._pick(browse_dir, on_change))
        desc = opt.explain or opt.help
        if opt.explain and opt.help and opt.help not in opt.explain:
            desc = f"{opt.explain}<br><span style='color:gray'>{opt.help}</span>"
        self.help = QLabel(desc)
        self.help.setWordWrap(True)
        self.help.setTextFormat(Qt.TextFormat.RichText)
        self.help.setStyleSheet("color: palette(mid); margin-left: 22px;")
        self.check.toggled.connect(lambda *_: on_change())

    def _touch(self, on_change) -> None:
        if not self.check.isChecked():
            self.check.setChecked(True)   # typing a value enables the option
        on_change()

    def _pick(self, start: str, on_change) -> None:
        m = (self.opt.metavar + self.opt.flag).upper()
        if "DIR" in m:
            path = QFileDialog.getExistingDirectory(None, self.opt.label, start)
        elif any(k in m for k in ("DUMP", "OUTPUT", "LOG", "EXTRACT")):
            path, _ = QFileDialog.getSaveFileName(None, self.opt.label, os.path.join(start, "output.bin"))
        else:
            path, _ = QFileDialog.getOpenFileName(None, self.opt.label, start)
        if path and isinstance(self.value, QLineEdit):
            self.value.setText(path)
            self._touch(on_change)

    def get(self):
        if not self.check.isChecked():
            return None
        if self.value is None:
            return True
        return self.value.currentText() if isinstance(self.value, QComboBox) else self.value.text().strip()

    def set(self, v) -> None:
        self.check.setChecked(bool(v))
        if isinstance(v, str):
            if isinstance(self.value, QComboBox):
                self.value.setCurrentText(v)
            elif isinstance(self.value, QLineEdit):
                self.value.setText(v)

    def matches(self, q: str) -> bool:
        o = self.opt
        return not q or q in f"{o.short} {o.long} {o.label} {o.help} {o.explain}".lower()

    def set_visible(self, vis: bool) -> None:
        for w in (self.check, self.value, self.browse, self.help):
            if w is not None:
                w.setVisible(vis)


class CommandBuilder(QWidget):
    """tools: tool names from clitools.TOOLS. presets: [(label, tool, "args")]."""

    def __init__(self, ctx: Context, tools: list[str], presets: list[tuple[str, str, str]] | None = None,
                 on_output=None, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.tools = [t for t in tools if t in ct.TOOLS]
        self.rows: list[_OptionRow] = []
        self.on_output = on_output       # callback(tool, RunResult) for view-specific follow-ups
        self.loaded_tool = ""
        self.pending: tuple[str, str] | None = None
        self._run_after_load = False

        self.tool_box = QComboBox()
        for t in self.tools:
            self.tool_box.addItem(t, t)
        self.tool_box.setVisible(len(self.tools) > 1)
        self.blurb = banner()
        self.preset = QComboBox()
        self.preset.addItem("Recipes…", None)
        for label, tool, args in presets or []:
            self.preset.addItem(label, (tool, args))
        self.preset.setVisible(bool(presets))
        self.search = QLineEdit(placeholderText="Find an option…")
        manual_btn = QPushButton("Manual")
        manual_btn.setToolTip("Show the tool's own manual / help text")
        reset_btn = QPushButton("Clear")

        self.form_host = QWidget()
        self.form = QVBoxLayout(self.form_host)
        self.form.setAlignment(Qt.AlignmentFlag.AlignTop)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.form_host)

        self.extra = QLineEdit(placeholderText="Extra arguments (anything not in the form)")
        self.with_sample = QCheckBox("Append sample path")
        self.with_sample.setChecked(True)
        self.preview = QLineEdit(readOnly=True)
        apply_mono(self.preview)
        copy_btn = QPushButton("Copy command")
        run_btn = QPushButton("Run")
        run_btn.setDefault(True)
        self.defang_out = QCheckBox("Defang URLs in output")
        self.defang_out.setChecked(True)

        self.output = text_view()
        self.manual_view = text_view()
        self.out_tabs = QTabWidget()
        self.out_tabs.addTab(self.output, "Output")
        self.out_tabs.addTab(self.manual_view, "Manual / help")
        self.status = banner()

        top = QVBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.addWidget(flow(self.tool_box, self.preset, manual_btn, reset_btn))
        top.addWidget(self.search)
        cmd = QGridLayout()
        cmd.addWidget(QLabel("Command"), 0, 0)
        cmd.addWidget(self.preview, 0, 1)
        cmd.addWidget(copy_btn, 0, 2)
        cmd.addWidget(run_btn, 0, 3)
        cmd.addWidget(self.extra, 1, 1)
        opts_row = QHBoxLayout()
        opts_row.addWidget(self.with_sample)
        opts_row.addWidget(self.defang_out)
        opts_row.addStretch(1)
        cmd.addLayout(opts_row, 1, 2, 1, 2)

        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.addWidget(self.blurb)
        ll.addLayout(top)
        ll.addWidget(scroll, 1)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addWidget(self.status)
        rl.addWidget(self.out_tabs, 1)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([560, 640])

        root = QVBoxLayout(self)
        root.addLayout(cmd)
        root.addWidget(split, 1)

        self.tool_box.currentIndexChanged.connect(lambda *_: self.load_tool(self.tool_box.currentData()))
        self.preset.activated.connect(self._apply_preset)
        self.search.textChanged.connect(self._filter)
        manual_btn.clicked.connect(self.show_manual)
        reset_btn.clicked.connect(self.clear)
        self.extra.textEdited.connect(lambda *_: self._update())
        self.with_sample.toggled.connect(lambda *_: self._update())
        copy_btn.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.preview.text()))
        run_btn.clicked.connect(self.run)

    # ------------------------------------------------------------ loading
    def showEvent(self, e) -> None:
        super().showEvent(e)
        if not self.loaded_tool and self.tools:
            self.load_tool(self.tool_box.currentData() or self.tools[0])

    def current_tool(self) -> str:
        return self.loaded_tool or (self.tools[0] if self.tools else "")

    def load_tool(self, tool: str) -> None:
        if not tool:
            return
        t = ct.TOOLS[tool]
        self.loaded_tool = tool
        found = ct.available(tool)
        self.blurb.setText(f"<b>{tool}</b>: {t.blurb}" + ("" if found else
                           " <b style='color:#e5484d'>Not installed: see Help → Tool status.</b>"))
        self._clear_form()
        self.status.setText("Reading options from the tool's -h…")
        self.ctx.runner.submit(ct.load_help, lambda res: self._on_help(tool, res),
                               lambda m: self.status.setText("Could not read options: "
                                                             + html.escape((m.splitlines() or [""])[0])), tool)

    def _clear_form(self) -> None:
        while self.form.count():
            item = self.form.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.rows = []

    def _on_help(self, tool: str, res) -> None:
        if tool != self.loaded_tool:
            return
        opts, text = res
        self.manual_view.setPlainText(text)
        self._clear_form()
        if not opts:
            self.status.setText("No options could be read from this tool's help (see Manual / help). "
                                "Use the Extra arguments field.")
        groups: dict[str, QVBoxLayout] = {}
        for o in opts:
            if o.group not in groups:
                box = QGroupBox(o.group)
                groups[o.group] = QVBoxLayout(box)
                self.form.addWidget(box)
            row = _OptionRow(o, self._update, self.ctx.output_dir())
            line = QHBoxLayout()
            line.addWidget(row.check)
            if row.value is not None:
                line.addWidget(row.value, 1)
            if row.browse is not None:
                line.addWidget(row.browse)
            if row.value is None:
                line.addStretch(1)
            groups[o.group].addLayout(line)
            groups[o.group].addWidget(row.help)
            self.rows.append(row)
        if opts:
            self.status.setText(f"{len(opts)} options available. Tick the ones you want; the command "
                                "updates live. Hover an option for the tool's own description.")
        if self.pending and self.pending[0] == tool:
            self._prefill(self.pending[1])
            self.pending = None
        self._filter(self.search.text())
        self._update()

    # ------------------------------------------------------------ prefill / presets
    def prefill(self, args: str, tool: str | None = None, run: bool = False) -> None:
        tool = tool or self.current_tool()
        if tool != self.loaded_tool or not self.rows:
            self.pending = (tool, args)
            idx = self.tool_box.findData(tool)
            if idx >= 0 and idx != self.tool_box.currentIndex():
                self.tool_box.setCurrentIndex(idx)
            else:
                self.load_tool(tool)
            if run:
                self._run_after_load = True
            return
        self._prefill(args)
        if run:
            self.run()

    def _prefill(self, args: str) -> None:
        try:
            parts = shlex.split(args, posix=(os.name != "nt"))
        except ValueError:
            parts = args.split()
        values, extra = ct.args_to_values([r.opt for r in self.rows], parts)
        for r in self.rows:
            r.set(values.get(r.opt.flag, False))
        self.extra.setText(" ".join(extra))
        self._update()
        if getattr(self, "_run_after_load", False):
            self._run_after_load = False
            self.run()

    def _apply_preset(self, _i: int) -> None:
        data = self.preset.currentData()
        if data:
            tool, args = data
            self.prefill(args, tool)
            self.preset.setCurrentIndex(0)

    def clear(self) -> None:
        for r in self.rows:
            r.set(False)
        self.extra.clear()
        self._update()

    def _filter(self, text: str) -> None:
        q = text.strip().lower()
        for r in self.rows:
            r.set_visible(r.matches(q))

    # ------------------------------------------------------------ command
    def args(self, shown: bool = False) -> list[str]:
        """The arguments to run with (the sample's private copy), or with shown=True to display
        and copy (the original file)."""
        values = {r.opt.flag: r.get() for r in self.rows}
        out = ct.values_to_args([r.opt for r in self.rows], values)
        extra = self.extra.text().strip()
        if extra:
            try:
                out += shlex.split(extra, posix=(os.name != "nt"))
            except ValueError:
                out += extra.split()
        sess = self.ctx.session()
        if self.with_sample.isChecked() and sess is not None and ct.TOOLS[self.current_tool()].takes_sample:
            out.append(sess.sample.path if shown else sess.sample.work_path)
        return out

    def _update(self) -> None:
        tool = self.current_tool()
        name = ct.TOOLS[tool].target if ct.TOOLS.get(tool) and ct.TOOLS[tool].kind == "script" else tool
        self.preview.setText(name + " " + " ".join(quote_arg(a) for a in self.args(shown=True)))

    def run(self) -> None:
        tool = self.current_tool()
        if not tool:
            return
        args = self.args()
        self.output.setPlainText("Running…")
        self.out_tabs.setCurrentWidget(self.output)
        self.ctx.runner.submit(ct.run, lambda r: self._on_run(tool, r),
                               lambda m: self.output.setPlainText(m), tool, args)

    def _on_run(self, tool: str, r) -> None:
        self.ctx.log(r.command, command=True)
        text = r.stdout.decode("utf-8", "replace")
        if r.stderr.strip():
            text += ("\n" if text else "") + r.stderr
        if r.timed_out:
            text += "\n[stopped: timeout]"
        nonprint = sum(1 for c in text[:4000] if ord(c) < 9 or 13 < ord(c) < 32)
        if nonprint > 40:
            text = (f"[{len(r.stdout):,} bytes of binary output. Use a dump-to-file option, or the "
                    "tab's own Save/Analyze buttons, to work with binary data.]\n\n" + r.stderr)
        self.output.setPlainText(defang(text) if self.defang_out.isChecked() else text)
        self.status.setText(f"Exit code {r.returncode}" + (" (timed out)" if r.timed_out else ""))
        if self.on_output:
            self.on_output(tool, r)

    def show_manual(self) -> None:
        tool = self.current_tool()
        if not tool:
            return
        self.manual_view.setPlainText("Loading manual…")
        self.out_tabs.setCurrentWidget(self.manual_view)
        self.ctx.runner.submit(ct.manual, self.manual_view.setPlainText,
                               lambda m: self.manual_view.setPlainText(m), tool)
