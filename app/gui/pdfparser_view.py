"""pdf-parser module: guided triggers & actions view, object explorer with
clickable references, stream decoding, and the full pdf-parser command builder."""
from __future__ import annotations

import html
import re

from PySide6.QtCore import Qt, QUrl
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QLineEdit, QListWidget, QPushButton,
                               QSplitter, QTabWidget, QTextBrowser, QVBoxLayout, QWidget)

from .. import edition
from ..adapters import isolated
from ..adapters import pdfparser_adapter as pp
from ..core.models import Severity, ToolResult
from ..core.safety import defang, safe_output_path
from .command_builder import CommandBuilder
from .common import banner, fill, flow, hbox, row_data, table, text_view, vbox_widget
from .context import Context
from .hex_view import HexPanel
from .theme import apply_mono

RECIPES = [
    ("Statistics: what kinds of objects, which are suspicious", "pdf-parser", "-a -O"),
    ("Find auto-actions (/AA)", "pdf-parser", "-O -s /AA"),
    ("Find open action (/OpenAction)", "pdf-parser", "-O -s /OpenAction"),
    ("Find JavaScript actions", "pdf-parser", "-O -s /JavaScript"),
    ("Find links (/URI)", "pdf-parser", "-O -s /URI"),
    ("Find launch actions", "pdf-parser", "-O -s /Launch"),
    ("Find embedded files", "pdf-parser", "-O -s /EmbeddedFile"),
    ("Who references object N? (edit the number)", "pdf-parser", "-O -r 1"),
    ("Decode object N's stream (edit the number)", "pdf-parser", "-O -o 1 -f"),
    ("Search inside decoded streams for 'eval'", "pdf-parser", "-O -f --searchstream=eval"),
    ("Search inside decoded streams for 'unescape'", "pdf-parser", "-O -f --searchstream=unescape"),
    ("Value of every /JS key", "pdf-parser", "-O -k /JS"),
    ("Value of every /URI key", "pdf-parser", "-O -k /URI"),
    ("Trailer and xref", "pdf-parser", "-e t"),
    ("Hash every stream", "pdf-parser", "-O -H"),
]
_REF_HTML = re.compile(r"(\d+) (\d+) R")


class PdfParserView(QWidget):
    """The pdf-parser tab: object explorer, triggers, streams, search and console."""
    SOURCES = ("pdf-parser",)

    def __init__(self, ctx: Context, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.pdf: pp.ParsedPdf | None = None
        self.stream_data = b""
        self.id_filter: set[int] | None = None
        self.last_ids: list[int] = []

        self.info = banner()
        rerun = QPushButton("Re-parse")
        self.decrypt_btn = QPushButton("Decrypt PDF (open a readable copy)")
        self.decrypt_btn.setToolTip("Encrypted PDFs hide their strings and streams from pdf-parser. This writes "
                                    "a decrypted copy (.bin) to the output folder and opens it as a new sample.")
        self.decrypt_btn.setVisible(False)

        # ---- triggers & actions ------------------------------------------------
        self.trig_help = banner(
            "Everything that runs <b>automatically or on interaction</b>, traced from the trigger to what it "
            "does. Start with <b style='color:#e5484d'>High</b> rows. Double-click a row to open the payload "
            "object (JavaScript is decoded for you).")
        self.triggers = table(["Severity", "Source", "Event", "When it fires", "Action", "Does", "Payload", "Note"], 5)
        self.triggers.setToolTip("Double-click to open the payload or action object.")
        open_payload = QPushButton("Open payload")
        to_js_btn = QPushButton("Open payload in JS workbench")
        trig_page = vbox_widget(self.trig_help, flow(open_payload, to_js_btn), (self.triggers, 1))

        # ---- object explorer ---------------------------------------------------
        self.filter = QLineEdit(placeholderText="Filter objects: id, /Type or any text in the dictionary")
        self.only_flagged = QCheckBox("Only suspicious")
        self.types = QComboBox()
        self.id_banner = banner()
        self.clear_ids = QPushButton("Show all objects")
        self.clear_ids.setVisible(False)
        self.objects = table(["Obj", "Type", "Stream", "Flags", "Refs → / ←"], 3)

        self.dict_view = QTextBrowser()
        self.dict_view.setOpenLinks(False)
        apply_mono(self.dict_view)
        self.dict_hint = banner("<span style='color:gray'>Blue <u>N 0 R</u> references are clickable: "
                                "follow them to see what an action points to.</span>")
        self.stream_text = text_view()
        self.stream_hex = HexPanel()
        self.filtered = QCheckBox("Apply filters (-f)")
        self.filtered.setChecked(True)
        load_stream = QPushButton("Decode stream")
        save_stream = QPushButton("Save stream…")
        to_js = QPushButton("Send to JS workbench")
        analyze = QPushButton("Analyze stream as new sample")
        self.refs_to = QListWidget()
        self.refs_from = QListWidget()
        refs_page = QSplitter(Qt.Orientation.Horizontal)
        refs_page.addWidget(vbox_widget(banner("<b>References</b> (this object → )"), (self.refs_to, 1)))
        refs_page.addWidget(vbox_widget(banner("<b>Referenced by</b> ( → this object): who triggers it"),
                                        (self.refs_from, 1)))

        self.detail = QTabWidget()
        self.detail.addTab(vbox_widget(self.dict_hint, (self.dict_view, 1)), "Dictionary")
        self.detail.addTab(vbox_widget(flow(self.filtered, load_stream, to_js, analyze, save_stream),
                                       (self.stream_text, 1)), "Stream (text)")
        self.detail.addTab(self.stream_hex, "Stream (hex)")
        self.detail.addTab(refs_page, "References")

        left = vbox_widget(hbox(self.filter, self.types, self.only_flagged),
                           hbox(self.id_banner, self.clear_ids), (self.objects, 1))
        explorer = QSplitter(Qt.Orientation.Horizontal)
        explorer.addWidget(left)
        explorer.addWidget(self.detail)
        explorer.setSizes([560, 700])

        # ---- command builder -----------------------------------------------------
        self.show_ids_btn = QPushButton("Show matching objects in the Objects tab")
        self.show_ids_btn.setEnabled(False)
        self.builder = CommandBuilder(ctx, ["pdf-parser"], RECIPES, on_output=self._builder_output)
        builder_page = vbox_widget(flow(self.show_ids_btn), (self.builder, 1))

        self.raw = text_view()
        self.trailer = text_view()
        tabs = QTabWidget()
        tabs.addTab(trig_page, "Triggers && actions")
        tabs.addTab(explorer, "Objects")
        tabs.addTab(builder_page, "All options (command builder)")
        tabs.addTab(self.trailer, "Trailers")
        tabs.addTab(self.raw, "Raw listing (-O)")
        self.tabs = tabs
        self.trig_page, self.explorer, self.builder_page = trig_page, explorer, builder_page

        root = QVBoxLayout(self)
        root.addLayout(hbox(self.info, self.decrypt_btn, rerun))
        root.addWidget(tabs, 1)

        rerun.clicked.connect(self.run)
        self.decrypt_btn.clicked.connect(lambda: self.ctx.run_action("pdf.decrypt"))
        self.triggers.cellDoubleClicked.connect(lambda r, _c: self._open_trigger(r))
        open_payload.clicked.connect(lambda: self._open_trigger(self.triggers.currentRow()))
        to_js_btn.clicked.connect(lambda: self._open_trigger(self.triggers.currentRow(), to_js=True))
        self.filter.textChanged.connect(lambda *_: self._fill_objects())
        self.types.currentIndexChanged.connect(lambda *_: self._fill_objects())
        self.only_flagged.toggled.connect(lambda *_: self._fill_objects())
        self.clear_ids.clicked.connect(lambda: self.set_id_filter(None))
        self.objects.currentCellChanged.connect(lambda *_: self._show_object())
        self.dict_view.anchorClicked.connect(self._on_link)
        load_stream.clicked.connect(self.decode_stream)
        self.filtered.toggled.connect(lambda *_: self.decode_stream())
        save_stream.clicked.connect(self.save_stream)
        to_js.clicked.connect(self.send_js)
        analyze.clicked.connect(self.analyze_stream)
        self.refs_to.itemDoubleClicked.connect(lambda it: self.select_object(int(it.data(Qt.ItemDataRole.UserRole))))
        self.refs_from.itemDoubleClicked.connect(lambda it: self.select_object(int(it.data(Qt.ItemDataRole.UserRole))))
        self.show_ids_btn.clicked.connect(lambda: self.set_id_filter(set(self.last_ids), "command builder result"))
        if not pp.locate():
            self.info.setText(f"<b>pdf-parser.py not found</b> ({html.escape(edition.hint('tools'))}).")

    # ================================================================ parsing
    def run(self) -> None:
        sess = self.ctx.session()
        if sess is None:
            return
        if not pp.locate():
            self.ctx.report_failure("pdf-parser", f"pdf-parser.py not found ({edition.hint('tools')})")
            return
        self.info.setText("Parsing with pdf-parser…")
        self.ctx.runner.submit(pp.run_full, self._on_full, self._err, sess.sample.work_path)

    def _err(self, msg: str) -> None:
        self.info.setText(f"<b>Failed:</b> {html.escape(isolated.tidy(msg))}")
        self.ctx.log(msg)
        if self.pdf is None:
            self.ctx.report_failure("pdf-parser", msg)

    def _on_full(self, res: ToolResult) -> None:
        self.ctx.log(res.command, command=True)
        self.raw.setPlainText(res.raw_output)
        if not res.ok:
            self.info.setText(f"<b>pdf-parser failed:</b> {html.escape(res.error)}")
            self.ctx.report_failure("pdf-parser", res.error)
            return
        self.pdf = res.data
        pdf = self.pdf
        types = sorted({o.type for o in pdf.objects if o.type})
        self.types.blockSignals(True)
        self.types.clear()
        self.types.addItem("All types", "")
        for t in types:
            self.types.addItem(t, t)
        self.types.blockSignals(False)
        flagged = sum(1 for o in pdf.objects if o.flags)
        high = sum(1 for t in pdf.triggers if t.severity >= Severity.HIGH)
        self.info.setText(f"{len(pdf.objects)} objects · {flagged} with suspicious names · "
                          f"{len(pdf.triggers)} trigger(s), <b>{high} high-risk</b> · {len(pdf.uris)} URI(s)"
                          + (" · <b style='color:#e5484d'>encrypted: strings and streams are unreadable "
                             "here</b>" if pdf.encrypted else ""))
        self.decrypt_btn.setVisible(pdf.encrypted)
        self.trailer.setPlainText("\n\n".join(pdf.trailers) or "No trailer found (cross-reference stream?).")
        self._fill_triggers()
        self._fill_objects()
        self.ctx.set_facts("pdf-parser", pp.facts(pdf))
        self.ctx.set_findings("pdf-parser", res.findings)
        self.ctx.set_iocs("pdf-parser", pp.iocs(pdf))

    # ================================================================ triggers
    def _fill_triggers(self) -> None:
        trig = self.pdf.triggers if self.pdf else []
        rows, colors = [], []
        for t in trig:
            payload = (f"obj {t.payload_obj}" if t.payload_obj is not None else
                       f"obj {t.action_obj}" if t.action_obj is not None else "inline")
            rows.append([t.severity.label, f"{t.source_kind} obj {t.source}", t.event, t.when,
                         t.action_type, defang(t.target)[:200], payload, t.note])
            colors.append(t.severity)
        if not rows:
            rows = [["", "", "", "No triggers or actions found.", "", "Nothing in this PDF runs automatically "
                     "or on click via /OpenAction, /AA or /A.", "", ""]]
            colors = [None]
            fill(self.triggers, rows, colors=colors)
            return
        fill(self.triggers, rows, data=trig, colors=colors)
        self.tabs.setTabText(0, f"Triggers && actions ({len(trig)})")

    def show_triggers(self) -> None:
        self.tabs.setCurrentWidget(self.trig_page)
        if self.triggers.rowCount() and row_data(self.triggers, 0) is not None:
            self.triggers.selectRow(0)

    def _open_trigger(self, row: int, to_js: bool = False) -> None:
        t = row_data(self.triggers, row)
        if not isinstance(t, pp.Trigger):
            return
        oid = t.payload_obj if t.payload_obj is not None else (t.action_obj if t.action_obj is not None else t.source)
        if to_js:
            self.send_object_js(t.action_obj if t.action_obj is not None else oid)
            return
        self.select_object(oid)
        o = self._current()
        if o is not None and o.has_stream:
            self.detail.setCurrentIndex(1)
            self.decode_stream()

    # ================================================================ objects
    def set_id_filter(self, ids: set[int] | None, why: str = "") -> None:
        self.id_filter = ids
        if ids is None:
            self.id_banner.setText("")
            self.clear_ids.setVisible(False)
        else:
            self.id_banner.setText(f"<b>Showing {len(ids)} object(s)</b> from {html.escape(why)}")
            self.clear_ids.setVisible(True)
            self.tabs.setCurrentWidget(self.explorer)
        self._fill_objects()
        if ids:
            self.objects.selectRow(0)

    def search_and_show(self, term: str) -> None:
        """pdf-parser -O -s TERM, then show the matching objects (the GUI version of the search)."""
        sess = self.ctx.session()
        if sess is None:
            return
        self.tabs.setCurrentWidget(self.explorer)
        self.id_banner.setText(f"Searching for {html.escape(term)}…")

        def done(r):
            self.ctx.log(r.command, command=True)
            ids = pp.search_ids(r.stdout.decode("latin-1", "replace"))
            if not ids and self.pdf:   # fall back to the parsed listing (e.g. obfuscated names)
                ids = [o.id for o in self.pdf.objects if term.lower() in o.text.lower()]
            self.set_id_filter(set(ids), f"pdf-parser -O -s {term}")
            if not ids:
                self.id_banner.setText(f"No objects contain {html.escape(term)} (it may be inside an "
                                       "encrypted or compressed stream).")
        self.ctx.runner.submit(pp.run_args, done, self._err, sess.sample.work_path, ["-O", "-s", term])

    def _fill_objects(self) -> None:
        if not self.pdf:
            return
        q = self.filter.text().strip().lower()
        want_type = self.types.currentData() or ""
        rows, data, colors = [], [], []
        hi = {"/JS", "/JavaScript", "/Launch", "/EmbeddedFile", "/XFA", "/RichMedia", "/JBIG2Decode"}
        for o in self.pdf.objects:
            if self.id_filter is not None and o.id not in self.id_filter:
                continue
            if want_type and o.type != want_type:
                continue
            if self.only_flagged.isChecked() and not o.flags:
                continue
            if q and not (q == str(o.id) or q in o.type.lower() or q in o.text.lower()):
                continue
            flags = o.flags
            rows.append([o.id, o.type or "—", "yes" if o.has_stream else "", " ".join(flags),
                         f"{len(o.references)} / {len(o.referenced_by)}"])
            data.append(o)
            colors.append(Severity.HIGH if hi & set(flags) else Severity.MEDIUM if flags else None)
        fill(self.objects, rows, data=data, colors=colors)

    def select_object(self, oid: int) -> None:
        self.tabs.setCurrentWidget(self.explorer)
        if self.id_filter is not None and oid not in self.id_filter:
            self.set_id_filter(None)
        if self.filter.text() or self.types.currentIndex() or self.only_flagged.isChecked():
            self.filter.clear()
            self.types.setCurrentIndex(0)
            self.only_flagged.setChecked(False)
        for r in range(self.objects.rowCount()):
            o = row_data(self.objects, r)
            if isinstance(o, pp.PdfObject) and o.id == oid:
                self.objects.selectRow(r)
                self.objects.scrollToItem(self.objects.item(r, 0))
                return
        self.ctx.log(f"obj {oid} is not in the parsed listing (it may be inside a stream that "
                     "pdf-parser couldn't expand).")

    def open_and_decode(self, oid: int) -> None:
        self.select_object(oid)
        o = self._current()
        if o is not None and o.has_stream:
            self.detail.setCurrentIndex(1)
            self.decode_stream()

    def _current(self) -> pp.PdfObject | None:
        o = row_data(self.objects)
        return o if isinstance(o, pp.PdfObject) else None

    def _dict_html(self, o: pp.PdfObject) -> str:
        esc = html.escape(o.text)
        linked = _REF_HTML.sub(lambda m: f'<a href="obj:{m.group(1)}">{m.group(1)} {m.group(2)} R</a>', esc)
        for name in o.flags:
            linked = re.sub(re.escape(html.escape(name)) + r"(?![A-Za-z])",
                            f"<b style='color:#e5484d'>{html.escape(name)}</b>", linked)
        head = (f"<b>obj {o.id} {o.gen}</b>  Type: {html.escape(o.type or '—')}"
                + (f"  (inside {html.escape(o.in_objstm)})" if o.in_objstm else "")
                + (f"<br>Suspicious names: <b style='color:#e5484d'>{' '.join(map(html.escape, o.flags))}</b>"
                   if o.flags else ""))
        if o.referenced_by:
            head += "<br>Referenced by: " + ", ".join(f'<a href="obj:{i}">obj {i}</a>' for i in o.referenced_by)
        return f"<pre style='white-space:pre-wrap'>{head}\n\n{linked}</pre>"

    def _on_link(self, url: QUrl) -> None:
        s = url.toString()
        if s.startswith("obj:"):
            self.select_object(int(s[4:]))

    def _show_object(self) -> None:
        o = self._current()
        if o is None:
            return
        self.dict_view.setHtml(self._dict_html(o))
        self.refs_to.clear()
        self.refs_from.clear()
        for lst, ids in ((self.refs_to, o.references), (self.refs_from, o.referenced_by)):
            for i in ids:
                tgt = self.pdf.by_id(i) if self.pdf else None
                lst.addItem(f"obj {i}  {tgt.type if tgt else ''}  {' '.join(tgt.flags) if tgt else ''}")
                lst.item(lst.count() - 1).setData(Qt.ItemDataRole.UserRole, i)
        self.stream_text.setPlainText("Press 'Decode stream' to extract it with pdf-parser."
                                      if o.has_stream else "This object has no stream.")
        self.stream_hex.set_data(b"")
        self.stream_data = b""

    # ================================================================ streams
    def decode_stream(self, then_js: bool = False) -> None:
        o = self._current()
        sess = self.ctx.session()
        if o is None or sess is None or not o.has_stream:
            return
        self.stream_text.setPlainText("Decoding…")
        self.ctx.runner.submit(pp.stream_bytes, lambda res: self._on_stream(res, o.id, then_js), self._err,
                               sess.sample.work_path, o.id, self.filtered.isChecked(), bool(o.in_objstm))

    def _on_stream(self, result, oid: int, then_js: bool = False) -> None:
        data, cmd, err = result
        if cmd:
            self.ctx.log(cmd, command=True)
        self.stream_data = data
        self.stream_hex.set_data(data)
        if not data:
            self.stream_text.setPlainText(err)
            return
        text = data[:4_000_000].decode("latin-1")
        printable = sum(32 <= ord(c) < 127 or c in "\r\n\t" for c in text[:4000])
        if printable / max(1, min(len(text), 4000)) > 0.8:
            self.stream_text.setPlainText(text)
            if then_js:
                self.ctx.send_to_js(text, f"pdf-parser obj {oid}")
        else:
            if then_js:
                self.ctx.log(f"obj {oid}'s stream isn't text, so it wasn't sent to the JS workbench.")
            self.stream_text.setPlainText(f"{len(data):,} bytes of binary data (see Stream (hex)). "
                                          + ("Try enabling 'Apply filters'." if not self.filtered.isChecked()
                                             else "If this is an embedded file, use 'Analyze stream as new sample'."))
            self.detail.setCurrentIndex(2)

    def save_stream(self) -> None:
        o = self._current()
        if o is None or not self.stream_data:
            return
        default = safe_output_path(self.ctx.output_dir(), f"obj{o.id}_stream")
        path, _ = QFileDialog.getSaveFileName(self, "Save stream", default, "Binary (*.bin)")
        if path:
            with open(path, "wb") as fh:
                fh.write(self.stream_data)
            self.ctx.add_artifact(path)
            self.ctx.log(f"Stream of obj {o.id} saved to {path}")

    def send_js(self) -> None:
        """'Send to JS workbench' button: the decoded stream if one is shown, else the object's /JS."""
        o = self._current()
        if o is None:
            return
        if self.stream_data:
            self.ctx.send_to_js(self.stream_data.decode("latin-1"), f"pdf-parser obj {o.id} (decoded stream)")
            return
        self.send_object_js(o.id)

    def send_object_js(self, oid: int) -> None:
        """Find the JavaScript behind an object (inline /JS, a /JS stream, or an action it points to)
        and load it into the JS workbench."""
        if not self.pdf:
            self.ctx.log("pdf-parser hasn't finished parsing yet.")
            return
        kind, ref = pp.js_source(self.pdf, oid)
        if kind == "inline":
            self.ctx.send_to_js(str(ref), f"inline JavaScript in obj {oid}")
        elif kind == "stream":
            self.select_object(int(ref))
            self.detail.setCurrentIndex(1)
            self.ctx.log(f"Decoding obj {ref} for the JS workbench")
            self.decode_stream(then_js=True)
        else:
            self.ctx.log(f"obj {oid} has no JavaScript (/JS) to send. Select an object flagged /JS.")

    def current_object_id(self) -> int | None:
        o = self._current()
        return o.id if o is not None else None

    def analyze_stream(self) -> None:
        o = self._current()
        sess = self.ctx.session()
        if o is None or sess is None or not self.stream_data:
            return
        self.ctx.analyze_child_bytes(f"obj{o.id}_stream", self.stream_data,
                                     f"stream of obj {o.id} in {sess.sample.name} (SHA256 {sess.sample.sha256})")

    # ================================================================ builder
    def open_builder(self, args: str = "", run: bool = False) -> None:
        self.tabs.setCurrentWidget(self.builder_page)
        if args:
            self.builder.prefill(args, "pdf-parser", run=run)

    def _builder_output(self, _tool: str, r) -> None:
        self.last_ids = pp.search_ids(r.stdout.decode("latin-1", "replace"))
        self.show_ids_btn.setEnabled(bool(self.last_ids))
        self.show_ids_btn.setText(f"Show the {len(self.last_ids)} matching object(s) in the Objects tab"
                                  if self.last_ids else "Show matching objects in the Objects tab")
