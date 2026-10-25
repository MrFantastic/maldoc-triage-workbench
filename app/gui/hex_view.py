"""Read-only hex viewer that paints only the visible rows (fine for 100+ MB files)."""
from __future__ import annotations

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QFontDatabase, QFontMetrics, QGuiApplication, QKeySequence, QPainter
from PySide6.QtWidgets import (QAbstractScrollArea, QComboBox, QHBoxLayout, QLabel, QLineEdit,
                               QPushButton, QVBoxLayout, QWidget)

BPR = 16  # bytes per row
_PRINTABLE = bytes(range(0x20, 0x7F))
_ASCII_TABLE = "".join(chr(b) if b in _PRINTABLE else "." for b in range(256))
_TRANS = str.maketrans({chr(i): _ASCII_TABLE[i] for i in range(256)})


class HexView(QAbstractScrollArea):
    """Hex and ASCII view of the sample's bytes, with selection."""
    selection_changed = Signal(int, int)  # start, length

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        font.setPointSize(max(font.pointSize(), 10))
        self.setFont(font)
        self._data = b""
        self._anchor = -1
        self._sel = (-1, -1)  # inclusive start, exclusive end
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.viewport().setCursor(Qt.CursorShape.IBeamCursor)

    # ---------------------------------------------------------------- geometry
    def _metrics(self):
        fm = QFontMetrics(self.font())
        cw = fm.horizontalAdvance("0")
        lh = fm.height() + 2
        margin = 6
        hex_x = margin + 10 * cw
        ascii_x = hex_x + (BPR * 3 + 2) * cw
        return fm, cw, lh, margin, hex_x, ascii_x

    def _byte_x(self, i: int, cw: int, hex_x: int) -> int:
        return hex_x + (i * 3 + (1 if i >= 8 else 0)) * cw

    def _rows(self) -> int:
        return (len(self._data) + BPR - 1) // BPR

    def _visible_rows(self) -> int:
        lh = self._metrics()[2]
        return max(1, self.viewport().height() // lh)

    def _update_scroll(self) -> None:
        sb = self.verticalScrollBar()
        sb.setRange(0, max(0, self._rows() - self._visible_rows()))
        sb.setPageStep(self._visible_rows())
        _, cw, _, _, _, ascii_x = self._metrics()
        self.horizontalScrollBar().setRange(0, max(0, ascii_x + BPR * cw + 12 - self.viewport().width()))

    # ---------------------------------------------------------------- public API
    def set_data(self, data: bytes) -> None:
        self._data = data
        self._sel = (-1, -1)
        self._anchor = -1
        self.verticalScrollBar().setValue(0)
        self._update_scroll()
        self.viewport().update()

    def data(self) -> bytes:
        return self._data

    def select(self, start: int, length: int = 1, scroll: bool = True) -> None:
        if not self._data:
            return
        start = max(0, min(start, len(self._data) - 1))
        end = max(start + 1, min(start + length, len(self._data)))
        self._sel = (start, end)
        self._anchor = start
        if scroll:
            row = start // BPR
            sb = self.verticalScrollBar()
            first = sb.value()
            if not (first <= row < first + self._visible_rows()):
                sb.setValue(max(0, row - 3))
        self.selection_changed.emit(start, end - start)
        self.viewport().update()

    def selection(self) -> tuple[int, int]:
        s, e = self._sel
        return (s, e - s) if s >= 0 else (-1, 0)

    def selected_bytes(self) -> bytes:
        s, e = self._sel
        return self._data[s:e] if s >= 0 else b""

    def find(self, needle: bytes, forward_from: int | None = None) -> int:
        if not needle or not self._data:
            return -1
        start = (self._sel[0] + 1) if forward_from is None and self._sel[0] >= 0 else (forward_from or 0)
        idx = self._data.find(needle, start)
        if idx == -1 and start > 0:      # wrap around
            idx = self._data.find(needle, 0)
        if idx != -1:
            self.select(idx, len(needle))
        return idx

    # ---------------------------------------------------------------- painting
    def paintEvent(self, _event) -> None:
        p = QPainter(self.viewport())
        pal = self.palette()
        p.fillRect(self.viewport().rect(), pal.base())
        if not self._data:
            p.setPen(pal.mid().color())
            p.drawText(self.viewport().rect(), Qt.AlignmentFlag.AlignCenter, "No data")
            return
        fm, cw, lh, margin, hex_x, ascii_x = self._metrics()
        dx = -self.horizontalScrollBar().value()
        first = self.verticalScrollBar().value()
        last = min(self._rows(), first + self._visible_rows() + 1)
        sel_s, sel_e = self._sel
        hl = pal.highlight()
        text_c, mid_c, hl_text = pal.text().color(), pal.mid().color(), pal.highlightedText().color()
        ascent = fm.ascent() + 1

        for r in range(first, last):
            y = (r - first) * lh
            off = r * BPR
            chunk = self._data[off:off + BPR]
            # selection background
            if sel_s >= 0 and sel_s < off + len(chunk) and sel_e > off:
                a = max(sel_s, off) - off
                b = min(sel_e, off + len(chunk)) - off
                x1 = self._byte_x(a, cw, hex_x) + dx
                x2 = self._byte_x(b - 1, cw, hex_x) + 2 * cw + dx
                p.fillRect(x1, y, x2 - x1, lh, hl)
                p.fillRect(ascii_x + a * cw + dx, y, (b - a) * cw, lh, hl)
            p.setPen(mid_c)
            p.drawText(margin + dx, y + ascent, f"{off:08X}")
            p.setPen(text_c)
            hx = chunk.hex(" ").upper()
            if len(chunk) > 8:
                hx = hx[:23] + "  " + hx[24:]
            p.drawText(hex_x + dx, y + ascent, hx)
            p.drawText(ascii_x + dx, y + ascent, chunk.decode("latin-1").translate(_TRANS))
            if sel_s >= 0 and sel_s < off + len(chunk) and sel_e > off:
                # redraw selected bytes in highlighted text colour
                p.setPen(hl_text)
                for i in range(max(sel_s, off) - off, min(sel_e, off + len(chunk)) - off):
                    p.drawText(self._byte_x(i, cw, hex_x) + dx, y + ascent, f"{chunk[i]:02X}")
                    p.drawText(ascii_x + i * cw + dx, y + ascent, _ASCII_TABLE[chunk[i]])

    # ---------------------------------------------------------------- interaction
    def _hit(self, pos: QPoint) -> int:
        _, cw, lh, _, hex_x, ascii_x = self._metrics()
        x = pos.x() + self.horizontalScrollBar().value()
        row = self.verticalScrollBar().value() + pos.y() // lh
        if x >= ascii_x:
            col = (x - ascii_x) // cw
        elif x >= hex_x:
            c = (x - hex_x) // cw
            if c >= 25:
                c -= 1
            col = c // 3
        else:
            col = 0
        col = max(0, min(BPR - 1, col))
        return max(0, min(len(self._data) - 1, row * BPR + col))

    def mousePressEvent(self, e) -> None:
        if self._data and e.button() == Qt.MouseButton.LeftButton:
            i = self._hit(e.position().toPoint())
            if e.modifiers() & Qt.KeyboardModifier.ShiftModifier and self._anchor >= 0:
                self._set_range(self._anchor, i)
            else:
                self._anchor = i
                self._set_range(i, i)

    def mouseMoveEvent(self, e) -> None:
        if self._data and e.buttons() & Qt.MouseButton.LeftButton and self._anchor >= 0:
            self._set_range(self._anchor, self._hit(e.position().toPoint()))

    def _set_range(self, a: int, b: int) -> None:
        s, e = min(a, b), max(a, b) + 1
        self._sel = (s, e)
        self.selection_changed.emit(s, e - s)
        self.viewport().update()

    def keyPressEvent(self, e) -> None:
        sb = self.verticalScrollBar()
        if e.matches(QKeySequence.StandardKey.Copy):
            QGuiApplication.clipboard().setText(self.selected_bytes().hex(" ").upper())
        elif e.key() == Qt.Key.Key_Down:
            sb.setValue(sb.value() + 1)
        elif e.key() == Qt.Key.Key_Up:
            sb.setValue(sb.value() - 1)
        elif e.key() == Qt.Key.Key_PageDown:
            sb.setValue(sb.value() + sb.pageStep())
        elif e.key() == Qt.Key.Key_PageUp:
            sb.setValue(sb.value() - sb.pageStep())
        elif e.key() == Qt.Key.Key_Home and e.modifiers() & Qt.KeyboardModifier.ControlModifier:
            sb.setValue(0)
        elif e.key() == Qt.Key.Key_End and e.modifiers() & Qt.KeyboardModifier.ControlModifier:
            sb.setValue(sb.maximum())
        else:
            super().keyPressEvent(e)

    def resizeEvent(self, e) -> None:
        super().resizeEvent(e)
        self._update_scroll()

    def scrollContentsBy(self, _dx: int, _dy: int) -> None:
        self.viewport().update()


class HexPanel(QWidget):
    """HexView plus go-to-offset, search and copy controls. With carve=True it also
    offers to save the selection or analyze it as a new sample (the main Hex tab)."""
    save_requested = Signal(int, object)      # offset, selected bytes
    analyze_requested = Signal(int, object)

    def __init__(self, parent: QWidget | None = None, carve: bool = False):
        super().__init__(parent)
        self.view = HexView(self)
        self.goto_edit = QLineEdit(placeholderText="Offset (0x1A2B or 6699)")
        self.goto_edit.setMaximumWidth(200)
        self.find_edit = QLineEdit(placeholderText="Search…")
        self.find_mode = QComboBox()
        self.find_mode.addItems(["Text", "Hex bytes"])
        find_btn = QPushButton("Find next")
        copy_hex = QPushButton("Copy hex")
        copy_txt = QPushButton("Copy text")
        self.status = QLabel("")
        self.status.setObjectName("Muted")

        bar = QHBoxLayout()
        bar.addWidget(QLabel("Go to"))
        bar.addWidget(self.goto_edit)
        bar.addSpacing(12)
        bar.addWidget(self.find_edit, 1)
        bar.addWidget(self.find_mode)
        bar.addWidget(find_btn)
        bar.addSpacing(12)
        bar.addWidget(copy_hex)
        bar.addWidget(copy_txt)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.addLayout(bar)
        if carve:
            save_sel = QPushButton("Save selection…")
            save_sel.setToolTip("Write the selected bytes to a .bin file in the output folder.")
            analyze_sel = QPushButton("Analyze selection as new sample")
            analyze_sel.setToolTip("Carve the selected bytes (e.g. data appended after %%EOF, or an "
                                   "embedded document) into a .bin file and open it as a new sample.")
            carve_bar = QHBoxLayout()
            carve_bar.addWidget(QLabel("Selection:"))
            carve_bar.addWidget(save_sel)
            carve_bar.addWidget(analyze_sel)
            carve_bar.addStretch(1)
            lay.addLayout(carve_bar)
            save_sel.clicked.connect(lambda: self._emit_selection(self.save_requested))
            analyze_sel.clicked.connect(lambda: self._emit_selection(self.analyze_requested))
        lay.addWidget(self.view, 1)
        lay.addWidget(self.status)

        self.goto_edit.returnPressed.connect(self._goto)
        self.find_edit.returnPressed.connect(self._find)
        find_btn.clicked.connect(self._find)
        copy_hex.clicked.connect(lambda: QGuiApplication.clipboard().setText(
            self.view.selected_bytes().hex(" ").upper()))
        copy_txt.clicked.connect(lambda: QGuiApplication.clipboard().setText(
            self.view.selected_bytes().decode("latin-1").translate(_TRANS)))
        self.view.selection_changed.connect(self._on_sel)

    def set_data(self, data: bytes) -> None:
        self.view.set_data(data)
        self.status.setText(f"{len(data):,} bytes")

    def goto(self, offset: int, length: int = 1) -> None:
        self.view.select(offset, length)
        self.view.setFocus()

    def _emit_selection(self, signal) -> None:
        start, _length = self.view.selection()
        data = self.view.selected_bytes()
        if not data:
            self.status.setText("Select a byte range first (drag, or Shift+click / Shift+arrows).")
            return
        signal.emit(start, data)

    def find_bytes(self, needle: bytes) -> int:
        return self.view.find(needle, forward_from=0)

    def _goto(self) -> None:
        text = self.goto_edit.text().strip().lower()
        try:
            off = int(text, 16) if text.startswith("0x") else int(text)
        except ValueError:
            self.status.setText(f"Not a valid offset: {text}")
            return
        self.goto(off)

    def _find(self) -> None:
        text = self.find_edit.text()
        if not text:
            return
        if self.find_mode.currentIndex() == 1:
            try:
                needle = bytes.fromhex(text.replace(" ", ""))
            except ValueError:
                self.status.setText("Hex search must be pairs of hex digits, e.g. 4D 5A 90")
                return
        else:
            needle = text.encode("latin-1", "replace")
        if self.view.find(needle) == -1:
            self.status.setText(f"Not found: {text}")

    def _on_sel(self, start: int, length: int) -> None:
        self.status.setText(f"Offset 0x{start:X} ({start:,})   length {length:,}   "
                            f"of {len(self.view.data()):,} bytes")
