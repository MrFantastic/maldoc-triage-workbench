"""Small widget helpers shared by the tool modules."""
from __future__ import annotations

import html

from PySide6.QtCore import QPoint, QRect, QSize, Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (QHBoxLayout, QHeaderView, QLabel, QLayout, QPlainTextEdit, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from ..core.models import Severity
from .theme import SEVERITY_COLOR, apply_mono


def text_view(wrap: bool = False) -> QPlainTextEdit:
    """A read-only monospace text view."""
    t = QPlainTextEdit(readOnly=True)
    t.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth if wrap else QPlainTextEdit.LineWrapMode.NoWrap)
    apply_mono(t)
    return t


def table(headers: list[str], stretch: int) -> QTableWidget:
    """A read-only table that selects whole rows; column stretch takes the spare width."""
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    t.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
    t.setAlternatingRowColors(True)
    h = t.horizontalHeader()
    for c in range(len(headers)):
        h.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
    h.setSectionResizeMode(stretch, QHeaderView.ResizeMode.Stretch)
    return t


def fill(t: QTableWidget, rows: list[list[str]], data: list | None = None,
         colors: list[Severity | None] | None = None) -> None:
    """Fill a table; data[i] is stored on column 0 (UserRole); colors tint columns 0-1."""
    t.setSortingEnabled(False)
    t.setRowCount(len(rows))
    for i, row in enumerate(rows):
        for c, text in enumerate(row):
            item = QTableWidgetItem(str(text))
            item.setToolTip(plain_tip(text))
            if c == 0 and data is not None:
                item.setData(Qt.ItemDataRole.UserRole, data[i])
            sev = colors[i] if colors else None
            if sev is not None and sev >= Severity.MEDIUM and c in (0, 1):
                item.setForeground(QBrush(QColor(SEVERITY_COLOR[sev])))
            t.setItem(i, c, item)


def row_data(t: QTableWidget, row: int | None = None):
    """The data stored on a row's first cell (the current row by default), or None."""
    r = t.currentRow() if row is None else row
    if r < 0 or t.item(r, 0) is None:
        return None
    return t.item(r, 0).data(Qt.ItemDataRole.UserRole)


def hbox(*widgets, stretch_after: bool = False) -> QHBoxLayout:
    """A horizontal layout: a str becomes a label and None a stretch."""
    lay = QHBoxLayout()
    for w in widgets:
        if w is None:
            lay.addStretch(1)
        elif isinstance(w, str):
            lay.addWidget(QLabel(w))
        else:
            lay.addWidget(w)
    if stretch_after:
        lay.addStretch(1)
    return lay


def vbox_widget(*items, margins: int = 0) -> QWidget:
    """A widget with a vertical layout of widgets, (widget, stretch) pairs and layouts."""
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(margins, margins, margins, margins)
    for it in items:
        if isinstance(it, tuple):
            widget, stretch = it
            lay.addWidget(widget, stretch)
        elif hasattr(it, "addWidget") and not isinstance(it, QWidget):
            lay.addLayout(it)
        else:
            lay.addWidget(it)
    return w


def banner(text: str = "") -> QLabel:
    """A word-wrapped, selectable rich-text label for the top of a tab."""
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.TextFormat.RichText)
    lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lbl


class FlowLayout(QLayout):
    """Lays widgets out left to right and wraps to the next line when the row is
    full, so toolbars never push the window wider than the screen."""

    def __init__(self, parent: QWidget | None = None, spacing: int = 6):
        super().__init__(parent)
        self._items = []
        self.setSpacing(spacing)
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item) -> None:
        self._items.append(item)

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, i: int):
        return self._items[i] if 0 <= i < len(self._items) else None

    def takeAt(self, i: int):
        return self._items.pop(i) if 0 <= i < len(self._items) else None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        return self._do(QRect(0, 0, width, 0), True)

    def setGeometry(self, rect: QRect) -> None:
        super().setGeometry(rect)
        self._do(rect, False)

    def sizeHint(self) -> QSize:
        return self.minimumSize()

    def minimumSize(self) -> QSize:
        size = QSize()
        for it in self._items:
            size = size.expandedTo(it.minimumSize())
        m = self.contentsMargins()
        return size + QSize(m.left() + m.right(), m.top() + m.bottom())

    def _do(self, rect: QRect, test: bool) -> int:
        m = self.contentsMargins()
        area = rect.adjusted(m.left(), m.top(), -m.right(), -m.bottom())
        x, y, line = area.x(), area.y(), 0
        sp = self.spacing()
        for it in self._items:
            w = it.widget()
            if w is not None and w.isHidden():
                continue
            hint = it.sizeHint()
            if x + hint.width() > area.right() + 1 and line > 0:
                x = area.x()
                y += line + sp
                line = 0
            if not test:
                it.setGeometry(QRect(QPoint(x, y), hint))
            x += hint.width() + sp
            line = max(line, hint.height())
        return y + line - rect.y() + m.bottom()


def flow(*widgets) -> QWidget:
    """A wrapping row of widgets. Strings become labels; None is ignored."""
    host = QWidget()
    lay = FlowLayout(host)
    for w in widgets:
        if w is None:
            continue
        lay.addWidget(QLabel(w) if isinstance(w, str) else w)
    return host


def plain_tip(text, limit: int = 2000) -> str:
    """Tooltip text shown literally. Qt renders tooltips that look like HTML as rich
    text, so text from a sample is escaped and wrapped to force a literal display."""
    t = str(text)[:limit]
    return "<qt>" + html.escape(t).replace("\n", "<br>") + "</qt>" if t else ""
