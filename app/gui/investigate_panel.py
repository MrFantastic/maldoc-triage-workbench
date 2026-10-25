"""Investigate panel: explains the selected finding and walks the analyst
through the next steps, each with a button that does it and the equivalent
command line."""
from __future__ import annotations

import html

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QFrame, QGridLayout, QLabel, QPushButton, QScrollArea, QToolButton, QVBoxLayout,
                               QWidget)

from ..core import guidance
from ..core.models import Finding
from ..core.safety import defang
from .theme import SEVERITY_COLOR, apply_mono


def _label(text: str = "", rich: bool = True, muted: bool = False) -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.TextFormat.RichText if rich else Qt.TextFormat.PlainText)
    lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    if muted:
        lbl.setStyleSheet("color: palette(mid);")
    return lbl


class InvestigatePanel(QWidget):
    """Explains the selected finding, with a Go button and the command line for each next step."""
    action_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.body = QWidget()
        self.lay = QVBoxLayout(self.body)
        self.lay.setAlignment(Qt.AlignmentFlag.AlignTop)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(self.body)
        root = QVBoxLayout(self)
        root.setContentsMargins(4, 0, 4, 4)
        header = QLabel("<b>Investigate</b>")
        root.addWidget(header)
        root.addWidget(scroll, 1)
        self.show_placeholder()

    def _clear(self) -> None:
        while self.lay.count():
            item = self.lay.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
            elif item.layout() is not None:
                lay = item.layout()
                while lay.count():
                    sub = lay.takeAt(0)
                    if sub.widget():
                        sub.widget().deleteLater()

    def show_placeholder(self) -> None:
        self._clear()
        self.lay.addWidget(_label("Select a finding to see what it means, how attackers use it, when it's "
                                  "harmless, and the steps to investigate it. Each step has a button that "
                                  "does it for you and shows the matching command.", muted=True))

    def show_finding(self, f: Finding) -> None:
        self._clear()
        g = guidance.guidance_for(f)
        color = SEVERITY_COLOR[f.severity]
        self.lay.addWidget(_label(f"<span style='color:{color};font-weight:700'>{f.severity.label}</span>"
                                  f"&nbsp; <b>{html.escape(defang(f.title))}</b>"))
        if g.title and g.title != f.title:
            self.lay.addWidget(_label(f"<i>{html.escape(g.title)}</i>", muted=True))
        if f.detail:
            self.lay.addWidget(_label(f"<b>Evidence:</b> {html.escape(defang(f.detail))}"))
        for heading, text in (("What it is", g.what), ("Why it matters", g.why), ("Often harmless when", g.benign)):
            if text:
                self.lay.addWidget(_label(f"<b>{heading}:</b> {html.escape(text)}"))
        steps = guidance.steps_for(f)
        if not steps:
            return
        self.lay.addWidget(_label("<b>Next steps</b>"))
        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        for i, s in enumerate(steps, 1):
            grid.addWidget(QLabel(f"<b>{i}.</b>"), i * 2, 0, Qt.AlignmentFlag.AlignTop)
            grid.addWidget(_label(html.escape(s.label)), i * 2, 1)
            if s.action:
                btn = QPushButton("Go")
                btn.setToolTip(f"Do this step ({s.action})")
                btn.clicked.connect(lambda _=False, a=s.action: self.action_requested.emit(a))
                grid.addWidget(btn, i * 2, 2, Qt.AlignmentFlag.AlignTop)
            if s.cli:
                cli = _label(html.escape(s.cli), muted=True)
                apply_mono(cli)
                cli.setToolTip("Equivalent command line")
                copy = QToolButton(text="Copy")
                copy.setToolTip("Copy the command")
                copy.clicked.connect(lambda _=False, c=s.cli: QGuiApplication.clipboard().setText(c))
                grid.addWidget(cli, i * 2 + 1, 1)
                grid.addWidget(copy, i * 2 + 1, 2, Qt.AlignmentFlag.AlignTop)
        holder = QWidget()
        holder.setLayout(grid)
        self.lay.addWidget(holder)

    def first_action(self, f: Finding) -> str:
        for s in guidance.steps_for(f):
            if s.action:
                return s.action
        return ""
