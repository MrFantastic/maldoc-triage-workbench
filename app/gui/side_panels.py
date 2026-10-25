"""Left-dock panels: sample information and the shared findings list."""
from __future__ import annotations

import html

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor, QGuiApplication
from PySide6.QtWidgets import (QFormLayout, QHBoxLayout, QHeaderView, QLabel, QToolButton,
                               QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ..core import outputcheck
from ..core.models import Finding, Severity
from ..core.session import Session
from .common import plain_tip
from .theme import SEVERITY_COLOR, apply_mono, badge_style


def _human_size(n: int) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,} {unit}" if unit == "bytes" else f"{n:,.1f} {unit}"
        n /= 1024
    return str(n)


class SamplePanel(QWidget):
    """Compact sample header: risk badge, name, one line of type/size/header,
    and the hashes folded behind a toggle."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.risk = QLabel("—")
        self.risk.setObjectName("Badge")
        self.risk.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.risk.setMinimumWidth(90)
        self.name = QLabel("No sample loaded")
        self.name.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        f = self.name.font()
        f.setBold(True)
        self.name.setFont(f)
        self.summary = QLabel("")
        self.summary.setWordWrap(True)
        self.summary.setObjectName("Muted")
        self.summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.toggle = QToolButton(text="Hashes ▸")
        self.toggle.setCheckable(True)
        self.toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)

        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.addWidget(self.risk)
        top.addWidget(self.name, 1)
        top.addWidget(self.toggle)

        self.hash_box = QWidget()
        form = QFormLayout(self.hash_box)
        form.setContentsMargins(0, 2, 0, 0)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.hashes: dict[str, QLabel] = {}
        for algo in ("MD5", "SHA1", "SHA256"):
            lbl = QLabel("—")
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            lbl.setWordWrap(True)
            apply_mono(lbl)
            self.hashes[algo] = lbl
            row = QHBoxLayout()
            row.setContentsMargins(0, 0, 0, 0)
            row.addWidget(lbl, 1)
            btn = QToolButton(text="Copy")
            btn.setToolTip(f"Copy {algo}")
            btn.clicked.connect(lambda _=False, w=lbl: QGuiApplication.clipboard().setText(w.text()))
            row.addWidget(btn, 0, Qt.AlignmentFlag.AlignTop)
            holder = QWidget()
            holder.setLayout(row)
            form.addRow(algo, holder)
        self.hash_box.setVisible(False)
        self.toggle.toggled.connect(self._toggle)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 4, 6, 4)
        lay.setSpacing(4)
        lay.addLayout(top)
        lay.addWidget(self.summary)
        lay.addWidget(self.hash_box)
        self.clear()

    def _toggle(self, on: bool) -> None:
        self.hash_box.setVisible(on)
        self.toggle.setText("Hashes ▾" if on else "Hashes ▸")

    def set_hashes_visible(self, on: bool) -> None:
        self.toggle.setChecked(on)

    def clear(self) -> None:
        self.name.setText("No sample loaded")
        self.name.setToolTip("")
        self.summary.setText("Drop a file on the window or use File → Open.")
        for w in self.hashes.values():
            w.setText("—")
        self.risk.setText("—")
        self.risk.setStyleSheet(badge_style(SEVERITY_COLOR[Severity.INFO]))

    def show_session(self, session: Session) -> None:
        s = session.sample
        self.name.setText(s.name)
        self.name.setToolTip(plain_tip(s.path))
        if s.route.pdf_version:
            hdr = f"{s.route.pdf_version} at offset {s.route.header_offset}"
        elif s.route.header_offset is not None:
            hdr = f"magic at offset {s.route.header_offset}"
        else:
            hdr = "no known magic"
        parent = f"<br>Derived: {html.escape(session.parent_note)}" if session.parent_note else ""
        self.summary.setText(f"{html.escape(s.route.subtype or s.family.value)} · {_human_size(s.size)} · {hdr}"
                             f"<br>SHA256 {s.sha256[:16]}…{parent}")
        self.summary.setToolTip(plain_tip(f"{s.family.value}\n{s.path}\nSHA256 {s.sha256}"))
        self.hashes["MD5"].setText(s.md5)
        self.hashes["SHA1"].setText(s.sha1)
        self.hashes["SHA256"].setText(s.sha256)
        self.update_risk(session.risk)

    def update_risk(self, risk: Severity, incomplete: bool = False) -> None:
        if incomplete:
            self.risk.setText("INCOMPLETE")
            self.risk.setStyleSheet(badge_style("#6e56cf"))
            self.risk.setToolTip("No analysis tool completed: the file has not been checked.")
            return
        self.risk.setText(risk.label.upper())
        self.risk.setStyleSheet(badge_style(SEVERITY_COLOR[risk]))
        self.risk.setToolTip("")


class FindingsPanel(QWidget):
    """Every finding for the sample, highest severity first."""
    activated = Signal(object)  # Finding (double-click)
    selected = Signal(object)   # Finding (current item changed)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Severity", "Source", "Finding"])
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setSortingEnabled(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        hdr = self.tree.header()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.detail = QLabel("")
        self.detail.setWordWrap(True)
        self.detail.setTextFormat(Qt.TextFormat.RichText)
        self.detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.detail.setObjectName("Muted")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.addWidget(self.tree, 1)
        lay.addWidget(self.detail)
        self.tree.currentItemChanged.connect(self._on_current)
        self.tree.itemDoubleClicked.connect(
            lambda item, _col: self.activated.emit(item.data(0, Qt.ItemDataRole.UserRole)))

    def set_findings(self, findings: list[Finding], tools_run: set[str] | None = None,
                     errors: dict[str, str] | None = None) -> None:
        self.tree.clear()
        counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in Severity}
        self.tree.setHeaderLabels(["Severity", "Source",
                                   f"Finding ({len(findings)}: {counts[Severity.HIGH]} high, "
                                   f"{counts[Severity.MEDIUM]} medium)" if findings else "Finding"])
        for f in sorted(findings, key=lambda x: (-x.severity, x.source)):
            item = QTreeWidgetItem([f.severity.label, f.source, f.title])
            item.setForeground(0, QBrush(QColor(SEVERITY_COLOR[f.severity])))
            item.setToolTip(2, plain_tip(f.detail or f.title))
            item.setData(0, Qt.ItemDataRole.UserRole, f)
            self.tree.addTopLevelItem(item)
        partial = outputcheck.warnings(findings)
        partial_html = ("<br><b style='color:#d9a400'>⚠ Some tool output wasn't recognized (newer tool "
                        "version?), so those results may be partial:</b><br>"
                        + "<br>".join(html.escape(t) for _s, t in sorted(partial.items()))
                        + "<br>Select the note in the list for what to check.") if partial else ""
        if errors:
            self.detail.setText("<b style='color:#e5484d'>⚠ Some tools failed, so results are incomplete:</b><br>"
                                + "<br>".join(html.escape(f"{k}: {v}") for k, v in sorted(errors.items()))
                                + "<br>Help → Tool status, or Help → Download / update tools." + partial_html)
        elif partial:
            self.detail.setText(partial_html[4:])
        elif findings:
            self.detail.setText("Double-click a finding to jump to it.")
        elif tools_run:
            self.detail.setText("Scan complete: nothing suspicious found by "
                                + ", ".join(sorted(tools_run)) + ".")
        else:
            self.detail.setText("No findings yet.")

    def _on_current(self, item, _prev) -> None:
        if item is None:
            return
        f: Finding = item.data(0, Qt.ItemDataRole.UserRole)
        self.detail.setText("Double-click to run the first investigation step.")
        self.selected.emit(f)
