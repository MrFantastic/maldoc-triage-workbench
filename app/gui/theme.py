"""Palette, severity colours and the small shared stylesheet."""
from __future__ import annotations

from PySide6.QtGui import QColor, QFontDatabase, QPalette
from PySide6.QtWidgets import QApplication, QStyleFactory

from ..core.models import Severity

SEVERITY_COLOR = {
    Severity.HIGH: "#e5484d",
    Severity.MEDIUM: "#f5a524",
    Severity.LOW: "#3e9bdb",
    Severity.INFO: "#8b8d98",
}

VERDICT_COLOR = {
    "SUSPICIOUS": SEVERITY_COLOR[Severity.HIGH],
    "MACRO OK": SEVERITY_COLOR[Severity.MEDIUM],
    "NO MACRO": "#30a46c",
    "ERROR": SEVERITY_COLOR[Severity.INFO],
}

_STYLE = """
QLabel#Badge { border-radius: 4px; padding: 2px 10px; font-weight: 600; color: white; }
QLabel#Verdict { border-radius: 6px; padding: 10px 18px; font-size: 18pt; font-weight: 700; color: white; }
QLabel#Chip { border-radius: 4px; padding: 6px 12px; font-weight: 700; }
QLabel#Muted { color: palette(mid); }
QLabel#DropZone { border: 2px dashed palette(mid); border-radius: 12px; padding: 40px;
                  font-size: 13pt; color: palette(mid); }
QGroupBox { font-weight: 600; }
"""


def apply_theme(app: QApplication, dark: bool = True) -> None:
    """Apply the Fusion style with the dark or light palette."""
    app.setStyle(QStyleFactory.create("Fusion"))
    if dark:
        p = QPalette()
        base, alt, text = QColor("#1b1c20"), QColor("#24262b"), QColor("#e6e6e9")
        p.setColor(QPalette.ColorRole.Window, QColor("#202227"))
        p.setColor(QPalette.ColorRole.WindowText, text)
        p.setColor(QPalette.ColorRole.Base, base)
        p.setColor(QPalette.ColorRole.AlternateBase, alt)
        p.setColor(QPalette.ColorRole.ToolTipBase, alt)
        p.setColor(QPalette.ColorRole.ToolTipText, text)
        p.setColor(QPalette.ColorRole.Text, text)
        p.setColor(QPalette.ColorRole.Button, QColor("#2b2d33"))
        p.setColor(QPalette.ColorRole.ButtonText, text)
        p.setColor(QPalette.ColorRole.Highlight, QColor("#3e63dd"))
        p.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
        p.setColor(QPalette.ColorRole.Link, QColor("#7aa2f7"))
        p.setColor(QPalette.ColorRole.Mid, QColor("#6b6e78"))
        p.setColor(QPalette.ColorRole.PlaceholderText, QColor("#6b6e78"))
        for role in (QPalette.ColorRole.Text, QPalette.ColorRole.WindowText, QPalette.ColorRole.ButtonText):
            p.setColor(QPalette.ColorGroup.Disabled, role, QColor("#5c5f68"))
        app.setPalette(p)
    else:
        app.setPalette(app.style().standardPalette())
    app.setStyleSheet(_STYLE)


def badge_style(color: str) -> str:
    """Style sheet for a coloured verdict badge."""
    return f"background-color: {color};"


def apply_mono(widget) -> None:
    """Use the OS's fixed-width font (Consolas on Windows, DejaVu Sans Mono etc. on Linux)."""
    f = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    f.setPointSize(max(f.pointSize(), widget.font().pointSize()))
    widget.setFont(f)


_BASE_FONT_PT: float | None = None


def apply_font(app: QApplication, delta: int) -> None:
    """Scale the UI text: base system size + delta points."""
    global _BASE_FONT_PT
    f = app.font()
    if _BASE_FONT_PT is None:
        _BASE_FONT_PT = f.pointSizeF() if f.pointSizeF() > 0 else 9.0
    f.setPointSizeF(max(6.0, _BASE_FONT_PT + delta))
    app.setFont(f)
