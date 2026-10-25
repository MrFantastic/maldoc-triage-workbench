"""VBA / XLM syntax highlighting, with olevba's flagged keywords marked in red."""
from __future__ import annotations

import re

from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat

VBA_KEYWORDS = (
    "Sub Function End Dim As If Then Else ElseIf For Next Each In Do Loop While Wend Until With "
    "Set Let Call Private Public Static Const Exit Select Case On Error Resume GoTo Not And Or Xor "
    "Mod New Nothing True False ByVal ByRef Declare Lib Alias PtrSafe Option Explicit Property Get "
    "Type Enum Optional ParamArray Is Like Step To Me Variant String Long Integer Boolean Object "
    "Byte Double Single Date Currency LongPtr Attribute"
).split()


def _fmt(color: str, bold: bool = False, italic: bool = False, bg: str | None = None) -> QTextCharFormat:
    f = QTextCharFormat()
    f.setForeground(QColor(color))
    if bold:
        f.setFontWeight(QFont.Weight.Bold)
    if italic:
        f.setFontItalic(True)
    if bg:
        f.setBackground(QColor(bg))
    return f


class VbaHighlighter(QSyntaxHighlighter):
    """VBA syntax highlighting, with suspicious keywords marked."""
    def __init__(self, document, dark: bool = True):
        super().__init__(document)
        self.f_kw = _fmt("#7aa2f7" if dark else "#1f4fd1", bold=True)
        self.f_str = _fmt("#9ece6a" if dark else "#2e7d32")
        self.f_num = _fmt("#ff9e64" if dark else "#b35900")
        self.f_com = _fmt("#6b6e78", italic=True)
        self.f_hit = _fmt("#ffffff", bold=True, bg="#b4232b")
        self._kw_re = re.compile(r"\b(" + "|".join(VBA_KEYWORDS) + r")\b", re.IGNORECASE)
        self._num_re = re.compile(r"\b(&H[0-9A-F]+|\d+(\.\d+)?)\b", re.IGNORECASE)
        self._hit_re: re.Pattern | None = None

    def set_flagged(self, keywords: list[str]) -> None:
        """Highlight olevba's AutoExec/Suspicious keywords wherever they appear."""
        words = sorted({k for k in keywords if k and len(k) > 1}, key=len, reverse=True)
        self._hit_re = (re.compile("|".join(re.escape(w) for w in words), re.IGNORECASE)
                        if words else None)
        self.rehighlight()

    def highlightBlock(self, text: str) -> None:
        # find strings and the comment start, honouring quotes
        strings, comment_at, in_str, start = [], -1, False, 0
        for i, ch in enumerate(text):
            if ch == '"':
                if in_str:
                    strings.append((start, i + 1))
                else:
                    start = i
                in_str = not in_str
            elif ch == "'" and not in_str:
                comment_at = i
                break
        if in_str:
            strings.append((start, len(text)))
        stripped = text.lstrip()
        if comment_at == -1 and stripped[:4].lower() == "rem ":
            comment_at = len(text) - len(stripped)
        code_end = comment_at if comment_at != -1 else len(text)

        for m in self._kw_re.finditer(text, 0, code_end):
            self.setFormat(m.start(), m.end() - m.start(), self.f_kw)
        for m in self._num_re.finditer(text, 0, code_end):
            self.setFormat(m.start(), m.end() - m.start(), self.f_num)
        for s, e in strings:
            if s < code_end:
                self.setFormat(s, min(e, code_end) - s, self.f_str)
        if comment_at != -1:
            self.setFormat(comment_at, len(text) - comment_at, self.f_com)
        if self._hit_re is not None:
            for m in self._hit_re.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), self.f_hit)
