#!/usr/bin/env python3
"""Build HARMLESS Office test files for the Office tabs (nothing in them executes).

  MTW_office_01_clean.docx            no links: expect NO INDICATORS FOUND
  MTW_office_02_hyperlink.docx        one external hyperlink to example.com: expect LOW
  MTW_office_03_remote_template.docx  remote attachedTemplate pointing at example.com
                                      (the template-injection pattern): expect HIGH
  MTW_office_04_link.rtf              RTF with a HYPERLINK field: expect LOW

Every link points to example.com, which is reserved for documentation.

Run:  python make_test_office.py [output folder]       (default MTW_test_office)
"""
from __future__ import annotations

import os
import sys
import zipfile

OUT = sys.argv[1] if len(sys.argv) > 1 else "MTW_test_office"

XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
PKG_RELS = "http://schemas.openxmlformats.org/package/2006/relationships"
DOC_RELS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
W_NS = ('xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        f'xmlns:r="{DOC_RELS}"')
WML = "application/vnd.openxmlformats-officedocument.wordprocessingml"

CONTENT_TYPES = (
    XML + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    f'<Override PartName="/word/document.xml" ContentType="{WML}.document.main+xml"/>'
    f'<Override PartName="/word/settings.xml" ContentType="{WML}.settings+xml"/>'
    "</Types>")


def rel(rid: str, kind: str, target: str, external: bool = False) -> str:
    mode = ' TargetMode="External"' if external else ""
    return f'<Relationship Id="{rid}" Type="{DOC_RELS}/{kind}" Target="{target}"{mode}/>'


def rels(*items: str) -> str:
    return XML + f'<Relationships xmlns="{PKG_RELS}">' + "".join(items) + "</Relationships>"


def para(text: str) -> str:
    return f"<w:p><w:r><w:t>{text}</w:t></w:r></w:p>"


def docx(name: str, body: str, doc_rels: str = "", template_url: str = "") -> None:
    settings = '<w:attachedTemplate r:id="rId1"/>' if template_url else ""
    with zipfile.ZipFile(os.path.join(OUT, name), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", CONTENT_TYPES)
        z.writestr("_rels/.rels", rels(rel("rId1", "officeDocument", "word/document.xml")))
        z.writestr("word/document.xml", XML + f"<w:document {W_NS}><w:body>{body}</w:body></w:document>")
        z.writestr("word/settings.xml", XML + f"<w:settings {W_NS}>{settings}</w:settings>")
        z.writestr("word/_rels/document.xml.rels", rels(rel("rId9", "settings", "settings.xml"), doc_rels))
        if template_url:
            z.writestr("word/_rels/settings.xml.rels", rels(rel("rId1", "attachedTemplate", template_url, True)))
    print(f"  {name}")


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    docx("MTW_office_01_clean.docx", para("A harmless test document with no links."))
    docx("MTW_office_02_hyperlink.docx",
         para("Link:") + '<w:p><w:hyperlink r:id="rId5"><w:r><w:t>example.com</w:t></w:r></w:hyperlink></w:p>',
         doc_rels=rel("rId5", "hyperlink", "https://example.com/mtw-test", True))
    docx("MTW_office_03_remote_template.docx",
         para("Remote template reference (template-injection pattern); the URL is example.com."),
         template_url="https://example.com/mtw-test-template.dotm")
    with open(os.path.join(OUT, "MTW_office_04_link.rtf"), "w", encoding="ascii") as fh:
        fh.write(r'{\rtf1\ansi{\fonttbl{\f0 Arial;}}\f0 Harmless RTF with a link: '
                 r'{\field{\*\fldinst HYPERLINK "https://example.com/mtw-rtf"}{\fldrslt example.com}}\par}')
    print("  MTW_office_04_link.rtf")


if __name__ == "__main__":
    main()
