"""
Render scripts/doc_content.py (plain-language code walkthrough) into
docs/Project-Code-Explained.pdf, with a title page and an automatic,
page-numbered table of contents.

Run:  python scripts/generate_code_doc.py
"""

import os
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, PageBreak,
    Table, TableStyle, Preformatted,
)
from reportlab.platypus.doctemplate import NextPageTemplate

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..")))
sys.path.insert(0, _HERE)   # so `import doc_content` finds scripts/doc_content.py

import doc_content as DC  # noqa: E402

OUT = "docs/Project-Code-Explained.pdf"
INK = colors.HexColor("#111827")
BLUE = colors.HexColor("#1f3a8a")
GREY = colors.HexColor("#6b7280")
PURPLE = colors.HexColor("#5b3fd6")

_TOC = []   # (level, text, page) captured during a build pass


class Doc(BaseDocTemplate):
    pass


class TOCHeading(Paragraph):
    """Heading that records its own true page number at draw time."""
    def __init__(self, text, style, level):
        super().__init__(text, style)
        self._level = level

    def draw(self):
        _TOC.append((self._level, self.getPlainText(), self.canv.getPageNumber()))
        super().draw()


def styles():
    s = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle("ct", parent=s["Title"], fontSize=23,
            leading=29, alignment=TA_CENTER, textColor=INK, spaceAfter=26),
        "cover_sub": ParagraphStyle("cs", parent=s["Normal"], fontSize=12,
            leading=19, alignment=TA_CENTER, textColor=GREY),
        "h1num": ParagraphStyle("h1n", parent=s["Normal"], fontSize=12,
            leading=15, textColor=GREY, fontName="Helvetica-Bold",
            spaceBefore=8),
        "h1": ParagraphStyle("h1", parent=s["Normal"], fontSize=22,
            leading=27, textColor=BLUE, fontName="Helvetica-Bold",
            spaceAfter=16),
        "h2": ParagraphStyle("h2", parent=s["Heading2"], fontSize=15,
            leading=19, textColor=INK, spaceBefore=16, spaceAfter=7),
        "h3": ParagraphStyle("h3", parent=s["Heading3"], fontSize=12,
            leading=15.5, textColor=PURPLE, spaceBefore=11, spaceAfter=3),
        "p": ParagraphStyle("p", parent=s["Normal"], fontSize=10.3,
            leading=15.5, textColor=INK, alignment=TA_JUSTIFY, spaceAfter=8),
        "b": ParagraphStyle("b", parent=s["Normal"], fontSize=10.3,
            leading=15, textColor=INK, leftIndent=16, bulletIndent=4,
            spaceAfter=4),
        "note": ParagraphStyle("note", parent=s["Normal"], fontSize=9.8,
            leading=14.5, textColor=INK, leftIndent=10, rightIndent=6,
            spaceBefore=4, spaceAfter=9, backColor=colors.HexColor("#eef0fb"),
            borderColor=colors.HexColor("#c7cbe8"), borderWidth=0.5,
            borderPadding=8, borderRadius=4),
        "code": ParagraphStyle("code", parent=s["Code"], fontName="Courier",
            fontSize=8.4, leading=11.5, textColor=INK,
            backColor=colors.HexColor("#f3f4f6"), borderPadding=6,
            spaceBefore=3, spaceAfter=9),
        "toc0": ParagraphStyle("t0", fontName="Helvetica-Bold", fontSize=11,
            leading=17, textColor=INK),
        "toc1": ParagraphStyle("t1", fontName="Helvetica", fontSize=9.6,
            leading=14, leftIndent=16, textColor=colors.HexColor("#374151")),
    }


def make_table(rows, st):
    data = [[Paragraph(str(c), st["p"]) for c in r] for r in rows]
    t = Table(data, hAlign="LEFT", colWidths=None)
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d8dae5")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef0fb")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def on_body(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(GREY)
    canvas.drawString(2 * cm, 1.15 * cm, "Behavior Anomaly Detection — Code")
    canvas.drawRightString(A4[0] - 2 * cm, 1.15 * cm, str(doc.page))
    canvas.setStrokeColor(colors.HexColor("#e5e7eb"))
    canvas.line(2 * cm, 1.5 * cm, A4[0] - 2 * cm, 1.5 * cm)
    canvas.restoreState()


def build_story(st, toc_rows):
    S = []

    # ---- cover ----
    S.append(NextPageTemplate("cover"))
    S.append(Spacer(1, 4.5 * cm))
    S.append(Paragraph(DC.TITLE, st["cover_title"]))
    S.append(Spacer(1, 0.6 * cm))
    S.append(Paragraph(DC.SUBTITLE, st["cover_sub"]))

    # ---- contents ----
    S.append(NextPageTemplate("body"))
    S.append(PageBreak())
    S.append(Paragraph("Contents", st["h1"]))
    if toc_rows:
        rows = []
        for level, text, page in toc_rows:
            style = st["toc0"] if level == 0 else st["toc1"]
            pstyle = ParagraphStyle("pp", parent=style, alignment=2)
            rows.append([Paragraph(text, style), Paragraph(str(page), pstyle)])
        tt = Table(rows, colWidths=[14.6 * cm, 1.2 * cm], hAlign="LEFT")
        tt.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
            ("TOPPADDING", (0, 0), (-1, -1), 1),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]))
        S.append(tt)

    # ---- body from doc_content BLOCKS ----
    for kind, payload in DC.BLOCKS:
        if kind == "h1":
            S.append(PageBreak())
            S.append(TOCHeading(payload, st["h1"], 0))
        elif kind == "h2":
            S.append(TOCHeading(payload, st["h2"], 1))
        elif kind == "h3":
            S.append(Paragraph(payload, st["h3"]))
        elif kind == "p":
            S.append(Paragraph(payload, st["p"]))
        elif kind == "b":
            S.append(Paragraph(payload, st["b"], bulletText="•"))
        elif kind == "note":
            S.append(Paragraph("<b>Note.</b> " + payload, st["note"]))
        elif kind == "code":
            S.append(Preformatted(payload, st["code"]))
        elif kind == "table":
            S.append(make_table(payload, st))
            S.append(Spacer(1, 8))
        elif kind == "space":
            S.append(Spacer(1, payload if isinstance(payload, (int, float)) else 8))
    return S


def render(toc_rows):
    _TOC.clear()
    st = styles()
    doc = Doc(OUT, pagesize=A4, leftMargin=2.2 * cm, rightMargin=2.2 * cm,
              topMargin=2 * cm, bottomMargin=1.9 * cm,
              title="Project Code Explained")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height,
                  id="f")
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=frame),
        PageTemplate(id="body", frames=frame, onPage=on_body),
    ])
    doc.build(build_story(st, toc_rows))
    return list(_TOC)


def main():
    os.makedirs("docs", exist_ok=True)
    rows = render(None)       # pass 1: collect true page numbers
    rows = render(rows)       # pass 2: render the contents table
    check = render(rows)      # pass 3 only if pagination shifted
    if check != rows:
        render(check)
    size = os.path.getsize(OUT) / 1024
    print(f"Written {OUT} ({size:.0f} KB, {len(rows)} contents entries)")


if __name__ == "__main__":
    main()
