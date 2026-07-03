#!/usr/bin/env python3
"""Markdown -> PDF im Layout der AzubiOS-Vorlage (Kopfzeile, Seitennummer x/n, Tabellen).

Deckt die Teilmenge von Markdown ab, die in lasten-/pflichtenheft.md vorkommt:
H1/H2/H3, Absaetze mit **bold**/`code`/[text](url), Aufzaehlungen, nummerierte
Listen, Tabellen, horizontale Linien, Code-Bloecke und Mermaid-Bloecke.
"""
import re
import sys
import html

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table, TableStyle,
    XPreformatted, HRFlowable, KeepTogether,
)
from reportlab.pdfgen import canvas

HEADER_TEXT = "IT-Ausbildung Kladow"
ACCENT = colors.HexColor("#1f3864")
LINK = colors.HexColor("#1155cc")
GRID = colors.HexColor("#9fb0c8")
HEADBG = colors.HexColor("#dce6f1")
CODEBG = colors.HexColor("#f3f4f6")

PAGE_W, PAGE_H = A4
L_MARGIN = R_MARGIN = 2.0 * cm
T_MARGIN = 2.2 * cm
B_MARGIN = 1.8 * cm
CONTENT_W = PAGE_W - L_MARGIN - R_MARGIN


# ---------- Inline-Formatierung -> reportlab-Minimarkup ----------
def inline(text):
    # Code-Spans zuerst sichern, damit ** und [] darin nicht geparst werden.
    codes = []

    def stash(m):
        codes.append(m.group(1))
        return "\x00%d\x00" % (len(codes) - 1)

    text = re.sub(r"`([^`]+)`", stash, text)
    text = html.escape(text, quote=False)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)

    def link(m):
        label, url = m.group(1), m.group(2)
        if url.startswith("http"):
            return '<a href="%s"><font color="#1155cc">%s</font></a>' % (url, label)
        return '<font color="#1155cc">%s</font>' % label

    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link, text)

    def unstash(m):
        code = html.escape(codes[int(m.group(1))], quote=False)
        return '<font face="Courier" size="8.5">%s</font>' % code

    text = re.sub(r"\x00(\d+)\x00", unstash, text)
    return text


# ---------- Tabellen ----------
def split_row(line):
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [c.strip() for c in line.split("|")]


def build_table(rows, styles):
    header = rows[0]
    body = rows[1:]
    ncol = len(header)
    cell = styles["cell"]
    head = styles["cellhead"]

    def to_cell(txt, st):
        return Paragraph(inline(txt) if txt else "", st)

    data = [[to_cell(c, head) for c in header]]
    for r in body:
        r = (r + [""] * ncol)[:ncol]
        data.append([to_cell(c, cell) for c in r])

    if ncol == 2:
        widths = [CONTENT_W * 0.30, CONTENT_W * 0.70]
    else:
        widths = [CONTENT_W / ncol] * ncol

    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HEADBG),
        ("GRID", (0, 0), (-1, -1), 0.5, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


# ---------- Markdown -> Flowables ----------
def parse(md, styles):
    flow = []
    lines = md.split("\n")
    i = 0
    n = len(lines)
    first_h1 = True

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Code-/Mermaid-Block
        if stripped.startswith("```"):
            lang = stripped[3:].strip()
            i += 1
            buf = []
            while i < n and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1  # schliessendes ```
            if lang == "mermaid":
                flow.append(Paragraph("<i>Architektur-Diagramm (Mermaid-Quelle, gerendert in der Markdown-Fassung):</i>", styles["small"]))
            code = "\n".join(html.escape(b, quote=False) for b in buf)
            flow.append(XPreformatted(code, styles["code"]))
            flow.append(Spacer(1, 6))
            continue

        # Tabelle
        if stripped.startswith("|") and i + 1 < n and re.match(r"^\|[\s:\-|]+\|?$", lines[i + 1].strip()):
            rows = [split_row(stripped)]
            i += 2  # Header + Trennzeile
            while i < n and lines[i].strip().startswith("|"):
                rows.append(split_row(lines[i].strip()))
                i += 1
            flow.append(build_table(rows, styles))
            flow.append(Spacer(1, 8))
            continue

        # Horizontale Linie
        if stripped == "---":
            flow.append(Spacer(1, 4))
            flow.append(HRFlowable(width="100%", thickness=0.7, color=GRID))
            flow.append(Spacer(1, 6))
            i += 1
            continue

        # Ueberschriften
        if stripped.startswith("### "):
            flow.append(Paragraph(inline(stripped[4:]), styles["h3"]))
            i += 1
            continue
        if stripped.startswith("## "):
            flow.append(Paragraph(inline(stripped[3:]), styles["h2"]))
            i += 1
            continue
        if stripped.startswith("# "):
            st = styles["title"] if first_h1 else styles["h1"]
            flow.append(Paragraph(inline(stripped[2:]), st))
            first_h1 = False
            i += 1
            continue

        # Aufzaehlung / nummerierte Liste
        m_ul = re.match(r"^(\s*)[-*]\s+(.*)$", line)
        m_ol = re.match(r"^(\s*)(\d+)\.\s+(.*)$", line)
        if m_ul or m_ol:
            while i < n:
                ll = lines[i]
                mu = re.match(r"^(\s*)[-*]\s+(.*)$", ll)
                mo = re.match(r"^(\s*)(\d+)\.\s+(.*)$", ll)
                if mu:
                    indent = len(mu.group(1))
                    bullet = "&bull;"
                    txt = mu.group(2)
                elif mo:
                    indent = len(mo.group(1))
                    bullet = mo.group(2) + "."
                    txt = mo.group(3)
                else:
                    break
                st = styles["li2"] if indent >= 2 else styles["li"]
                flow.append(Paragraph("%s&nbsp;&nbsp;%s" % (bullet, inline(txt)), st))
                i += 1
            flow.append(Spacer(1, 4))
            continue

        # Leerzeile
        if stripped == "":
            i += 1
            continue

        # Absatz
        flow.append(Paragraph(inline(stripped), styles["body"]))
        i += 1

    return flow


def make_styles():
    ss = getSampleStyleSheet()
    s = {}
    s["title"] = ParagraphStyle("title", parent=ss["Title"], fontName="Helvetica-Bold",
                                fontSize=24, leading=28, textColor=ACCENT, spaceAfter=14)
    s["h1"] = ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=16, leading=20,
                             textColor=ACCENT, spaceBefore=14, spaceAfter=8)
    s["h2"] = ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=13, leading=17,
                             textColor=ACCENT, spaceBefore=14, spaceAfter=6)
    s["h3"] = ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=11, leading=15,
                             textColor=colors.HexColor("#2f5496"), spaceBefore=10, spaceAfter=4)
    s["body"] = ParagraphStyle("body", fontName="Helvetica", fontSize=10, leading=14,
                               spaceAfter=6, alignment=4)  # justify
    s["li"] = ParagraphStyle("li", parent=s["body"], leftIndent=14, spaceAfter=2,
                             alignment=0)
    s["li2"] = ParagraphStyle("li2", parent=s["li"], leftIndent=30)
    s["small"] = ParagraphStyle("small", fontName="Helvetica-Oblique", fontSize=8.5,
                                leading=11, textColor=colors.HexColor("#555555"), spaceAfter=2)
    s["code"] = ParagraphStyle("code", fontName="Courier", fontSize=8, leading=10,
                               backColor=CODEBG, borderPadding=5, textColor=colors.HexColor("#1a1a1a"))
    s["cell"] = ParagraphStyle("cell", fontName="Helvetica", fontSize=8.5, leading=11)
    s["cellhead"] = ParagraphStyle("cellhead", fontName="Helvetica-Bold", fontSize=8.5,
                                   leading=11, textColor=ACCENT)
    return s


class NumberedCanvas(canvas.Canvas):
    """Zweiter Durchlauf, um 'Seite x / n' mit Gesamtzahl zu setzen."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            self._draw_chrome(total)
            super().showPage()
        super().save()

    def _draw_chrome(self, total):
        self.saveState()
        # Kopfzeile
        self.setFont("Helvetica", 8.5)
        self.setFillColor(colors.HexColor("#666666"))
        self.drawString(L_MARGIN, PAGE_H - 1.2 * cm, HEADER_TEXT)
        self.setStrokeColor(GRID)
        self.setLineWidth(0.5)
        self.line(L_MARGIN, PAGE_H - 1.35 * cm, PAGE_W - R_MARGIN, PAGE_H - 1.35 * cm)
        # Fusszeile
        self.setFont("Helvetica", 8.5)
        self.drawCentredString(PAGE_W / 2.0, 1.1 * cm, "%d / %d" % (self._pageNumber, total))
        self.restoreState()


def build(md_path, pdf_path):
    with open(md_path, encoding="utf-8") as f:
        md = f.read()
    styles = make_styles()
    flow = parse(md, styles)
    doc = BaseDocTemplate(pdf_path, pagesize=A4,
                          leftMargin=L_MARGIN, rightMargin=R_MARGIN,
                          topMargin=T_MARGIN, bottomMargin=B_MARGIN)
    frame = Frame(L_MARGIN, B_MARGIN, CONTENT_W, PAGE_H - T_MARGIN - B_MARGIN, id="main")
    doc.addPageTemplates([PageTemplate(id="tmpl", frames=[frame])])
    doc.build(flow, canvasmaker=NumberedCanvas)
    print("OK ->", pdf_path)


if __name__ == "__main__":
    build(sys.argv[1], sys.argv[2])
