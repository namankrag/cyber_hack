"""Build the end-to-end pack PDF from the docs set.

Usage:  python scripts/build_pdf.py   (run from the repo root)
Output: docs/AgentShield_end_to_end.pdf

Reads PITCH.md, README.md, ARCHITECTURE.md, THREAT_MODEL.md,
RED_LOOP_REPORT.md, DEMO_SCRIPT.md + red_loop_ledger.csv and renders one
paginated PDF (portrait, ledger table on landscape pages). Pure reportlab,
no system dependencies.
"""
from __future__ import annotations

import csv
import datetime
import re
import subprocess
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (BaseDocTemplate, Frame, HRFlowable,
                                NextPageTemplate, PageBreak, PageTemplate,
                                Paragraph, Preformatted, Spacer, Table,
                                TableStyle)

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

SANITIZE = {"\U0001f6e1\ufe0f": "", "\U0001f6e1": "", "\u2192": "->",
            "\u2014": "--", "\u2013": "-", "\u2018": "'", "\u2019": "'",
            "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u2713": "yes",
            "\u2714": "yes", "\u25e6": "-", "\u00a0": " "}


def clean(text: str) -> str:
    for src, dst in SANITIZE.items():
        text = text.replace(src, dst)
    return re.sub(r"[^\x00-\xff]", "", text)


def inline_md(text: str) -> str:
    text = clean(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"`([^`]+)`", r'<font face="Courier">\1</font>', text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)
    return text


def styles():
    base = getSampleStyleSheet()
    s = {}
    s["h1"] = ParagraphStyle("h1", parent=base["Heading1"], fontSize=18,
                             spaceBefore=14, spaceAfter=8, textColor=colors.HexColor("#1a1a2e"))
    s["h2"] = ParagraphStyle("h2", parent=base["Heading2"], fontSize=13,
                             spaceBefore=10, spaceAfter=6, textColor=colors.HexColor("#16213e"))
    s["h3"] = ParagraphStyle("h3", parent=base["Heading3"], fontSize=11,
                             spaceBefore=8, spaceAfter=4)
    s["body"] = ParagraphStyle("body", parent=base["Normal"], fontSize=9.5,
                               leading=13.5, spaceAfter=4)
    s["bullet"] = ParagraphStyle("bullet", parent=s["body"], leftIndent=14,
                                 bulletIndent=4, spaceAfter=2)
    s["code"] = ParagraphStyle("code", parent=base["Code"], fontSize=6.5,
                               leading=8, leftIndent=6)
    s["cell"] = ParagraphStyle("cell", parent=base["Normal"], fontSize=7,
                               leading=9)
    s["cellh"] = ParagraphStyle("cellh", parent=s["cell"], textColor=colors.white,
                                fontName="Helvetica-Bold")
    s["cover_title"] = ParagraphStyle("ct", parent=base["Title"], fontSize=30,
                                      spaceAfter=6, textColor=colors.HexColor("#1a1a2e"))
    s["cover_sub"] = ParagraphStyle("cs", parent=base["Normal"], fontSize=12,
                                    leading=16, alignment=1, spaceAfter=3)
    return s


def md_to_flowables(path: Path, s: dict) -> list:
    """Minimal markdown subset: headings, bullets, tables, code, rules."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    out: list = []
    i, in_code, code_buf = 0, False, []
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("```"):
            if in_code:
                out.append(Preformatted(clean("\n".join(code_buf)), s["code"]))
                code_buf = []
            in_code = not in_code
            i += 1
            continue
        if in_code:
            code_buf.append(line)
            i += 1
            continue
        if re.match(r"^\s*\|.*\|\s*$", line):
            tbl, i = [], i
            while i < len(lines) and re.match(r"^\s*\|.*\|\s*$", lines[i]):
                tbl.append(lines[i])
                i += 1
            rows = []
            for r in tbl:
                cells = [c.strip() for c in r.strip().strip("|").split("|")]
                if all(re.match(r"^:?-{2,}:?$", c) for c in cells):
                    continue
                rows.append([Paragraph(inline_md(c), s["cellh"] if not rows else s["cell"])
                             for c in cells])
            if rows:
                w = (A4[0] - 4 * cm) / len(rows[0])
                t = Table(rows, colWidths=[w] * len(rows[0]), repeatRows=1)
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.white, colors.HexColor("#f2f2f7")]),
                ]))
                out += [Spacer(1, 4), t, Spacer(1, 6)]
            continue
        m = re.match(r"^(#{1,3})\s+(.*)", line)
        if m:
            lvl = {"#": "h1", "##": "h2", "###": "h3"}[m.group(1)]
            out.append(Paragraph(inline_md(m.group(2)), s[lvl]))
            i += 1
            continue
        if re.match(r"^\s*---+\s*$", line):
            out.append(HRFlowable(width="100%", thickness=0.6, color=colors.grey))
            i += 1
            continue
        m = re.match(r"^\s*(?:[-*]|\d+[.)])\s+(.*)", line)
        if m:
            out.append(Paragraph(inline_md(m.group(1)), s["bullet"], bulletText="\u2022"))
            i += 1
            continue
        if line.strip():
            out.append(Paragraph(inline_md(line.strip()), s["body"]))
        i += 1
    return out


def ledger_table(s: dict) -> Table:
    with open(DOCS / "red_loop_ledger.csv", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    header, body = rows[0], rows[1:]
    keep = [0, 1, 2, 3, 5, 6, 7, 8]
    head = [header[k] for k in keep]
    data = [[Paragraph(f"<b>{inline_md(c)}</b>", s["cellh"]) for c in head]]
    for r in body:
        data.append([Paragraph(inline_md(r[k]), s["cell"]) for k in keep])
    widths = [34, 30, 52, 92, 150, 48, 48, 60]
    t = Table(data, colWidths=[w for w in widths], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f7")]),
    ]))
    return t


def git_head() -> str:
    try:
        return subprocess.run(["git", "log", "-1", "--format=%h %cs"],
                              capture_output=True, text=True,
                              cwd=ROOT).stdout.strip()
    except Exception:
        return "unknown"


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.grey)
    canvas.drawString(2 * cm, 1.2 * cm, "AgentShield end-to-end pack — muse branch")
    canvas.drawRightString(doc.pagesize[0] - 2 * cm, 1.2 * cm,
                           f"page {doc.page}")
    canvas.restoreState()


def main() -> int:
    s = styles()
    out = DOCS / "AgentShield_end_to_end.pdf"
    doc = BaseDocTemplate(str(out), leftMargin=2 * cm, rightMargin=2 * cm,
                          topMargin=2 * cm, bottomMargin=2 * cm,
                          showBoundary=0)
    pw, ph = A4
    lw, lh = landscape(A4)
    portrait = Frame(doc.leftMargin, doc.bottomMargin, pw - 4 * cm, ph - 4 * cm,
                     id="portrait")
    land = Frame(doc.leftMargin, doc.bottomMargin, lw - 4 * cm, lh - 4 * cm,
                 id="landscape")
    doc.addPageTemplates([
        PageTemplate(id="P", frames=[portrait], pagesize=A4, onPage=footer),
        PageTemplate(id="L", frames=[land], pagesize=landscape(A4),
                     onPage=footer),
    ])

    story: list = [
        Spacer(1, 4 * cm),
        Paragraph("AgentShield", s["cover_title"]),
        Paragraph("Secure the agent, not just the prompt.<br/>"
                  "End-to-end pack: architecture, security model, red-team "
                  "evidence, demo.", s["cover_sub"]),
        Spacer(1, 1 * cm),
        Paragraph(f"muse branch · {clean(git_head())} · "
                  f"{datetime.date.today().isoformat()}<br/>"
                  "81 tests passing · Semgrep 238 rules 0 findings · "
                  "demo 6 beats · 14-doc corpus", s["cover_sub"]),
        PageBreak(),
    ]
    chapters = ["docs/PITCH.md", "README.md", "docs/ARCHITECTURE.md",
                "THREAT_MODEL.md", "docs/RED_LOOP_REPORT.md",
                "docs/DEMO_SCRIPT.md"]
    for ch in chapters:
        story += md_to_flowables(ROOT / ch, s)
        story.append(PageBreak())
    story.append(Paragraph("Red-loop ledger (all 51 items)", s["h1"]))
    story.append(Paragraph("Machine-readable twin: docs/red_loop_ledger.csv",
                           s["body"]))
    story.append(NextPageTemplate("L"))
    story.append(PageBreak())
    story.append(ledger_table(s))
    story.append(NextPageTemplate("P"))
    story.append(PageBreak())

    doc.build(story)
    print(f"wrote {out} ({out.stat().st_size} bytes, {doc.page} pages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
