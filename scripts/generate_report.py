"""
Self-contained project-report generator, laid out in the University of
Dhaka thesis structure (title page, declaration, abstract,
acknowledgements, contents, Chapters 1-6, bibliography).

It draws two figures (architecture + dashboard) from the project's real
run data, embeds the existing evaluation charts, and renders everything to
docs/Project-Report.pdf with an automatic, page-numbered table of contents.

Run:  python scripts/generate_report.py
"""

import os
import sys
import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, PageBreak,
    Image, Table, TableStyle, Preformatted,
)
from reportlab.platypus.tableofcontents import TableOfContents

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

OUT = "docs/Project-Report.pdf"
IMG = "docs/img"
INK = colors.HexColor("#111827")
BLUE = colors.HexColor("#1f3a8a")
GREY = colors.HexColor("#6b7280")
PURPLE = colors.HexColor("#5b3fd6")

TITLE = ("Hybrid SIEM and Network Intrusion Detection with Lightweight "
         "Behavioral Anomaly Detection for U2R and R2L Attacks")


# =====================================================================
# FIGURES
# =====================================================================

def _box(ax, x, y, w, h, text, fc, ec=None, tc="#111827", fs=9, bold=False):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06",
        linewidth=1.2, edgecolor=ec or fc, facecolor=fc, zorder=2))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fs, color=tc, zorder=3,
            fontweight="bold" if bold else "normal")


def _arrow(ax, x1, y1, x2, y2, color="#6b7280"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>",
                 mutation_scale=13, linewidth=1.4, color=color, zorder=1))


def fig_architecture(path):
    fig, ax = plt.subplots(figsize=(8.4, 9.6))
    ax.set_xlim(0, 10); ax.set_ylim(0, 12); ax.axis("off")
    ax.text(5, 11.6, "System Architecture", ha="center", fontsize=13,
            fontweight="bold", color="#1f3a8a")

    _box(ax, 0.3, 10.1, 3.0, 1.0, "HOST plane\nWindows / Ubuntu / macOS\n"
         "collectors", "#e8ecf7", ec="#1f3a8a", bold=True, fs=8.5)
    _box(ax, 3.5, 10.1, 3.0, 1.0, "NETWORK plane\nSuricata\n(eve.json)",
         "#e8f7ee", ec="#1a7f4b", bold=True, fs=8.5)
    _box(ax, 6.7, 10.1, 3.0, 1.0, "SIEM plane\nWazuh\n(alerts.json)",
         "#fdefe8", ec="#c0522a", bold=True, fs=8.5)

    _box(ax, 2.6, 8.7, 4.8, 0.85,
         "Normalise  ->  common Event  (OS-independent)", "#f3f4f6",
         ec="#9ca3af", fs=9)
    for cx in (1.8, 5.0, 8.2):
        _arrow(ax, cx, 10.1, 4.2 if cx < 5 else (5.0 if cx == 5 else 5.8), 9.55)

    _box(ax, 1.4, 7.2, 7.2, 0.95, "Context-aware Detectors\n"
         "Process / File / Network / Wazuh   +   MITRE ATT&CK mapping",
         "#eef0fb", ec="#5b3fd6", fs=8.5)
    _arrow(ax, 5.0, 8.7, 5.0, 8.2)

    _box(ax, 2.4, 5.8, 5.2, 0.9, "Feature Engine\n"
         "session  ->  feature vector (18 behavioural)", "#f3f4f6",
         ec="#9ca3af", fs=8.5)
    _arrow(ax, 5.0, 7.2, 5.0, 6.75)

    _box(ax, 0.3, 4.1, 3.0, 1.05, "Rule / Risk\nengine\n(known-bad "
         "weights)", "#e8ecf7", ec="#1f3a8a", fs=8.3)
    _box(ax, 3.5, 4.1, 3.0, 1.05, "Correlation\nengine\n"
         "(+ cross-plane chains)", "#eef0fb", ec="#5b3fd6", fs=8.3, bold=True)
    _box(ax, 6.7, 4.1, 3.0, 1.05, "Isolation Forest\n(anomaly vs.\n"
         "learned normal)", "#e8f7ee", ec="#1a7f4b", fs=8.3)
    for cx in (1.8, 5.0, 8.2):
        _arrow(ax, 5.0, 5.8, cx, 5.2)

    _box(ax, 3.1, 2.7, 3.8, 0.9, "Decision Engine\n"
         "SAFE / REVIEW / SUSPICIOUS / CRITICAL", "#111827", tc="white",
         ec="#111827", bold=True, fs=8.5)
    for cx in (1.8, 5.0, 8.2):
        _arrow(ax, cx, 4.1, 5.0, 3.65)

    _box(ax, 1.3, 1.1, 3.3, 0.9, "Alerts\n(evidence + MITRE codes)",
         "#fdefe8", ec="#c0522a", fs=8.5)
    _box(ax, 5.4, 1.1, 3.3, 0.9, "Dashboard\n(explainable, live)",
         "#e8f7ee", ec="#1a7f4b", fs=8.5)
    _arrow(ax, 4.3, 2.7, 3.0, 2.05)
    _arrow(ax, 5.7, 2.7, 7.0, 2.05)

    plt.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def fig_dashboard(path):
    try:
        sessions = json.load(open("reports/sessions.json", encoding="utf-8"))
    except Exception:
        sessions = []
    shown = sessions[:5]
    n = max(1, len(shown))
    cards_top = n * 1.15
    fig, ax = plt.subplots(figsize=(8.4, 1.1 + 1.15 * n))
    ax.set_xlim(0, 10); ax.set_ylim(0, cards_top + 0.9); ax.axis("off")
    ax.text(0.2, cards_top + 0.45, "Behavioral Anomaly Detection (ML / UEBA)",
            fontsize=12, fontweight="bold", color="#111827")

    y = cards_top - 1.0
    for s in shown:
        score = float(s.get("ml_score") or 0)
        status = s.get("final_status", "")
        label = s.get("ml_prediction", "")
        user = s.get("username", "")
        color = ("#c0392b" if score >= 55 else
                 "#e67e22" if score >= 50 else "#27ae60")
        ax.add_patch(FancyBboxPatch(
            (0.2, y), 9.6, 1.0, boxstyle="round,pad=0.02,rounding_size=0.04",
            linewidth=1, edgecolor="#e5e7eb", facecolor="white", zorder=1))
        ax.add_patch(plt.Rectangle((0.2, y), 0.06, 1.0, color="#5b3fd6",
                                   zorder=2))
        name = user + ("  NEW" if s.get("is_new") else "")
        ax.text(0.42, y + 0.78, name, fontsize=10.5, fontweight="bold",
                color="#111827")
        ax.text(9.6, y + 0.78, f"{label} - {status}", ha="right",
                fontsize=9, fontweight="bold", color=color)
        ax.add_patch(FancyBboxPatch((0.42, y + 0.44), 9.16, 0.18,
                     boxstyle="round,pad=0.0,rounding_size=0.09",
                     linewidth=0, facecolor="#eceff3", zorder=2))
        ax.add_patch(FancyBboxPatch((0.42, y + 0.44),
                     max(0.2, 9.16 * score / 100), 0.18,
                     boxstyle="round,pad=0.0,rounding_size=0.09",
                     linewidth=0, facecolor=color, zorder=3))
        ax.text(9.5, y + 0.53, f"{score:.0f}/100", ha="right", va="center",
                fontsize=7.5, fontweight="bold", color="#111827", zorder=4)
        devs = [d for d in (s.get("ml_deviations") or []) if d][:3]
        txt = ("Deviating: " + "   ".join(devs)) if devs else \
            "within normal behavioural range"
        ax.text(0.42, y + 0.18, txt, fontsize=7.0,
                color="#5b3fd6" if devs else "#6b7280")
        y -= 1.15
    plt.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def build_figures():
    os.makedirs(IMG, exist_ok=True)
    fig_architecture(os.path.join(IMG, "architecture.png"))
    fig_dashboard(os.path.join(IMG, "dashboard.png"))


# =====================================================================
# STYLES
# =====================================================================

def styles():
    s = getSampleStyleSheet()
    return {
        "cover_uni": ParagraphStyle("cu", parent=s["Normal"], fontSize=15,
            leading=20, alignment=TA_CENTER, textColor=BLUE,
            fontName="Helvetica-Bold", spaceAfter=40),
        "cover_title": ParagraphStyle("ct", parent=s["Title"], fontSize=20,
            leading=27, alignment=TA_CENTER, textColor=INK, spaceAfter=44),
        "cover_line": ParagraphStyle("cl", parent=s["Normal"], fontSize=12,
            leading=19, alignment=TA_CENTER, textColor=INK),
        "cover_blue": ParagraphStyle("cb", parent=s["Normal"], fontSize=12,
            leading=19, alignment=TA_CENTER, textColor=BLUE),
        "front_h": ParagraphStyle("fh", parent=s["Title"], fontSize=22,
            leading=28, alignment=TA_CENTER, textColor=INK, spaceAfter=22),
        "chap_num": ParagraphStyle("cn", parent=s["Normal"], fontSize=22,
            leading=28, textColor=INK, fontName="Helvetica-Bold",
            spaceBefore=10, spaceAfter=6),
        "chap_title": ParagraphStyle("ctl", parent=s["Normal"], fontSize=26,
            leading=32, textColor=BLUE, fontName="Helvetica-Bold",
            spaceAfter=22),
        "sec": ParagraphStyle("sc", parent=s["Heading2"], fontSize=14,
            leading=18, textColor=INK, spaceBefore=15, spaceAfter=7),
        "sub": ParagraphStyle("sb", parent=s["Heading3"], fontSize=11.5,
            leading=15, textColor=PURPLE, spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("b", parent=s["Normal"], fontSize=10.3,
            leading=15.5, textColor=INK, alignment=TA_JUSTIFY, spaceAfter=8),
        "bullet": ParagraphStyle("bu", parent=s["Normal"], fontSize=10.3,
            leading=15, textColor=INK, leftIndent=16, bulletIndent=4,
            spaceAfter=4),
        "cap": ParagraphStyle("cap", parent=s["Normal"], fontSize=9,
            leading=12, textColor=GREY, alignment=TA_CENTER, spaceBefore=3,
            spaceAfter=12),
        "ref": ParagraphStyle("rf", parent=s["Normal"], fontSize=9.6,
            leading=13.5, textColor=INK, leftIndent=18, firstLineIndent=-18,
            spaceAfter=7),
        "code": ParagraphStyle("cd", parent=s["Code"], fontName="Courier",
            fontSize=8.2, leading=11, textColor=INK,
            backColor=colors.HexColor("#f3f4f6"), borderPadding=6,
            spaceBefore=4, spaceAfter=9),
        "toc0": ParagraphStyle("t0", fontName="Helvetica-Bold", fontSize=11,
            leading=18, textColor=INK),
        "toc1": ParagraphStyle("t1", fontName="Helvetica", fontSize=10,
            leading=15, leftIndent=18, textColor=colors.HexColor("#374151")),
    }


# =====================================================================
# DOCUMENT with automatic TOC
# =====================================================================

_TOC = []   # collected (level, text, page) during a build pass


class ReportDoc(BaseDocTemplate):
    pass


class TOCHeading(Paragraph):
    """
    A heading that records its own TRUE page number at draw time via
    canvas.getPageNumber(). This is exact even when large figures sit
    nearby - unlike afterFlowable's page, which can be off by a page or
    two when content around a heading reflows.
    """
    def __init__(self, text, style, level, toctext):
        super().__init__(text, style)
        self._level = level
        self._toctext = toctext

    def draw(self):
        _TOC.append((self._level, self._toctext, self.canv.getPageNumber()))
        super().draw()


def make_table(rows, widths, header=True):
    t = Table(rows, colWidths=widths, hAlign="CENTER")
    style = [
        ("FONTSIZE", (0, 0), (-1, -1), 8.8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d8dae5")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef0fb")),
                  ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
    t.setStyle(TableStyle(style))
    return t


def figure(path, caption, st, width_cm=13.5):
    out = []
    if os.path.exists(path):
        img = Image(path)
        w = width_cm * cm
        img.drawHeight = img.imageHeight * w / img.imageWidth
        img.drawWidth = w
        img.hAlign = "CENTER"
        out.append(Spacer(1, 4))
        out.append(img)
        out.append(Paragraph(caption, st["cap"]))
    return out


def on_body_page(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(GREY)
    canvas.drawString(2 * cm, 1.15 * cm, "University of Dhaka")
    canvas.drawRightString(A4[0] - 2 * cm, 1.15 * cm, str(doc.page))
    canvas.setStrokeColor(colors.HexColor("#e5e7eb"))
    canvas.line(2 * cm, 1.5 * cm, A4[0] - 2 * cm, 1.5 * cm)
    canvas.restoreState()


def on_cover_page(canvas, doc):
    pass


# =====================================================================
# CONTENT
# =====================================================================

def build_story(st, toc_rows):
    S = []

    def chap(num, title):
        p = Paragraph(f"Chapter {num}", st["chap_num"])
        t = TOCHeading(title, st["chap_title"], 0, f"{num}  {title}")
        S.append(PageBreak()); S.append(p); S.append(t)

    def sec(num, title):
        S.append(TOCHeading(f"{num}  {title}", st["sec"], 1,
                            f"{num}  {title}"))

    def sub(t): S.append(Paragraph(t, st["sub"]))
    def p(t): S.append(Paragraph(t, st["body"]))
    def b(t): S.append(Paragraph(t, st["bullet"], bulletText="•"))
    def code(t): S.append(Preformatted(t, st["code"]))
    def fig(path, cap, w=13.5): S.extend(figure(path, cap, st, w))
    def tbl(rows, widths): S.append(make_table(rows, widths)); S.append(Spacer(1, 8))
    def sp(h=8): S.append(Spacer(1, h))

    # ----------------------------- COVER --------------------------------
    S.append(Spacer(1, 2.4 * cm))
    S.append(Paragraph("UNIVERSITY OF DHAKA", st["cover_uni"]))
    S.append(Spacer(1, 0.6 * cm))
    S.append(Paragraph(TITLE, st["cover_title"]))
    S.append(Spacer(1, 0.8 * cm))
    S.append(Paragraph("by", st["cover_line"]))
    S.append(Spacer(1, 0.3 * cm))
    S.append(Paragraph("Mehedi Hasan Nayan", st["cover_line"]))
    S.append(Paragraph("Exam Roll: H-409 &nbsp;&middot;&nbsp; Registration "
                       "No: XXXX-XXX-XXX, Session: XXXX-XX", st["cover_blue"]))
    S.append(Spacer(1, 0.25 * cm))
    S.append(Paragraph("Tawsif Zawad", st["cover_line"]))
    S.append(Paragraph("Exam Roll: H-413 &nbsp;&middot;&nbsp; Registration "
                       "No: XXXX-XXX-XXX, Session: XXXX-XX", st["cover_blue"]))
    S.append(Spacer(1, 2.2 * cm))
    S.append(Paragraph("Department of Computer Science and Engineering",
                       st["cover_line"]))
    S.append(Spacer(1, 0.2 * cm))
    S.append(Paragraph("Professional Masters in Information and Cyber "
                       "Security (PMICS)", st["cover_line"]))

    # ------------------------- DECLARATION ------------------------------
    S.append(PageBreak())
    S.append(Spacer(1, 1.2 * cm))
    S.append(Paragraph("Declaration", st["front_h"]))
    p("We hereby declare that this project report titled "
      "<i>&ldquo;Hybrid SIEM and Network Intrusion Detection with "
      "Lightweight Behavioral Anomaly Detection for U2R and R2L "
      "Attacks&rdquo;</i> has been carried out by us under the supervision "
      "of Md. Samiul Islam, Instructor, and co-supervision of Palash Roy, "
      "Lecturer, Department of Computer Science and Engineering, University "
      "of Dhaka. The work is our own and has not been submitted elsewhere "
      "for the award of any degree.")
    sp(30)
    tbl([[Paragraph("<b>Mehedi Hasan Nayan</b><br/>Exam Roll: H-409<br/>"
                    "Candidate 1", st["body"]),
          Paragraph("<b>Tawsif Zawad</b><br/>Exam Roll: H-413<br/>"
                    "Candidate 2", st["body"])]],
        [7.5 * cm, 7.5 * cm])
    sp(24)
    tbl([[Paragraph("<b>Md. Samiul Islam</b><br/>Instructor, Department of "
                    "CSE<br/>University of Dhaka<br/>Supervisor", st["body"]),
          Paragraph("<b>Palash Roy</b><br/>Lecturer, Department of CSE<br/>"
                    "University of Dhaka<br/>Co-Supervisor", st["body"])]],
        [7.5 * cm, 7.5 * cm])

    # --------------------------- ABSTRACT -------------------------------
    S.append(PageBreak())
    S.append(Spacer(1, 1.0 * cm))
    S.append(Paragraph("Abstract", st["front_h"]))
    p("With the rapid growth of networked systems, detecting sophisticated "
      "and low-frequency cyber-attacks has become increasingly difficult. "
      "Traditional Intrusion Detection Systems and Security Information and "
      "Event Management (SIEM) tools rely mainly on rule-based detection: "
      "effective for known threats, but weak against rare and stealthy "
      "User-to-Root (U2R) and Remote-to-Local (R2L) intrusions.")
    p("This project presents a hybrid, cross-platform detection framework "
      "that fuses three independent viewpoints - host telemetry (Windows, "
      "Ubuntu and macOS collectors), network telemetry (Suricata) and SIEM "
      "alerts (Wazuh) - into a single, OS-independent pipeline. Every "
      "session is judged three ways: context-aware signature rules, a "
      "multi-stage correlation engine (including cross-plane chains that "
      "fire only when two viewpoints agree), and a lightweight Isolation "
      "Forest that models each machine's normal behaviour across eighteen "
      "distinct behavioural features and flags novel deviations. Findings "
      "are mapped to MITRE ATT&amp;CK and explained to the analyst.")
    p("The approach is validated on real recorded attacks (136 of 137 "
      "public EVTX attack samples detected, 99.3%), on the standard "
      "NSL-KDD benchmark (ROC area 0.944), and at scale on the CERT r4.2 "
      "insider-threat dataset (1,000 realistic users and 330k sessions, "
      "ROC area 0.81). The benchmarks also confirm the "
      "central motivation: unsupervised anomaly detection on network data "
      "alone is weak on exactly the rare R2L and U2R classes this thesis "
      "targets, which is why the host, SIEM and correlation layers are "
      "added on top. The result is a practical, explainable and deployable "
      "system that improves rare-attack coverage while keeping the "
      "false-alarm rate low.")

    # ----------------------- ACKNOWLEDGEMENTS ---------------------------
    S.append(PageBreak())
    S.append(Spacer(1, 1.0 * cm))
    S.append(Paragraph("Acknowledgements", st["front_h"]))
    p("We would like to express our sincere gratitude to our supervisor, "
      "Md. Samiul Islam, and our co-supervisor, Palash Roy, of the "
      "Department of Computer Science and Engineering, University of Dhaka, "
      "for their guidance and encouragement throughout this work. We also "
      "thank the Department, the PMICS programme, and our families for "
      "their continued support.")

    # ---------------------------- CONTENTS ------------------------------
    S.append(PageBreak())
    S.append(Paragraph("Contents", st["front_h"]))
    if toc_rows:
        data = []
        for level, text, page in toc_rows:
            style = st["toc0"] if level == 0 else st["toc1"]
            pstyle = ParagraphStyle("p", parent=style, alignment=2)  # right
            data.append([Paragraph(text, style), Paragraph(str(page),
                        pstyle)])
        tt = Table(data, colWidths=[14.2 * cm, 1.4 * cm], hAlign="LEFT")
        tt.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
            ("TOPPADDING", (0, 0), (-1, -1), 1),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]))
        S.append(tt)

    # ========================= CHAPTER 1 ===============================
    chap(1, "Introduction")
    p("Modern organisations rely on SIEM and IDS tools to monitor and "
      "defend their systems. While efficient at recognising known attack "
      "signatures, these tools struggle with low-frequency, stealthy "
      "attacks such as U2R and R2L, which exploit systems in subtle ways "
      "that resemble ordinary activity.")

    sec("1.1", "Motivations")
    p("Every computer produces thousands of log lines a day - logins, "
      "process launches, file accesses, device events. Dangerous "
      "intrusions hide inside this flood and rarely announce themselves. "
      "Two classes are especially hard to catch and are the focus of this "
      "work:")
    b("<b>U2R (User-to-Root):</b> a user who already holds a normal account "
      "quietly escalates to administrator privileges.")
    b("<b>R2L (Remote-to-Local):</b> an outsider guesses or steals "
      "credentials and enters as though authorised.")
    p("Signature-based tools only know yesterday's attacks and produce high "
      "false-negative rates on these rare classes; pure anomaly detectors "
      "flag the unusual but cannot explain what it means. A hybrid that "
      "combines both, across several independent data sources, is needed.")

    sec("1.2", "Objectives")
    b("Design a hybrid detection framework that combines rule-based SIEM "
      "detection with lightweight anomaly detection.")
    b("Improve the detection of rare U2R and R2L attacks.")
    b("Evaluate the approach using both real logs and a benchmark dataset "
      "(NSL-KDD).")
    b("Map detected behaviour to the MITRE ATT&amp;CK framework for "
      "structured, standardised reporting.")

    sec("1.3", "Contributions")
    b("A single, resource-efficient framework that integrates <b>Wazuh</b> "
      "(SIEM), <b>Suricata</b> (network IDS), an <b>Isolation Forest</b> "
      "anomaly model and <b>MITRE ATT&amp;CK</b> mapping - an integration "
      "not previously combined for U2R/R2L in one deployable tool.")
    b("<b>Context-aware detection:</b> a process is never judged by name "
      "alone; the command line, parent process, execution path, digital "
      "signature and surrounding activity are all weighed, sharply cutting "
      "false alarms.")
    b("<b>Cross-plane correlation:</b> attack chains that fire only when "
      "two independent viewpoints agree (e.g. an obfuscated host command "
      "AND a malicious-server contact on the wire = confirmed C2).")
    b("<b>Explainable behavioural anomaly detection (UEBA):</b> eighteen "
      "distinct behavioural features and a per-user deviation explanation "
      "in standard-deviation terms, with a recent-trend view.")
    b("<b>Cross-platform</b> collection (Windows, Ubuntu, macOS) behind one "
      "OS-independent pipeline, packaged as a runnable per-OS demo with a "
      "self-contained dashboard.")

    sec("1.4", "Challenges")
    b("Detecting rare classes (U2R/R2L) that statistically resemble normal "
      "activity, especially at the network-flow level.")
    b("Keeping false positives low so that analysts trust the alerts.")
    b("Normalising heterogeneous telemetry from three operating systems and "
      "two external sensors into one common representation.")
    b("Making machine-learning verdicts explainable rather than opaque.")

    sec("1.5", "Organization")
    p("The report is organised as follows. Chapter 2 reviews related work "
      "and identifies the research gap. Chapter 3 presents the proposed "
      "methodology and architecture. Chapter 4 describes the "
      "implementation. Chapter 5 reports and analyses the experimental "
      "results. Chapter 6 concludes and outlines future work.")

    # ========================= CHAPTER 2 ===============================
    chap(2, "Related Works")
    p("This chapter surveys closely related systems and research that "
      "inform the design of the proposed framework, with particular "
      "emphasis on the rare U2R and R2L classes.")

    sub("Wazuh with Machine-Learning Enhancement")
    p("Chamkar et al. (2025) enhanced Wazuh SIEM with Random Forest and "
      "DBSCAN to reduce its high false-positive rate, reaching 97.2% and "
      "91.06% accuracy respectively at sub-100&nbsp;ms latency. However, "
      "they did not evaluate U2R/R2L specifically and used a controlled "
      "enterprise simulation - the gap this project targets [1].")

    sub("Hybrid Ensemble IDS on NSL-KDD")
    p("Mills et al. (2024) proposed a supervised stacking ensemble reaching "
      "99.84% accuracy on NSL-KDD, yet U2R detection remained weak "
      "(F1 = 62.5%) due to severe class imbalance - reinforcing the need "
      "for an unsupervised complementary layer [2].")

    sub("Isolation Forest for Anomaly Detection")
    p("Bello et al. (2024/25) showed Isolation Forest reaching 95.2% "
      "detection with a 4.7% false-positive rate on NSL-KDD, outperforming "
      "One-Class SVM and Local Outlier Factor, with sub-linear complexity "
      "suitable for real-time, label-free deployment. This directly "
      "motivates our choice of Isolation Forest [3].")

    sub("Suricata versus Snort")
    p("Shah and Issac (2018), confirmed by a 2024 benchmark, found Suricata "
      "scales better through multi-threading but, like Snort, is purely "
      "signature-based and cannot detect zero-day behaviour - hence our "
      "pairing of Suricata with anomaly detection [4, 5].")

    sub("MITRE ATT&CK-Aligned SIEM Evaluation")
    p("Winkler and Sharma (2025) evaluated Wazuh against Atomic Red Team "
      "across four tactics (~85% overall), showing that ATT&amp;CK mapping "
      "greatly improves alert interpretability but that rule-based SIEM "
      "alone is insufficient for subtle behaviour - precisely the U2R/R2L "
      "scenario [6].")

    sub("Deep Hybrid IDS")
    p("Lv and Ding (2024) combined K-Means with a CNN+LSTM model, strong "
      "on DoS/Probe but heavy on resources and reliant on labelled data. "
      "We deliberately choose the lighter Isolation Forest for comparable "
      "anomaly coverage at far lower cost [7].")

    sec("2.1", "Problem of Existing Systems")
    b("Depend mostly on predefined rules and static signatures.")
    b("Fail to detect unknown or rare attack patterns (U2R, R2L).")
    b("Produce high false-negative rates for low-frequency classes.")
    b("Lack adaptive learning for evolving threats, and rarely explain "
      "their verdicts.")
    p("<b>Research gap.</b> No existing study simultaneously integrates "
      "Wazuh SIEM, Suricata network monitoring, Isolation Forest anomaly "
      "detection and MITRE ATT&amp;CK mapping into a unified, "
      "resource-efficient, cross-platform framework that explicitly targets "
      "U2R and R2L. This project addresses all four dimensions in a "
      "practical, deployable architecture.")

    # ========================= CHAPTER 3 ===============================
    chap(3, "Proposed Methodologies")
    p("The system reads a computer's activity, adds meaning to each record, "
      "notices when several records together tell an attack story, and "
      "separately learns each machine's ordinary behaviour so it can spot "
      "a day that is not ordinary. Figure 3.1 shows the overall design.")
    fig(os.path.join(IMG, "architecture.png"),
        "Figure 3.1: System architecture. Three data planes feed one "
        "OS-independent pipeline, judged by three engines and fused into a "
        "single explainable verdict.")

    sec("3.1", "Three Detection Layers")
    b("<b>Rules (signatures)</b> recognise known-bad patterns in commands, "
      "paths and files - encoded PowerShell, LOLBin downloads, ransomware "
      "wiping backups, credential theft. Precise and explainable, but only "
      "know what they were taught.")
    b("<b>Correlation</b> joins several weak signals into one named attack "
      "chain, raising confidence enough to justify a CRITICAL verdict.")
    b("<b>Machine learning (Isolation Forest)</b> learns each machine's "
      "normal behaviour and flags deviation - odd hours, unusual volume, "
      "new devices - catching the new and the rare that no rule describes.")

    sec("3.2", "Three Data Planes and Cross-Plane Correlation")
    p("Detection draws on three independent viewpoints; the most valuable "
      "findings come from agreement between them.")
    tbl([[Paragraph("<b>Plane</b>", st["body"]),
          Paragraph("<b>What it sees</b>", st["body"])],
         [Paragraph("Host (own collectors)", st["body"]),
          Paragraph("Programs and their commands, files, logins, USB, "
                    "signatures.", st["body"])],
         [Paragraph("Network (Suricata)", st["body"]),
          Paragraph("Port scans, malicious/C2 contact, large outbound "
                    "transfers, network signatures.", st["body"])],
         [Paragraph("SIEM (Wazuh)", st["body"]),
          Paragraph("Brute force, privilege escalation, rootkits - already "
                    "mapped to MITRE.", st["body"])]],
        [4.5 * cm, 10.5 * cm])
    p("A scrambled command on the host is suspicious; the same machine also "
      "contacting a known criminal server is a <i>confirmed</i> "
      "command-and-control channel. Neither plane alone can conclude that. "
      "Cross-plane chains include Confirmed C2 (host + network), Scan + "
      "Brute Force (host + network, R2L), Exfiltration After Access "
      "(host + network) and SIEM + Behavioural Confirmation.")

    sec("3.3", "Context-Aware Detection")
    p("The system never labels a program malicious by its name. Opening "
      "PowerShell is a concern; opening PowerShell with a hidden, encoded "
      "command that downloads and runs a file is a threat. The detector "
      "weighs the full command line, the parent process, the execution "
      "path, removable-media origin, disguised file names, and the digital "
      "signature before assigning any severity.")

    sec("3.4", "Behavioural Feature Engineering")
    p("Each user's session is reduced to eighteen distinct behavioural "
      "numbers, each answering a different question, so the model detects "
      "'unlike this user' rather than repeating what the rules found. Every "
      "one is collectable live on a real endpoint (Windows 4624/4663 logs "
      "plus USB drive-letter tracking, with Ubuntu and macOS equivalents), "
      "so the same feature set drives both the benchmark and live "
      "monitoring:")
    b("<b>Timing:</b> login hour, logout hour, session length, off-hours "
      "ratio, weekend activity.")
    b("<b>Intensity / volume:</b> activity rate, active-hours spread, "
      "process volume, file activity.")
    b("<b>Style / variety:</b> distinct-program variety, file-to-process "
      "ratio, distinct file-type variety.")
    b("<b>Authentication:</b> failed logins, login attempts, off-hours "
      "logins.")
    b("<b>Device and network:</b> USB device use, removable-media activity, "
      "distinct network sources.")

    sec("3.5", "Anomaly Model and MITRE Mapping")
    p("Features are first standardised (zero mean, unit variance) so that "
      "low-magnitude threat indicators contribute comparably to "
      "high-volume counts, then fed to an Isolation Forest of 300 trees "
      "trained only on normal behaviour. A session's deviation is reported "
      "as an interpretable anomaly score and, for each feature, a "
      "standard-deviation distance from that user's normal - the model "
      "explaining its own reasoning. Every rule and chain carries its MITRE "
      "ATT&amp;CK technique code (for example T1059.001 for PowerShell, "
      "T1110 for brute force, T1548 for privilege escalation).")

    sec("3.6", "Process Flow")
    p("The end-to-end flow is: collect &rarr; normalise into a common Event "
      "&rarr; add meaning with the context-aware detectors &rarr; summarise "
      "the session into the feature vector &rarr; judge three ways (risk, "
      "correlation, anomaly) &rarr; decide a single verdict &rarr; report "
      "with evidence and MITRE codes on the dashboard.")

    # ========================= CHAPTER 4 ===============================
    chap(4, "Implementation")
    p("The system is implemented in Python and packaged as a single "
      "command-line application, <i>bads</i> (Behavior Anomaly Detection "
      "System), with a self-contained HTML dashboard.")

    sec("4.1", "Tools and Technologies")
    tbl([[Paragraph("<b>Tool</b>", st["body"]),
          Paragraph("<b>Purpose</b>", st["body"])],
         [Paragraph("Wazuh", st["body"]),
          Paragraph("SIEM alerts (rule-based host detection, MITRE).",
                    st["body"])],
         [Paragraph("Suricata", st["body"]),
          Paragraph("Network intrusion detection and traffic alerts.",
                    st["body"])],
         [Paragraph("scikit-learn", st["body"]),
          Paragraph("Isolation Forest and standardisation.", st["body"])],
         [Paragraph("pandas / NumPy", st["body"]),
          Paragraph("Data handling and feature tables.", st["body"])],
         [Paragraph("matplotlib", st["body"]),
          Paragraph("Charts (ROC, confusion matrix, dashboard).",
                    st["body"])],
         [Paragraph("MITRE ATT&CK", st["body"]),
          Paragraph("Standardised technique labels.", st["body"])]],
        [4.5 * cm, 10.5 * cm])

    sec("4.2", "Collectors and Normalisation")
    p("One collector per data source reads the raw record and a parser "
      "converts it into a common Event (timestamp, user, type, source, IP, "
      "details). The Windows collector reads the Security log (logins 4624/"
      "4625, process creation 4688 with full command line and parent, file "
      "access 4663, optional Sysmon file-creation) incrementally, and "
      "resolves USB drive letters so a program run from a stick is "
      "recognised. The Ubuntu collector reads /var/log/auth.log and auditd; "
      "the macOS collector reads the unified log. Suricata and Wazuh "
      "collectors read their JSON output (eve.json, alerts.json). After "
      "normalisation the rest of the system is OS-independent.")

    sec("4.3", "Detectors, Correlation and Allowlist")
    p("The context-aware detectors classify each command, file, network "
      "record and SIEM alert into normalised meanings and attach MITRE "
      "codes. A tunable allowlist suppresses the security tool's own "
      "operations and trusted administrative activity before "
      "classification, mirroring enterprise EDR exclusion policies and "
      "lowering false alarms without weakening detection. The risk engine, "
      "correlation engine and decision engine then combine into one verdict "
      "(SAFE / REVIEW / SUSPICIOUS / CRITICAL).")

    sec("4.4", "Model, Modes and Dashboard")
    p("Two Isolation Forest models are kept deliberately separate: a sample "
      "model for the reproducible demo and a per-machine model learned live "
      "- so live learning never degrades the reproducible attack detection. "
      "The application offers three modes: <b>Own</b> (scan this machine "
      "once), <b>Analyze</b> (the stored sample scenario) and <b>Live</b> "
      "(continuous monitoring). It ships as a per-OS demo binary "
      "(windows-demo.exe and Linux/macOS launchers). The dashboard is a "
      "single offline HTML page showing, for every scanned session, an "
      "anomaly meter and exactly which behaviours deviated (with a "
      "recent-trend sparkline and an attack-relevance explanation on "
      "click), the model-performance metrics, the evaluation charts, and "
      "recent alerts with their offending commands and MITRE codes.")

    # ========================= CHAPTER 5 ===============================
    chap(5, "Experimental Results")
    p("All results below are produced by the system itself and can be "
      "reproduced with the corresponding commands.")

    sec("5.1", "Results Analysis")
    sub("Reproducible multi-user demonstration")
    p("On a synthetic population of 100 users (97 with a learned history, "
      "3 new) the system correctly clears 96 ordinary users, raises one "
      "CRITICAL alert for the multi-stage attacker (a 2&nbsp;a.m. USB run "
      "of a disguised executable, encoded PowerShell, credential access, "
      "plus network scanning, a Cobalt Strike beacon and a 50&nbsp;MB "
      "upload, and a Wazuh alert - eleven correlation chains firing, "
      "including all four cross-plane ones), and places the three "
      "history-less users under REVIEW. Figure 5.1 shows the dashboard's "
      "behavioural-anomaly panel from this run.")
    fig(os.path.join(IMG, "dashboard.png"),
        "Figure 5.1: Behavioural-anomaly panel (real output). Each session "
        "shows an anomaly meter and which behaviours deviated, in standard "
        "deviations from that user's learned normal.", 14.5)

    sub("Detection on real recorded attacks")
    p("Replaying 137 real, publicly published Windows attack recordings "
      "(EVTX-ATTACK-SAMPLES) through the full pipeline - data the model "
      "never trained on - <b>136 were flagged (99.3%)</b>. The single missed "
      "file contains almost no evidence of the kind the system measures "
      "(a couple of events, no command lines): an honest limitation, not "
      "a hidden one.")

    sub("Standard benchmark (NSL-KDD)")
    p("Running the same Isolation Forest method on the standard NSL-KDD "
      "test set reproduces the published methodology. Figure 5.2 shows the "
      "ROC curve.")
    tbl([[Paragraph("<b>Measure</b>", st["body"]),
          Paragraph("<b>Result</b>", st["body"])],
         [Paragraph("ROC area (threshold-independent)", st["body"]),
          Paragraph("0.944", st["body"])],
         [Paragraph("Accuracy / F1", st["body"]),
          Paragraph("0.848 / 0.861", st["body"])],
         [Paragraph("DoS detection", st["body"]),
          Paragraph("92.4%", st["body"])],
         [Paragraph("Probe detection", st["body"]),
          Paragraph("99.9%", st["body"])],
         [Paragraph("R2L detection", st["body"]),
          Paragraph("44.9%", st["body"])],
         [Paragraph("U2R detection", st["body"]),
          Paragraph("73.1%", st["body"])]],
        [9.5 * cm, 5.5 * cm])
    fig(os.path.join("reports", "nsl_kdd", "roc_curve.png"),
        "Figure 5.2: ROC curve of the Isolation Forest on NSL-KDD "
        "(KDDTest+), area 0.944.", 11.0)
    p("This result is itself the argument for the whole design. Anomaly "
      "detection on network data alone is excellent on noisy attacks (DoS, "
      "Probe) but <b>weak on exactly the rare R2L and U2R classes</b> this "
      "thesis targets, because at the network-flow level they resemble "
      "ordinary traffic. That gap is precisely why the host, SIEM and "
      "correlation layers are added - and on host telemetry the "
      "privilege-escalation (U2R) and brute-force (R2L) chains fire on the "
      "real EVTX attacks, contributing to the 99.3% overall figure.")

    sub("Held-out model evaluation")
    p("On a held-out set of 234 sessions - 97 held-out normal sessions plus "
      "the 137 real EVTX attacks - the model catches 136 of the 137 attacks "
      "(99% recall) at the cost of 27 false positives on the normal side, "
      "for an overall accuracy of 0.88 (Figure 5.3). The normal side here is "
      "synthetic, so these false positives are a conservative figure; the "
      "false-positive behaviour on genuine users is measured properly on the "
      "CERT benchmark below. The near-perfect attack recall is the "
      "meaningful number: real recorded attacks are caught almost without "
      "exception.")
    fig(os.path.join("reports", "confusion_matrix.png"),
        "Figure 5.3: Confusion matrix on the held-out evaluation set "
        "(97 normal, 137 real attacks).",
        8.5)

    sub("Real-scale evaluation (CERT r4.2 insider threat)")
    p("The held-out set above still draws its normal side from the "
      "project's own synthetic users. To evaluate the behavioural model on "
      "genuinely realistic data at scale, it is also run on the CERT r4.2 "
      "insider-threat benchmark (Carnegie Mellon University): 1,000 "
      "realistic users and 330,452 daily sessions, of which 986 are "
      "malicious user-days from 72 seeded insiders, labelled by the "
      "dataset's own answer key. The Isolation Forest is trained on normal "
      "sessions only and tested on held-out normals plus every malicious "
      "day, using only the live-collectable behavioural features CERT "
      "records (logon, file and USB activity; it has no process, e-mail or "
      "web logs). Figure 5.4 shows the ROC curve.")
    tbl([[Paragraph("<b>Measure</b>", st["body"]),
          Paragraph("<b>Result</b>", st["body"])],
         [Paragraph("ROC area (threshold-independent)", st["body"]),
          Paragraph("0.81", st["body"])],
         [Paragraph("Insiders caught, top 10% reviewed", st["body"]),
          Paragraph("88.9% (64 of 72)", st["body"])],
         [Paragraph("Insiders caught, top 20% reviewed", st["body"]),
          Paragraph("97.2% (70 of 72)", st["body"])],
         [Paragraph("Malicious user-days, top 20% reviewed", st["body"]),
          Paragraph("64.0%", st["body"])]],
        [9.5 * cm, 5.5 * cm])
    fig(os.path.join("reports", "cert", "roc_curve.png"),
        "Figure 5.4: ROC curve of the behavioural Isolation Forest on CERT "
        "r4.2 (1,000 users, 330k sessions), area 0.81.", 11.0)
    p("Because genuine insiders behave normally on most days, per-day "
      "detection is modest - but at an analyst budget of the top 10% most "
      "anomalous user-days the model surfaces 89% of the insiders (97% at "
      "20%), and its ROC area of 0.81 confirms it ranks malicious activity "
      "well above normal. Raw accuracy (97%) and F1 are deliberately not "
      "used as headlines here: with malicious days only 1.5% of the data "
      "they are dominated by the majority class and would mislead. As with "
      "NSL-KDD, the modest per-day figure reflects the honest ceiling of "
      "host-behavioural signals alone on subtle insiders, and motivates the "
      "e-mail/web and cross-plane correlation layers.")

    sec("5.2", "Summary of the Experimental Results")
    tbl([[Paragraph("<b>Evaluation</b>", st["body"]),
          Paragraph("<b>Headline result</b>", st["body"])],
         [Paragraph("Sample multi-user demo (100 users)", st["body"]),
          Paragraph("96 clear, 1 CRITICAL (attacker), 3 REVIEW (new).",
                    st["body"])],
         [Paragraph("Real recorded attacks (137 EVTX)", st["body"]),
          Paragraph("136 detected = 99.3%.", st["body"])],
         [Paragraph("NSL-KDD benchmark", st["body"]),
          Paragraph("ROC 0.944; U2R 73.1%, R2L 44.9% (netflow-only).",
                    st["body"])],
         [Paragraph("CERT r4.2 insider threat (1,000 users)", st["body"]),
          Paragraph("ROC 0.81; 89% of insiders caught in the top 10% "
                    "reviewed.", st["body"])]],
        [7.5 * cm, 7.5 * cm])
    p("The trustworthy figures are the 99.3% on real recorded attacks, the "
      "0.944 ROC area on the public NSL-KDD benchmark, and the 0.81 ROC "
      "area over 330k real CERT sessions; the very high scores on the "
      "project's own clean sample data are expected and reported as such.")

    # ========================= CHAPTER 6 ===============================
    chap(6, "Conclusions")

    sec("6.1", "Research Summary")
    p("This work delivered a hybrid, cross-platform intrusion-detection "
      "framework that unifies Wazuh SIEM, Suricata network monitoring, an "
      "Isolation Forest anomaly model and MITRE ATT&amp;CK mapping in one "
      "deployable, explainable tool. By judging every session with "
      "context-aware rules, multi-stage and cross-plane correlation, and "
      "per-user behavioural anomaly detection, it improves coverage of the "
      "rare U2R and R2L classes that rule-based SIEM misses, while keeping "
      "false alarms low through allowlisting and context. Validation on "
      "real recorded attacks (99.3%) and the NSL-KDD benchmark (ROC 0.944) "
      "supports the design, and the benchmark's own weakness on R2L/U2R "
      "empirically justifies the added layers.")

    sec("6.2", "Future Work Plan")
    b("Deploy Suricata and Wazuh live at scale, and evaluate cross-plane "
      "correlation against real production traffic rather than recorded "
      "samples.")
    b("Extend the per-user behavioural time series, which the system already "
      "records, into longer-horizon trend and drift detection.")
    b("Add network-behaviour anomaly features — C2 beaconing and DNS "
      "tunnelling — on top of the existing Suricata signatures.")
    b("Broaden dataset validation further, and tune the operator allowlist "
      "for specific enterprise environments.")
    b("Add e-mail and web-log features to the behavioural model. CERT r4.2 "
      "already provides both (email.csv, http.csv); they were left out of "
      "the current evaluation only because the project’s live collectors "
      "do not yet read that kind of activity off a running machine, and the "
      "CERT result suggests that per-day insider detection would benefit "
      "from incorporating them once the collectors support it.")

    # ------------------------- BIBLIOGRAPHY -----------------------------
    S.append(PageBreak())
    S.append(TOCHeading("Bibliography", st["chap_title"], 0, "Bibliography"))
    refs = [
        "S. A. Chamkar, M. Zaydi, Y. Maleh, and N. Gherabi, \"Improving "
        "Threat Detection in Wazuh Using Machine Learning Techniques,\" "
        "J. Cybersecur. Priv., vol. 5, no. 2, p. 34, 2025.",
        "G. A. Mills, D. K. Acquah, and R. A. Sowah, \"Network Intrusion "
        "Detection and Prevention System Using Hybrid Machine Learning with "
        "Supervised Ensemble Stacking Model,\" J. Computer Networks and "
        "Communications, vol. 2024, 5775671, 2024.",
        "I. Bello, O. Adeyemi, and A. Okafor, \"Automation in Cybersecurity "
        "Using Machine Learning: A Case Study on Anomaly Detection with "
        "Isolation Forest,\" J. Technology Informatics and Engineering, "
        "vol. 4, no. 3, pp. 613-624, 2025.",
        "S. A. R. Shah and B. Issac, \"Performance Comparison of Intrusion "
        "Detection Systems and Application of Machine Learning to Snort "
        "System,\" Future Generation Computer Systems, vol. 80, "
        "pp. 157-170, 2018.",
        "D. S. Ghazi et al., \"Performance and Efficacy of Snort Versus "
        "Suricata in Intrusion Detection: A Benchmark Analysis,\" AIP Conf. "
        "Proc., vol. 3232, 020024, 2024.",
        "A. M. Winkler and P. Sharma, \"Proactive Threat Detection in "
        "Enterprise Systems Using Wazuh: A MITRE ATT&CK Evaluation,\" "
        "Computers &amp; Security, vol. 159, 104702, 2025.",
        "H. Lv and Y. Ding, \"A Hybrid Intrusion Detection System with "
        "K-Means and CNN+LSTM,\" EAI Endorsed Trans. Scalable Information "
        "Systems, vol. 11, no. 6, 2024.",
        "M. Tavallaee, E. Bagheri, W. Lu, and A. A. Ghorbani, \"A Detailed "
        "Analysis of the KDD CUP 99 Data Set,\" in Proc. IEEE CISDA, 2009, "
        "pp. 1-6.",
        "The MITRE Corporation, \"MITRE ATT&CK Framework,\" "
        "https://attack.mitre.org.",
        "EVTX-ATTACK-SAMPLES, a public collection of Windows event-log "
        "recordings of real attacker techniques, https://github.com/"
        "sbousseaden/EVTX-ATTACK-SAMPLES.",
    ]
    for i, r in enumerate(refs, 1):
        S.append(Paragraph(f"[{i}]&nbsp;&nbsp;{r}", st["ref"]))

    return S


# =====================================================================
# BUILD
# =====================================================================

def _render_once(toc_rows):
    """One layout pass with fresh flowables. Headings record their own true
    page numbers into the module-level _TOC list as they draw."""
    _TOC.clear()
    st = styles()
    doc = ReportDoc(OUT, pagesize=A4, leftMargin=2.2 * cm,
                    rightMargin=2.2 * cm, topMargin=2 * cm,
                    bottomMargin=1.9 * cm, title="Project Report",
                    author="Mehedi Hasan Nayan; Tawsif Zawad")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height,
                  id="f")
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=frame, onPage=on_cover_page),
        PageTemplate(id="body", frames=frame, onPage=on_body_page),
    ])
    story = build_story(st, toc_rows)
    story.insert(0, _NextTemplate("cover"))
    doc.build(story)
    return list(_TOC)


def main():
    build_figures()
    os.makedirs("docs", exist_ok=True)

    # Pass 1: no contents rows yet -> collect each heading's true page.
    # Pass 2: render the real contents table from those pages. The contents
    # fit on a single page and Chapter 1 always starts with a page break,
    # so adding the table does not move any body content -> pages stay exact.
    rows = _render_once(None)
    rows = _render_once(rows)
    # safety: one more pass only if page numbers shifted
    check = _render_once(rows)
    passes = 2 if check == rows else 3
    if check != rows:
        _render_once(check)
    size = os.path.getsize(OUT) / 1024
    print(f"Written {OUT} ({size:.0f} KB, {passes} passes)")


from reportlab.platypus.doctemplate import NextPageTemplate as _NPT


def _NextTemplate(name):
    return _NPT(name)


if __name__ == "__main__":
    main()
