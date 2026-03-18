"""
==========================================
 PDF REPORT — PDF Report Generation
==========================================
Transforms the consolidated report into a professional PDF
using FPDF2. Includes: header, summary, tables, actions.
"""

from fpdf import FPDF
from datetime import datetime, timezone
import os

# ✅ Fonts already copied from system — no download needed
FONT_PATH   = "/kaggle/working/DejaVuSans.ttf"
FONT_PATH_B = "/kaggle/working/DejaVuSans-Bold.ttf"


class CTIReport(FPDF):
    """Custom PDF with CTI header and footer."""

    def __init__(self):
        super().__init__()
        self.add_font("DejaVu", "",  FONT_PATH)
        self.add_font("DejaVu", "B", FONT_PATH_B)

    def header(self):
        self.set_font("DejaVu", "B", 12)
        self.set_fill_color(26, 35, 126)
        self.set_text_color(255, 255, 255)
        self.cell(0, 12, "  CTI Threat Intelligence Report", fill=True, align="L", new_x="LMARGIN", new_y="NEXT")
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("DejaVu", "", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", align="C")

    def section_title(self, title: str):
        """Adds a colored section title."""
        self.set_font("DejaVu", "B", 13)
        self.set_text_color(26, 35, 126)
        self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(26, 35, 126)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def key_value(self, key: str, value: str):
        """Displays a key: value pair."""
        self.set_font("DejaVu", "B", 10)
        self.set_text_color(0, 0, 0)
        self.cell(55, 7, f"{key}:", new_x="END")
        self.set_font("DejaVu", "", 10)
        self.multi_cell(0, 7, str(value), new_x="LMARGIN", new_y="NEXT")

    def severity_badge(self, level: str, score: float):
        """Displays a colored severity badge."""
        colors = {
            "Critical": (211, 47, 47),
            "High": (245, 124, 0),
            "Medium": (251, 192, 45),
            "Low": (56, 142, 60),
        }
        r, g, b = colors.get(level, (128, 128, 128))
        self.set_font("DejaVu", "B", 11)
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.cell(45, 8, f" {level} ({score}/5.0)", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(3)


def generate_pdf_report(
    aggregated_report: dict,
    prioritized_actions: list[dict],
    executive_summary: dict,
    dashboard_path: str = None,
    output_path: str = "cti_report.pdf",
) -> str:
    """
    Generates the complete PDF report.

    Args:
        aggregated_report:   Result from aggregate_reports()
        prioritized_actions: Result from prioritize_actions()
        executive_summary:   Result from generate_executive_summary()
        dashboard_path:      Path to dashboard PNG (optional)
        output_path:         Output PDF file path

    Returns:
        Path to the generated PDF file.
    """
    pdf = CTIReport()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    stats = aggregated_report.get("statistics", {})

    # 1. EXECUTIVE SUMMARY
    pdf.section_title("1. Executive Summary")
    pdf.key_value("Global Severity", aggregated_report.get("global_severity", "N/A"))
    pdf.severity_badge(
        aggregated_report.get("global_severity", "Low"),
        aggregated_report.get("global_severity_score", 0),
    )
    pdf.key_value("Risk Trend", executive_summary.get("risk_trend", "unknown"))
    pdf.key_value("Reports Analyzed", str(aggregated_report.get("report_metadata", {}).get("reports_aggregated", 0)))
    pdf.ln(3)
    pdf.set_font("DejaVu", "", 10)
    pdf.multi_cell(0, 6, executive_summary.get("executive_summary", "No summary available."))
    pdf.ln(5)

    # 2. THREATS OVERVIEW
    pdf.section_title("2. Threats Overview")
    pdf.key_value("Threats Identified", ", ".join(aggregated_report.get("threats_identified", [])) or "None")
    pdf.key_value("Threat Actors", ", ".join(aggregated_report.get("threat_actors", [])) or "None")
    pdf.key_value("Total IOCs", str(stats.get("total_iocs", 0)))
    pdf.key_value("Unique Techniques", str(stats.get("unique_techniques", 0)))

    # IOC breakdown
    iocs = aggregated_report.get("all_iocs", {})
    for ioc_type, values in iocs.items():
        if values:
            pdf.key_value(f"  {ioc_type.upper()}", ", ".join(values[:10]))
            if len(values) > 10:
                pdf.set_font("DejaVu", "", 9)
                pdf.cell(0, 5, f"    ... and {len(values) - 10} more", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # 3. MITRE ATT&CK TECHNIQUES
    pdf.section_title("3. MITRE ATT&CK Techniques")
    techniques = aggregated_report.get("techniques", [])
    if techniques:
        # Table header
        pdf.set_font("DejaVu", "B", 9)
        pdf.set_fill_color(44, 62, 80)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(25, 8, "ID", border=1, fill=True, align="C")
        pdf.cell(55, 8, "Name", border=1, fill=True)
        pdf.cell(45, 8, "Tactic", border=1, fill=True)
        pdf.cell(20, 8, "Score", border=1, fill=True, align="C")
        pdf.cell(25, 8, "Level", border=1, fill=True, align="C")
        pdf.ln()

        # Rows
        pdf.set_text_color(0, 0, 0)
        sev_colors = {
            "Critical": (255, 220, 220), "High": (255, 240, 220),
            "Medium": (255, 255, 220), "Low": (220, 255, 220),
        }
        for tech in techniques[:20]:
            level = tech.get("severity_level", "Low")
            r, g, b = sev_colors.get(level, (255, 255, 255))
            pdf.set_fill_color(r, g, b)
            pdf.set_font("DejaVu", "B", 8)
            pdf.cell(25, 7, tech.get("id", ""), border=1, fill=True, align="C")
            pdf.set_font("DejaVu", "", 8)
            pdf.cell(55, 7, tech.get("name", "")[:30], border=1, fill=True)
            pdf.cell(45, 7, tech.get("tactic", "")[:25], border=1, fill=True)
            pdf.cell(20, 7, str(tech.get("severity", 0)), border=1, fill=True, align="C")
            pdf.cell(25, 7, level, border=1, fill=True, align="C")
            pdf.ln()
    pdf.ln(5)

    # 4. PRIORITY ACTIONS
    pdf.add_page()
    pdf.section_title("4. Priority Actions")
    urgency_colors = {
        "IMMEDIATE": (211, 47, 47),
        "SHORT_TERM": (245, 124, 0),
        "LONG_TERM": (56, 142, 60),
    }
    for action in prioritized_actions[:10]:
        urgency = action.get("urgency", "LONG_TERM")
        r, g, b = urgency_colors.get(urgency, (128, 128, 128))
        # Urgency badge
        pdf.set_font("DejaVu", "B", 9)
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(25, 6, f" {urgency}", fill=True, new_x="END")
        # Technique
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("DejaVu", "B", 9)
        pdf.cell(0, 6, f"  {action['technique_id']} — {action['technique_name']} "
               f"(Score: {action['priority_score']})", new_x="LMARGIN", new_y="NEXT")
        # Recommendations
        pdf.set_font("DejaVu", "", 8)
        for rec in action.get("recommended_actions", [])[:3]:
            pdf.cell(10, 5, "", new_x="END")
            pdf.multi_cell(0, 5, f"→ {rec}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # 5. TOP 3 IMMEDIATE ACTIONS
    top3 = executive_summary.get("top_3_actions", [])
    if top3:
        pdf.section_title("5. Top 3 Immediate Actions")
        for i, action in enumerate(top3, 1):
            pdf.set_font("DejaVu", "B", 10)
            pdf.cell(8, 7, f"{i}.", new_x="END")
            pdf.set_font("DejaVu", "", 10)
            pdf.multi_cell(0, 7, action, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

    # 6. DASHBOARD (embedded PNG)
    if dashboard_path:
        try:
            pdf.add_page("L")
            pdf.section_title("6. Visual Dashboard")
            pdf.image(dashboard_path, x=10, y=30, w=270)
        except Exception as e:
            pdf.set_font("DejaVu", "", 10)
            pdf.cell(0, 10, f"Dashboard unavailable: {e}", new_x="LMARGIN", new_y="NEXT")

    # Save
    pdf.output(output_path)
    print(f"[PDF] Report saved → {output_path}")
    return output_path