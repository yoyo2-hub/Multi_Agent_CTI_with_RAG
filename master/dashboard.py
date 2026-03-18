"""
==========================================
 DASHBOARD — Threat Visualization
==========================================
Generates matplotlib charts from the consolidated report.
Produces 4 charts in a single PNG file.
"""

import matplotlib
matplotlib.use("Agg")  # Non-interactive mode (no GUI needed)
import matplotlib.pyplot as plt
from collections import Counter


def generate_dashboard(aggregated_report: dict, output_path: str = "dashboard.png"):
    """
    Generates a 4-panel dashboard as PNG.

    Panels:
      1. ATT&CK tactics distribution (horizontal bars)
      2. Severity distribution (pie chart)
      3. Kill Chain coverage (ordered bars)
      4. Top priority actions (table)

    Args:
        aggregated_report: Result from aggregate_reports()
        output_path: Output PNG file path
    """
    stats = aggregated_report.get("statistics", {})

    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle(
        f"CTI Threat Dashboard — Severity: {aggregated_report.get('global_severity', '?')}",
        fontsize=16, fontweight="bold", y=0.98,
    )

    # Panel 1: ATT&CK Tactics
    ax1 = axes[0, 0]
    tactics = stats.get("tactics_distribution", {})
    if tactics:
        sorted_tactics = sorted(tactics.items(), key=lambda x: x[1], reverse=True)
        names, counts = zip(*sorted_tactics)
        colors = plt.cm.Reds([c / max(counts) for c in counts])
        ax1.barh(names, counts, color=colors)
        ax1.set_xlabel("Count")
        ax1.set_title("ATT&CK Tactics Distribution")
        ax1.invert_yaxis()
    else:
        ax1.text(0.5, 0.5, "No data", ha="center", va="center")
        ax1.set_title("ATT&CK Tactics Distribution")

    # Panel 2: Severity pie chart
    ax2 = axes[0, 1]
    severity = stats.get("severity_distribution", {})
    if severity:
        sev_colors = {
            "Critical": "#d32f2f", "High": "#f57c00",
            "Medium": "#fbc02d", "Low": "#388e3c",
        }
        labels = list(severity.keys())
        sizes = list(severity.values())
        colors = [sev_colors.get(l, "#999") for l in labels]
        ax2.pie(sizes, labels=labels, colors=colors, autopct="%1.0f%%", startangle=90)
        ax2.set_title("Severity Distribution")
    else:
        ax2.text(0.5, 0.5, "No data", ha="center", va="center")
        ax2.set_title("Severity Distribution")

    # Panel 3: Kill Chain Coverage
    ax3 = axes[1, 0]
    kill_chain_order = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command And Control",
        "Exfiltration", "Impact",
    ]
    if tactics:
        kc_counts = [tactics.get(t, 0) for t in kill_chain_order]
        # Keep only tactics with at least 1 hit
        filtered = [(t, c) for t, c in zip(kill_chain_order, kc_counts) if c > 0]
        if filtered:
            names, counts = zip(*filtered)
            bar_colors = ["#d32f2f" if c > 0 else "#e0e0e0" for c in counts]
            ax3.bar(range(len(names)), counts, color=bar_colors)
            ax3.set_xticks(range(len(names)))
            ax3.set_xticklabels(names, rotation=45, ha="right", fontsize=8)
            ax3.set_ylabel("Count")
    ax3.set_title("Kill Chain Coverage")

    # Panel 4: Top Actions table
    ax4 = axes[1, 1]
    ax4.axis("off")
    actions = aggregated_report.get("priority_actions", [])[:8]
    if actions:
        table_data = [[f"{i+1}", action[:70]] for i, action in enumerate(actions)]
        table = ax4.table(
            cellText=table_data,
            colLabels=["#", "Priority Action"],
            cellLoc="left",
            loc="center",
            colWidths=[0.08, 0.92],
        )
        table.auto_set_font_size(False)
        table.set_fontsize(8)
        table.scale(1, 1.5)
        # Color the header
        for j in range(2):
            table[0, j].set_facecolor("#1a237e")
            table[0, j].set_text_props(color="white", fontweight="bold")
    ax4.set_title("Priority Actions", fontweight="bold")

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()

    print(f"[DASHBOARD] Saved → {output_path}")
    return output_path