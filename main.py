"""
==========================================
 MAIN.PY — CTI Multi-Agent System
==========================================
Complete pipeline orchestrated by LangGraph:
  Message(s) → CTI Agent → MITRE Agent → Aggregation → Dashboard → PDF

Usage:
    python main.py                       # Test messages
    python main.py -f msg1.txt msg2.txt  # From files
    python main.py -i                    # Interactive mode
"""

import json
import argparse
from graph import run_pipeline


SAMPLE_MESSAGES = [
    """LockBit 3.0 ransomware targeting European banks.
    C2: 185.220.101.45 | Payload: https://dl.malware-depot.xyz/lockbit3_loader.exe
    Uses process injection into svchost.exe, registry persistence via
    HKLM\\CurrentVersion\\Run, encrypts files (.lockbit), deletes shadow copies.
    Credentials harvested with mimikatz. Anti-VM checks enabled.
    BTC wallet: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh""",

    """APT29 phishing campaign detected against government agencies.
    Spear-phishing emails with malicious .docx attachments exploiting CVE-2023-36884.
    Payload communicates via DNS tunneling to c2.cozy-update[.]xyz.
    Uses scheduled tasks for persistence and Cobalt Strike for lateral movement.
    Data exfiltrated over encrypted HTTPS channel.""",
]


def print_final_report(state: dict):
    """Displays the final consolidated report."""

    print("\n" + "═" * 70)
    print("  CONSOLIDATED THREAT INTELLIGENCE REPORT")
    print("═" * 70)

    # Executive Summary
    summary = state.get("executive_summary", {})
    print(f"\n📋 Executive Summary:")
    print(f"   {summary.get('executive_summary', 'N/A')}")
    print(f"   Risk Trend: {summary.get('risk_trend', 'unknown')}")

    # Global Stats
    report = state.get("aggregated_report", {})
    print(f"\n📊 Global Severity : {report.get('global_severity', '?')} "
          f"({report.get('global_severity_score', 0)}/5.0)")
    print(f"   Threats  : {report.get('threats_identified', [])}")
    print(f"   Actors   : {report.get('threat_actors', [])}")

    stats = report.get("statistics", {})
    print(f"   Techniques: {stats.get('unique_techniques', 0)} unique")
    print(f"   IOCs      : {stats.get('total_iocs', 0)} total")

    # Priority Actions
    actions = state.get("prioritized_actions", [])
    if actions:
        print(f"\n🚨 Priority Actions ({len(actions)} total):")
        for a in actions[:5]:
            print(f"   [{a['urgency']}] {a['technique_id']} {a['technique_name']} "
                  f"(score: {a['priority_score']})")
            for rec in a.get("recommended_actions", [])[:2]:
                print(f"       → {rec}")

    # Top 3 Immediate Actions
    top3 = summary.get("top_3_actions", [])
    if top3:
        print(f"\n⚡ Top 3 Immediate Actions:")
        for i, action in enumerate(top3, 1):
            print(f"   {i}. {action}")

    # Dashboard
    dash = state.get("dashboard_path", "")
    if dash:
        print(f"\n📈 Dashboard: {dash}")

    # PDF
    pdf_path = state.get("pdf_path", "")
    if pdf_path:
        print(f"📄 PDF Report: {pdf_path}")

    # Save full JSON
    output_file = "final_report.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump({
            "executive_summary": summary,
            "aggregated_report": report,
            "prioritized_actions": actions,
        }, f, indent=2, ensure_ascii=False)
    print(f"\n💾 Full report saved → {output_file}")
    print("\n" + "═" * 70)


if __name__ == "__main__":
    print("""
    ╔════════════════════════════════════════════════════╗
    ║  CTI Multi-Agent System v2.0                       ║
    ║  LangGraph Orchestrated Pipeline                   ║
    ║                                                    ║
    ║  CTI Analysis → MITRE Mapping → Master Manager     ║
    ╚════════════════════════════════════════════════════╝
    """)

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--files", nargs="+", help="CTI message file(s)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    args = parser.parse_args()

    if args.interactive:
        print("Enter your messages (blank line between each, 'done' to start, 'quit' to exit)\n")
        messages = []
        current = []
        while True:
            line = input()
            if line.strip().lower() == "quit":
                exit()
            if line.strip().lower() == "done":
                if current:
                    messages.append("\n".join(current))
                break
            if line == "" and current:
                messages.append("\n".join(current))
                current = []
                print(f"  Message {len(messages)} saved. Continue or type 'done'.")
            else:
                current.append(line)

        if messages:
            state = run_pipeline(messages)
            print_final_report(state)

    elif args.files:
        messages = []
        for fp in args.files:
            with open(fp, "r", encoding="utf-8") as f:
                messages.append(f.read())
        state = run_pipeline(messages)
        print_final_report(state)

    else:
        state = run_pipeline(SAMPLE_MESSAGES)
        print_final_report(state)

        try:
            from IPython.display import Image, display, FileLink
            if state.get("dashboard_path"):
                print("\n📈 Dashboard Preview:")
                display(Image(filename=state["dashboard_path"]))
            if state.get("pdf_path"):
                print("\n📄 Download PDF Report:")
                display(FileLink(state["pdf_path"]))
        except ImportError:
            print(f"\n📈 Dashboard saved at : {state.get('dashboard_path', 'N/A')}")
            print(f"📄 PDF saved at       : {state.get('pdf_path', 'N/A')}")
            print(f"💾 JSON saved at      : final_report.json")