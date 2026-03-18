"""
==========================================
 AGGREGATOR — Multi-Report Consolidation
==========================================
Aggregates N JSON reports from the MITRE Mapping Agent
into a single consolidated report for stakeholders.
"""

from datetime import datetime, timezone
from collections import Counter


def aggregate_reports(reports: list[dict]) -> dict:
    """
    Merges multiple CTI reports into a single global report.

    Args:
        reports: List of JSON reports (output of generate_report)

    Returns:
        Consolidated report with global statistics.
    """
    if not reports:
        return {"error": "No reports to aggregate"}

    # Collect all data
    all_techniques = []
    all_iocs = {"ips": [], "urls": [], "domains": [], "emails": [], "cves": []}
    all_malware = []
    all_actors = []
    all_actions = []
    severity_scores = []

    for report in reports:
        # Techniques
        for tech in report.get("techniques", []):
            all_techniques.append(tech)

        # IOCs
        entities = report.get("entities", {})
        for key in all_iocs:
            all_iocs[key].extend(entities.get(key, []))

        # Malware & actors
        all_malware.append(report.get("malware", "Unknown"))
        all_actors.extend(entities.get("threat_actors", []))

        # Priority actions
        all_actions.extend(report.get("priority_actions", []))

        # Severity
        score = report.get("global_severity_score", 0)
        if score:
            severity_scores.append(score)

    # Global statistics
    tactic_counts = Counter(t.get("tactic", "") for t in all_techniques)
    severity_dist = Counter(t.get("severity_level", "") for t in all_techniques)

    # Global score = max across all reports
    global_score = max(severity_scores) if severity_scores else 0
    global_level = (
        "Critical" if global_score >= 4 else
        "High" if global_score >= 3 else
        "Medium" if global_score >= 2 else "Low"
    )

    # Deduplicate IOCs
    for key in all_iocs:
        all_iocs[key] = list(set(all_iocs[key]))

    return {
        "report_metadata": {
            "type": "consolidated_threat_report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "reports_aggregated": len(reports),
        },
        "global_severity": global_level,
        "global_severity_score": global_score,
        "threats_identified": list(set(all_malware)),
        "threat_actors": list(set(all_actors)),

        "statistics": {
            "total_techniques": len(all_techniques),
            "unique_techniques": len(set(t.get("id", "") for t in all_techniques)),
            "tactics_distribution": dict(tactic_counts),
            "severity_distribution": dict(severity_dist),
            "total_iocs": sum(len(v) for v in all_iocs.values()),
        },

        "all_iocs": all_iocs,
        "techniques": all_techniques,
        "priority_actions": list(dict.fromkeys(all_actions))[:15],  # Deduplicated, top 15
    }