"""
==========================================
 PRIORITIZER — Action Ranking
==========================================
Ranks mitigations by urgency by combining:
  - Technique severity
  - Number of reports affected
  - Ease of implementation
"""

from llm_helper import llm_analyze


# STATIC SCORING

SEVERITY_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def prioritize_actions(aggregated_report: dict) -> list[dict]:
    """
    Ranks actions by priority.

    Scoring: severity_weight × frequency
    The higher the score, the more urgent the action.

    Args:
        aggregated_report: Result from aggregate_reports()

    Returns:
        List of actions sorted by descending priority.
    """
    techniques = aggregated_report.get("techniques", [])

    # Count the frequency of each technique
    tech_freq = {}
    for t in techniques:
        tid = t.get("id", "")
        if tid not in tech_freq:
            tech_freq[tid] = {
                "id": tid,
                "name": t.get("name", ""),
                "tactic": t.get("tactic", ""),
                "severity_level": t.get("severity_level", "Low"),
                "severity_score": t.get("severity", 0),
                "mitigations": t.get("mitigation", []),
                "count": 0,
            }
        tech_freq[tid]["count"] += 1

    # Score and sort
    prioritized = []
    for tid, data in tech_freq.items():
        weight = SEVERITY_WEIGHT.get(data["severity_level"], 1)
        priority_score = round(weight * data["count"] * (data["severity_score"] / 5), 2)

        urgency = (
            "IMMEDIATE" if priority_score >= 8 else
            "SHORT_TERM" if priority_score >= 4 else
            "LONG_TERM"
        )

        prioritized.append({
            "technique_id": tid,
            "technique_name": data["name"],
            "tactic": data["tactic"],
            "severity": data["severity_level"],
            "occurrence_count": data["count"],
            "priority_score": priority_score,
            "urgency": urgency,
            "recommended_actions": data["mitigations"][:5],
        })

    prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
    return prioritized


# LLM ENRICHMENT — Executive Summary

LLM_SUMMARY_PROMPT = """You are a CISO advisor. Given this consolidated threat data,
write a brief executive summary (3-5 sentences) for non-technical stakeholders.

Focus on:
1. What are the main threats?
2. How severe is the situation?
3. What are the top 3 actions to take immediately?

Return ONLY valid JSON:
{
    "executive_summary": "...",
    "top_3_actions": ["action1", "action2", "action3"],
    "risk_trend": "increasing|stable|decreasing"
}"""


def generate_executive_summary(aggregated_report: dict) -> dict:
    """Generates an executive summary via LLM."""
    content = (
        f"Threats: {aggregated_report.get('threats_identified', [])}\n"
        f"Severity: {aggregated_report.get('global_severity', 'Unknown')}\n"
        f"Techniques: {aggregated_report['statistics'].get('unique_techniques', 0)}\n"
        f"IOCs: {aggregated_report['statistics'].get('total_iocs', 0)}\n"
        f"Tactics: {aggregated_report['statistics'].get('tactics_distribution', {})}"
    )

    result = llm_analyze(LLM_SUMMARY_PROMPT, content)

    if result.get("llm_failed") or result.get("parse_error"):
        return {
            "executive_summary": "Automated summary unavailable.",
            "top_3_actions": aggregated_report.get("priority_actions", [])[:3],
            "risk_trend": "unknown",
        }
    return result