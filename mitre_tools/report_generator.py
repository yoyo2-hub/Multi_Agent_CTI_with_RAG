"""
==========================================
 TOOL 4 — JSON Report Generator
==========================================
Compiles all results into a final structured report.
This report will be passed to the Master Manager.
"""

from datetime import datetime, timezone
from langchain_core.tools import tool

@tool
def generate_report(
    entities: dict,
    behaviors: list[dict],
    mitre_techniques: list[dict],
    severity_data: dict,
    mitigations_data: dict,
    rag_context: dict = {},   
    patterns: dict = {},      
) -> dict:
    """
    Generates the final CTI report in structured JSON.

    Args:
        entities:         Result from extract_entities
        behaviors:        Result from detect_behaviors
        mitre_techniques: Result from map_to_mitre
        severity_data:    Result from calculate_severity
        mitigations_data: Result from recommend_mitigations
        rag_context:      Result from rag_search (optional)
        patterns:         Result from detect_patterns (optional)

    Returns:
        Complete JSON report ready for the Master Manager.
    """
    # Determine the threat name
    malware_names = entities.get("malware_names", [])
    campaign_names = entities.get("campaign_names", [])
    threat_name = (
        campaign_names[0] if campaign_names
        else malware_names[0] if malware_names
        else "Unknown Threat"
    )

    # Build the technique list for the report
    technique_mitigations = mitigations_data.get("technique_mitigations", [])
    report_techniques = []
    for tm in technique_mitigations:
        report_techniques.append({
            "id": tm["id"],
            "name": tm["name"],
            "tactic": tm["tactic"],
            "severity": tm["severity_score"],
            "severity_level": tm["severity_level"],
            "mitigation": tm["mitigations"],
            "priority": tm.get("priority", ""),
        })
    # Fallback: use raw mitre_techniques if mitigations_data is empty
    if not report_techniques:
        report_techniques = mitre_techniques

    # Final report
    report = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "agent_version": "2.0-hybrid",
            "analysis_type": "CTI Threat Analysis",
        },
        "malware": threat_name,
        "global_severity": severity_data.get("global_severity_level", "Unknown"),
        "global_severity_score": severity_data.get("global_severity_score", 0),

        "entities": {
            "ips": entities.get("ips", []),
            "urls": entities.get("urls", []),
            "domains": entities.get("domains", []),
            "hashes": entities.get("hashes", {}),
            "crypto_wallets": entities.get("crypto_wallets", {}),
            "emails": entities.get("emails", []),
            "cves": entities.get("cves", []),
            "threat_actors": entities.get("threat_actors", []),
            "ioc_count": entities.get("ioc_count", 0),
        },

        "techniques": report_techniques,

        "behaviors_summary": {
            "total_detected": len(behaviors),
            "max_severity": max(
                (b.get("severity", "low") for b in behaviors),
                key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0),
                default="none",
            ),
            "categories": list(set(b.get("category", "") for b in behaviors)),
        },

        "intelligence_context": {
            "similar_campaigns": rag_context.get("num_results", 0) if rag_context else 0,
            "threat_classification": patterns.get("threat_classification", "") if patterns else "",
            "emerging_terms": patterns.get("emerging_terms", []) if patterns else [],
        },

        "priority_actions": mitigations_data.get("priority_actions", []),
        "global_recommendations": mitigations_data.get("global_recommendations", []),
    }

    return report