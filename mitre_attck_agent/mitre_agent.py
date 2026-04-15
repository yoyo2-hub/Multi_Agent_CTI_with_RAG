from Tools import map_to_mitre
from Tools import calculate_severity
from Tools import recommend_mitigations
from Tools import generate_report

def run_mitre_analysis(cti_output: dict) -> dict:
    """
    Orchestrates the MITRE analysis pipeline.
    """
    entities  = cti_output.get("entities", {})
    behaviors = cti_output.get("behaviors", [])
    rag_context = cti_output.get("rag_context", None)
    patterns    = cti_output.get("patterns", None)

    # Step 1: MITRE Mapping
    print("[Step 1] Mapping behaviors to MITRE ATT&CK...")
    mitre_result = map_to_mitre.invoke({"behaviors": behaviors})

    # Step 2: Severity Calculation
    print("[Step 2] Calculating severity...")
    severity_result = calculate_severity.invoke({
        "techniques": mitre_result.get("techniques", [])
    })

    # Step 3: Mitigation Recommendations
    print("[Step 3] Recommending mitigations...")
    mitigations_result = recommend_mitigations.invoke({
        "scored_techniques": severity_result.get("scored_techniques", [])
    })

    # Step 4: Report Generation
    print("[Step 4] Generating final report...")
    report = generate_report.invoke({
        "entities":         entities,
        "behaviors":        behaviors,
        "mitre_techniques": mitre_result.get("techniques", []),
        "severity_data":    severity_result,
        "mitigations_data": mitigations_result,
        "rag_context":      rag_context or {},
        "patterns":         patterns or {},
    })

    # Logic Check: If the report is missing recommendations, provide baseline security posture
    if not report.get("global_recommendations"):
        report["global_recommendations"] = [
            "Implement network segmentation to limit lateral movement.",
            "Deploy EDR solution across all endpoints.",
            "Enforce MFA for all privileged accounts.",
        ]
    
    print(f"[Step 5] MITRE analysis complete. Global Severity: {report.get('global_severity')}")

    return report