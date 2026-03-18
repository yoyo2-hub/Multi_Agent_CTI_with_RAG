from mitre_tools.mitre_mapper import map_to_mitre
from mitre_tools.severity_engine import calculate_severity
from mitre_tools.mitigation_engine import recommend_mitigations
from mitre_tools.report_generator import generate_report


def run_mitre_analysis(cti_output: dict) -> dict:
    """
    Entry point: receives the result from the CTI Analysis Agent.
    Calls all 4 tools directly instead of relying on the LLM to chain them.

    Args:
        cti_output: Complete result from analyze_message()

    Returns:
        Final JSON report for the Master Manager.
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
    if not final_report.get("global_recommendations"):
      final_report["global_recommendations"] = [
        "Implement network segmentation to limit lateral movement.",
        "Deploy EDR solution across all endpoints.",
        "Enforce MFA for all privileged accounts.",
    ]
    
    # ✅ Add this to see what generate_report actually returned
    print(f"[DEBUG] Report type: {type(report)}")
    print(f"[DEBUG] Report value: {report}")

    return report