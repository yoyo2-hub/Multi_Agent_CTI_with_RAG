"""
==========================================
 TOOL 3 — Mitigation Engine
==========================================
Associates each ATT&CK technique with recommendations:
  - Official MITRE ATT&CK Mitigations (via STIX)
  - CIS Controls
  - NIST recommendations

Hybrid: STIX mitigations + LLM enrichment.
"""
from langchain_core.tools import tool
from llm_helper import llm_analyze
from mitre_mapper import _get_mitre_data


# LAYER 1: OFFICIAL STIX MITIGATIONS

def _get_stix_mitigations(technique_id: str) -> list[str]:
    """
    Retrieves official MITRE mitigations for a technique.
    Each result is a dict with 'object' (CourseOfAction) and 'relationships' keys.
    """
    mitre = _get_mitre_data()
    mitigations = []

    try:
        # Find the technique STIX ID by external ID
        techniques = mitre.get_techniques()
        tech_stix_id = None
        for t in techniques:
            for ref in t.get("external_references", []):
                if ref.get("external_id") == technique_id:
                    tech_stix_id = t.get("id")
                    break
            if tech_stix_id:
                break

        if not tech_stix_id:
            print(f"[STIX] No STIX ID found for {technique_id}")
            return []

        # ✅ Each item is {'object': CourseOfAction, 'relationships': [...]}
        mit_objects = mitre.get_mitigations_mitigating_technique(tech_stix_id)
        for item in mit_objects:
            coa = item.get("object")          # CourseOfAction STIX object
            name = coa.get("name", "")        # .get() works on STIX dicts
            ext_id = ""
            for ref in coa.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id", "")
                    break
            if name:
                # Include the M-code for clarity e.g. "M1042: Disable or Remove Feature"
                label = f"{ext_id}: {name}" if ext_id else name
                mitigations.append(label)

        print(f"[STIX] {technique_id} → {len(mitigations)} mitigation(s): {mitigations}")

    except Exception as e:
        print(f"[STIX ERROR] {technique_id} → {e}")

    return mitigations
# CIS / NIST TABLE BY TACTIC (baseline)

FRAMEWORK_MITIGATIONS = {
    "Execution": [
        "CIS 2.7: Allowlist authorized scripts (Preventative)",
        "NIST SI-7: Software Integrity (Preventative)",
        "Enable PowerShell Script Block Logging (Detective)",
    ],
    "Lateral_Movement": [
        "CIS 6.3: Network Segmentation (Preventative)",
        "NIST AC-4: Information Flow Enforcement (Preventative)",
        "Disable SMBv1 and unnecessary admin shares (Hardening)",
    ],
    "Defense_Evasion": [
        "CIS 8.2: Deploy EDR (Detective/Responsive)",
        "NIST SI-4: Continuous Monitoring (Detective)",
        "Enforce Signed Binary Execution (Preventative)",
    ],
    "Credential_Access": [
        "CIS 6.5: MFA for Administrative Access (Preventative)",
        "NIST IA-5: Strong Authenticator Management (Policy)",
        "Windows Credential Guard & LSA Protection (Hardening)",
    ],
    "Initial_Access": [
        "CIS 14.6: Deliver Training to Fill Skills Gaps (Anti-Phishing)",
        "NIST AC-17: Remote Access - Enforce MFA and Managed VPN",
        "Block malicious attachments and URL rewriting (Email Security)",
    ],
    "Discovery": [
        "CIS 5.1: Maintain Secure Configurations (Hardening)",
        "NIST AC-6: Least Privilege - Restrict AD/LDAP querying",
        "Monitor for rapid/abnormal API or CMD enumeration (Detective)",
    ],
    "Collection": [
        "CIS 13.1: Inventory Sensitive Data",
        "NIST AC-3: Access Enforcement (RBAC/ABAC)",
        "Implement Clipboard and Removable Media restrictions",
    ],
    "Resource_Development": [
        "CIS 1.1: Inventory of Enterprise Assets (Prevent Shadow IT)",
        "NIST IA-3: Device Identification and Authentication",
        "Block known-bad hosting infrastructure and proxy IPs",
    ]
}


# LAYER 2: LLM ENRICHMENT

LLM_MITIGATION_PROMPT = """Act as a Defense Expert. 
Provide 2-3 actionable steps per technique. 
Include MITRE M-codes, CIS, or NIST refs.

JSON ONLY:
{
  "mits": [
    {"id": "TXXXX", "recs": ["step 1", "step 2"], "pri": "immediate"}
  ],
    "global_recommendations": ["org-wide recommendation 1"]
}"""


def _llm_mitigations(techniques: list[dict]) -> dict:
    """LLM enrichment of recommendations."""
    content = "\n".join(
        f"- {t['id']} {t['name']} ({t.get('tactic','')}) — Severity: {t.get('severity_score', '?')}"
        for t in techniques
    )
    result = llm_analyze(LLM_MITIGATION_PROMPT, content)

    if result.get("llm_failed") or result.get("parse_error"):
        return {"mitigations": [], "global_recommendations": []}
    return result


# LANGCHAIN TOOL

@tool
def recommend_mitigations(scored_techniques: list[dict]) -> dict:
    """
    Recommends mitigations for each scored ATT&CK technique.

    Combines:
    - Official MITRE STIX mitigations
    - CIS Controls / NIST references
    - Contextual LLM recommendations

    Args:
        scored_techniques: List from calculate_severity
            Each item: {"id", "name", "tactic", "severity_score", ...}

    Returns:
        {
            "technique_mitigations": [{id, name, severity, mitigations: [...]}],
            "global_recommendations": [str],
            "priority_actions": [str]
        }
    """
    if not scored_techniques:
        return {"error": "No techniques provided"}

    # Collect from all 3 sources
    llm_result = _llm_mitigations(scored_techniques)
    llm_map = {
        m["technique_id"]: m
        for m in llm_result.get("mitigations", [])
    }

    technique_mitigations = []
    for tech in scored_techniques:
        tech_id = tech.get("id", "")
        tactic = tech.get("tactic", "")

        # Source 1: MITRE STIX
        stix_mits = _get_stix_mitigations(tech_id)

        # Source 2: CIS / NIST by tactic
        framework_mits = FRAMEWORK_MITIGATIONS.get(tactic, [])

        # Source 3: LLM
        llm_mits = llm_map.get(tech_id, {}).get("recommendations", [])
        priority = llm_map.get(tech_id, {}).get("priority", "short_term")

        # Merge and deduplicate
        all_mits = []
        seen = set()
        for mit in stix_mits + framework_mits + llm_mits:
            if mit.lower() not in seen:
                seen.add(mit.lower())
                all_mits.append(mit)

        technique_mitigations.append({
            "id": tech_id,
            "name": tech.get("name", ""),
            "tactic": tactic,
            "severity_score": tech.get("severity_score", 0),
            "severity_level": tech.get("severity_level", ""),
            "mitigations": all_mits,
            "priority": priority,
        })

    # Sort by descending severity
    technique_mitigations.sort(key=lambda t: t["severity_score"], reverse=True)

    # Priority actions = mitigations from Critical/High techniques
    priority_actions = []
    for tm in technique_mitigations:
        if tm["severity_level"] in ("Critical", "High"):
            for mit in tm["mitigations"][:2]:
                priority_actions.append(f"[{tm['id']}] {mit}")

    return {
        "technique_mitigations": technique_mitigations,
        "global_recommendations": llm_result.get("global_recommendations", []),
        "priority_actions": priority_actions[:10],
    }