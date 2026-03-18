"""
==========================================
 TOOL 1 — MITRE ATT&CK Mapper
==========================================
Associates detected behaviors with MITRE ATT&CK techniques.

Hybrid architecture:
  Layer 1 (Static)      : Direct behavior → technique mapping table
  Layer 2 (mitre-python): Search in the official STIX database
  Layer 3 (LLM)         : Contextual mapping for ambiguous behaviors

Dependency: mitreattack-python (STIX database access)
"""
import os
import json
from mitreattack.stix20 import MitreAttackData
from langchain_core.tools import tool
from llm_helper import llm_analyze

# Load the STIX Enterprise ATT&CK database
# Automatically downloaded by mitreattack-python
_mitre_data: MitreAttackData | None = None

def _get_mitre_data() -> MitreAttackData:
    global _mitre_data
    if _mitre_data is None:
        # Using the exact path found by the Smart Finder
        path = "/kaggle/input/datasets/chaymadallel/mitre-attack-stix/enterprise-attack.json"
        
        if os.path.exists(path):
            print(f"[MITRE] Loading database from: {path}")
            _mitre_data = MitreAttackData(path)
            print("[MITRE] Database loaded successfully.")
        else:
            raise FileNotFoundError(f"❌ Critical Error: enterprise-attack.json not found at {path}")
    return _mitre_data

#  LAYER 1 : STATIC MAPPING TABLE

BEHAVIOR_TO_TECHNIQUE = {
    "process_creation": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
    ],
    "process_injection": [
        {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
        {"id": "T1055.012", "name": "Process Hollowing", "tactic": "Defense Evasion"},
    ],
    "registry_modification": [
        {"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence"},
        {"id": "T1112", "name": "Modify Registry", "tactic": "Defense Evasion"},
    ],
    "scheduled_task": [
        {"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"},
    ],
    "network_communication": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control"},
    ],
    "dns_tunneling": [
        {"id": "T1071.004", "name": "DNS", "tactic": "Command and Control"},
    ],
    "exfiltration": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    ],
    "file_system_activity": [
        {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
        {"id": "T1485", "name": "Data Destruction", "tactic": "Impact"},
    ],
    "shadow_copy_deletion": [
        {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
    ],
    "credential_access": [
        {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
        {"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"},
        {"id": "T1056.001", "name": "Keylogging", "tactic": "Collection"},
    ],
    "defense_evasion": [
        {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
        {"id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "Defense Evasion"},
        {"id": "T1497", "name": "Virtualization/Sandbox Evasion", "tactic": "Defense Evasion"},
    ],
    "lateral_movement": [
        {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
        {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    ],
    "discovery": [
        {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
        {"id": "T1016", "name": "System Network Configuration Discovery", "tactic": "Discovery"},
    ],
}


def _static_mapping(behaviors: list[dict]) -> list[dict]:
    """Layer 1: Direct mapping via the static table."""
    results = []
    for behavior in behaviors:
        category = behavior.get("category", "")
        techniques = BEHAVIOR_TO_TECHNIQUE.get(category, [])
        for tech in techniques:
            results.append({
                **tech,
                "source_behavior": category,
                "mapping_source": "static_table",
            })
    return results

#  LAYER 2 : MITRE STIX SEARCH

def _search_mitre_stix(keyword: str, limit: int = 3) -> list[dict]:
    """
    Searches the official STIX database by keyword.
    Scans technique names and descriptions.
    """
    mitre = _get_mitre_data()
    results = []

    techniques = mitre.get_techniques()
    keyword_lower = keyword.lower()

    for tech in techniques:
        name = tech.get("name", "").lower()
        description = tech.get("description", "").lower()

        # Match if the keyword is in the name or description
        if keyword_lower in name or keyword_lower in description:
            # Retrieve the external ID (T1059, etc.)
            external_id = ""
            for ref in tech.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    external_id = ref.get("external_id", "")
                    break

            # Retrieve the tactic
            tactic = ""
            for phase in tech.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactic = phase.get("phase_name", "").replace("-", " ").title()
                    break

            if external_id:
                results.append({
                    "id": external_id,
                    "name": tech.get("name", ""),
                    "tactic": tactic,
                    "mapping_source": "mitre_stix",
                })

            if len(results) >= limit:
                break

    return results

#  LAYER 3 : LLM MAPPING (ambiguous behaviors)
LLM_MAPPING_PROMPT = """You are a MITRE ATT&CK mapping expert.

Given a list of malicious behaviors, map each to the most relevant
MITRE ATT&CK technique(s).

STRICT RULES:
- Only use REAL technique IDs from the MITRE ATT&CK framework
- "Dumping memory" → T1003 OS Credential Dumping, NOT PowerShell
- "Keylogger" → T1056.001, NOT T1059
- If you are not 100% sure, set confidence below 0.85
- Never guess — return empty mappings if uncertain

Return ONLY valid JSON:
{
    "mappings": [
        {
            "behavior": "original behavior description",
            "technique_id": "T1003.001",
            "technique_name": "LSASS Memory",
            "tactic": "Credential Access",
            "confidence": 0.95
        }
    ]
}"""

def _llm_mapping(behaviors: list[dict]) -> list[dict]:
    """Layer 3: LLM mapping for behaviors not covered by the static table."""
    descriptions = [
        f"- {b.get('category', 'unknown')}: {b.get('description', '')}"
        for b in behaviors
    ]
    content = "Behaviors to map:\n" + "\n".join(descriptions)

    result = llm_analyze(LLM_MAPPING_PROMPT, content)

    if result.get("llm_failed") or result.get("parse_error"):
        return []

    mappings = []
    for m in result.get("mappings", []):
        mappings.append({
            "id": m.get("technique_id", ""),
            "name": m.get("technique_name", ""),
            "tactic": m.get("tactic", ""),
            "source_behavior": m.get("behavior", ""),
            "mapping_source": "llm",
            "confidence": m.get("confidence", 0.7),
        })
    return mappings

#  MERGING AND DEDUPLICATION
def _merge_mappings(static: list, stix: list, llm: list) -> list[dict]:
    """Merges the 3 layers by deduplicating on technique ID."""
    seen = {}

    # Priority: static > stix > llm
    for mapping in static + stix + llm:
        tech_id = mapping.get("id", "")
        if tech_id and tech_id not in seen:
            seen[tech_id] = mapping
        elif tech_id in seen:
            # If already seen, record multiple sources
            existing = seen[tech_id]
            existing["mapping_source"] += f"+{mapping['mapping_source']}"

    return list(seen.values())
#  LANGCHAIN TOOL
@tool
def map_to_mitre(behaviors: list[dict]) -> dict:
    """
    Maps detected behaviors to MITRE ATT&CK techniques.

    Args:
        behaviors: List of behaviors from detect_behaviors.
                   Each item: {"category": str, "description": str, ...}

    Returns:
        {
            "techniques": [{"id", "name", "tactic", "mapping_source"}],
            "total_techniques": int,
            "tactics_covered": [str],
            "coverage_summary": str
        }
    """
    if not behaviors:
        return {"techniques": [], "total_techniques": 0, "error": "No behaviors provided"}

    #Layer 1: Static table 
    static_results = _static_mapping(behaviors)

    # Layer 2: STIX search by indicators
    stix_results = []
    for b in behaviors:
        for indicator in b.get("matched_indicators", [])[:2]:
            stix_results.extend(_search_mitre_stix(indicator, limit=2))

    # Layer 3: LLM for uncovered behaviors 
    # Identify behaviors without a static mapping
    covered = {r["source_behavior"] for r in static_results}
    uncovered = [b for b in behaviors if b.get("category") not in covered]
    llm_results = _llm_mapping(uncovered) if uncovered else []

    # Merge 
    techniques = _merge_mappings(static_results, stix_results, llm_results)

    # Tactics covered 
    tactics = sorted(set(t.get("tactic", "") for t in techniques if t.get("tactic")))

    return {
        "techniques": techniques,
        "total_techniques": len(techniques),
        "tactics_covered": tactics,
        "coverage_summary": (
            f"{len(techniques)} ATT&CK technique(s) mapped "
            f"covering {len(tactics)} tactic(s): {', '.join(tactics)}"
        ),
    }