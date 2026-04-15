''' TOOL 4 — Dynamic Behavior Detection (HYBRIDE)
Hybrid detection of malicious behaviors.
    Layer 1 (Static) : Regex signatures for known techniques
    Layer 2 (LLM)    : Contextual analysis for new techniques
    Layer 3 (Scoring): Merge with weighted confidence score'''
import re
from langchain_core.tools import tool
from llm_helper import llm_analyze
from config import WEIGHTS
#  LAYER 1 : STATIC SIGNATURES (Regex)
BEHAVIOR_SIGNATURES = {
    "process_creation": {
        "description": "Suspicious process creation or injection",
        "patterns": [
            r"(?i)process\s*(creation|injection|hollowing)",
            r"(?i)(spawn|execute|launch|run)\s*(cmd|powershell|wscript|mshta|rundll)",
            r"(?i)(CreateProcess|NtCreateThread|WriteProcessMemory)",
            r"(?i)shellcode\s*(inject|execution|load)",
            r"(?i)(?:cmd|powershell|bash)\.exe",
            r"(?i)invoke[- ]expression",
        ],
        "severity": "high",
    },
    "registry_modification": {
        "description": "Windows registry modification for persistence",
        "patterns": [
            r"(?i)reg(istry)?\s*(key|value|modif|add|set|delete|write)",
            r"(?i)(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)",
            r"(?i)\\CurrentVersion\\Run",
            r"(?i)(autorun|startup|persistence)\s*(registry|reg)",
        ],
        "severity": "high",
    },
    "network_communication": {
        "description": "Suspicious network communications (C2, data exfiltration)",
        "patterns": [
            r"(?i)(c2|c&c|command\s*and\s*control)\s*(server|communication|beacon)",
            r"(?i)(beacon|callback|phone\s*home|heartbeat)",
            r"(?i)(exfiltrat|data\s*theft|upload\s*stolen)",
            r"(?i)(reverse\s*shell|bind\s*shell|netcat)",
            r"(?i)tor\s*(network|proxy|hidden|onion)",
        ],
        "severity": "critical",
    },
    "file_system_activity": {
        "description": "Suspicious file activity (encryption, deletion)",
        "patterns": [
            r"(?i)(encrypt|decrypt|cipher)\s*(file|document|data)",
            r"(?i)(ransom\s*note|\.locked|\.encrypted|\.crypt)",
            r"(?i)(drop|write|create)\s*(file|payload|executable|dll)",
            r"(?i)(delete|wipe|shred)\s*(log|shadow|backup)",
            r"(?i)vssadmin\s*delete\s*shadows",
        ],
        "severity": "high",
    },
    "credential_access": {
        "description": "Theft or access of credentials",
        "patterns": [
            r"(?i)(steal|dump|harvest|extract)\s*(credential|password|token|cookie)",
            r"(?i)(mimikatz|lsass\s*dump|hashdump|sam\s*dump)",
            r"(?i)(keylog|keystroke|clipboard)",
            r"(?i)(brute\s*force|password\s*spray|credential\s*stuff)",
        ],
        "severity": "critical",
    },
    "defense_evasion": {
        "description": "Evasion and anti-analysis techniques",
        "patterns": [
            r"(?i)(obfuscat|pack|crypt|encod)\s*(code|payload|script|binary)",
            r"(?i)(anti[- ]?(debug|vm|sandbox|analysis))",
            r"(?i)(disable|bypass|tamper)\s*(antivirus|defender|edr|amsi)",
            r"(?i)(fileless|living\s*off\s*the\s*land|lolbin)",
        ],
        "severity": "medium",
    },
}
def _static_behavior_detection(text: str) -> list[dict]:
    behaviors = []
    
    for category, config in BEHAVIOR_SIGNATURES.items():
        matched = []
        for pattern in config["patterns"]:
            matches = re.findall(pattern, text) # Find all matches in the text
            if matches:
                for m in matches:
                    indicator = m if isinstance(m, str) else m[0] # if m is a tuple (because regex has groups), take the first element
                    if indicator and indicator not in matched: # Only add the indicator if it's not empty and not already in the list
                        matched.append(indicator)
        if matched:
            behaviors.append({
                "category": category,
                "description": config["description"],
                "severity": config["severity"],
                "matched_indicators": matched[:10], #maximum 10 to avoid overload
                "match_count": len(matched), #total number of matched
                "detection_source": "static_regex",
                "confidence": 0.95,  # high confiance because match exact
            })
    
    return behaviors


#  LAYER 2 : LLM DETECTION (New behaviors)

LLM_BEHAVIOR_PROMPT = """You are a literal-minded Malware Behavior Analyst.

### CRITICAL NEUTRALITY MANDATE:
- Do NOT search for hidden malicious intent in routine IT tasks.
- Routine reboots, patching, or HR links are NOT "Persistence" or "Phishing".
- If the text describes legitimate activity, return an EMPTY behaviors list.

### TASK:
Analyze the message and identify explicit malicious behaviors:
1. Process manipulation (injection, hollowing)
2. Persistence (registry, scheduled tasks)
3. Network activity (C2, tunneling)
4. File system operations (encryption, dropper)
5. Credential theft (dumping, keylogging)
... (keep other categories) ...

Return ONLY valid JSON:
{
    "behaviors": [
        {
            "category": "category_name",
            "description": "Literal description",
            "severity": "critical|high|medium|low",
            "confidence": 0.0-1.0,
            "indicators": ["excerpts"],
            "is_novel": false,
            "notes": "Context"
        }
    ],
    "attack_chain_summary": "Summary",
    "novel_techniques": ["Description of any never-seen-before techniques"]
}"""


def _llm_behavior_detection(text: str) -> dict:
    result = llm_analyze(LLM_BEHAVIOR_PROMPT, text)
    if result.get("llm_failed") or result.get("parse_error"):
        return {"behaviors": [], "attack_chain_summary": "", "novel_techniques": []}
    return result
#  LAYER 3 : Fusion and Scoring

SEVERITY_SCORES = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

def _merge_behaviors(
    static_behaviors: list[dict],
    llm_result: dict,
) -> list[dict]:
    """
    Merge behaviors detected by both layers.
    Strategy:
    - If both layers detect the same category → boost confidence
    - If only static detects → high confidence (exact match)
    - If only LLM detects → moderate confidence (to be validated)
    - Novel behaviors detected by LLM are specially flagged
    """
    merged = []
    static_categories = {b["category"] for b in static_behaviors}
    llm_behaviors = llm_result.get("behaviors", [])
    llm_categories = {b.get("category", "") for b in llm_behaviors}
    # Static behaviors 
    for sb in static_behaviors:
        cat = sb["category"]
        # Check if LLM also detected this category
        llm_match = next(
            (lb for lb in llm_behaviors if lb.get("category") == cat),
            None,
        )
        
        if llm_match:
            # Boost confidence if both agree
            sb["confidence"] = min(0.99, sb["confidence"] + 0.05)
            sb["detection_source"] = "static+llm"
            sb["llm_notes"] = llm_match.get("notes", "")
            # Enrich indicators 
            llm_indicators = llm_match.get("indicators", [])
            all_indicators = sb["matched_indicators"] + [
                i for i in llm_indicators if i not in sb["matched_indicators"]
            ]
            sb["matched_indicators"] = all_indicators[:15]
        
        merged.append(sb)
    LLM_CATEGORY_MAP = {
    "process manipulation": "process_creation",
    "persistence mechanisms": "registry_modification",
    "network activity": "network_communication",
    "file system operations": "file_system_activity",
    "defense evasion": "defense_evasion",
    "discovery": "discovery",
    "lateral movement": "lateral_movement",
    "impact": "file_system_activity",
}
    # LLM-only behaviors
    for lb in llm_behaviors:
        cat = lb.get("category", "unknown").lower()
        cat = LLM_CATEGORY_MAP.get(cat, cat)  # ✅ normalize
        lb["category"] = cat
        if cat not in static_categories:
            merged.append({
                "category": cat,
                "description": lb.get("description", ""),
                "severity": lb.get("severity", "medium"),
                "confidence": lb.get("confidence", 0.7) * WEIGHTS["llm"],
                "matched_indicators": lb.get("indicators", []),
                "match_count": len(lb.get("indicators", [])),
                "detection_source": "llm_only",
                "is_novel": lb.get("is_novel", False),
                "llm_notes": lb.get("notes", ""),
            })
    
    # Sort by severity and confidence
    merged.sort(
        key=lambda b: (
            SEVERITY_SCORES.get(b["severity"], 0),
            b.get("confidence", 0),
        ),
        reverse=True,
    ) 
    return merged
#  TOOL LANGCHAIN 
@tool
def detect_behaviors(message: str) -> dict:
    """
    Hybrid detection of malicious behaviors.
    Layer 1 (Static) : Regex signatures for known techniques
    Layer 2 (LLM)    : Contextual analysis for new techniques
    Layer 3 (Scoring): Merge with weighted confidence score
    Args:
        message: Raw text describing a threat or malware
    Returns:
        Complete behavioral analysis with detection source
    """
    static_behaviors = _static_behavior_detection(message)
    llm_result = _llm_behavior_detection(message)
    merged = _merge_behaviors(static_behaviors, llm_result)
    # ==========================================
    # 🛡️ THE SAFETY THRESHOLD GATE
    # ==========================================
    ALERT_THRESHOLD = 0.5
    SEVERITY_SCORES = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

   # Only keep behaviors if:
    # A) Static Regex found it (high certainty)
    # B) Both Static AND LLM found it (verified)
    # C) LLM found it alone BUT has confidence >= 0.5 (weighted)
    filtered_merged = [
        b for b in merged 
        if b.get("detection_source") in ["static_regex", "static+llm"] 
        or b.get("confidence", 0) >= ALERT_THRESHOLD
    ]

    merged = filtered_merged
    max_severity = "none"
    if merged:
        max_severity = max(
            merged,
            key=lambda b: SEVERITY_SCORES.get(b["severity"], 0),
        )["severity"]
    # Count detections per source
    source_counts = {
        "static_regex": sum(1 for b in merged if b["detection_source"] == "static_regex"),
        "static_plus_llm": sum(1 for b in merged if b["detection_source"] == "static+llm"),
        "llm_only": sum(1 for b in merged if b["detection_source"] == "llm_only"),
    }
    
    # Identify novel techniques
    novel = [b for b in merged if b.get("is_novel")]
    
    # Generate a summary of the findings
    summary_parts = [f"{len(merged)} behavior(s) detected."]
    if source_counts["llm_only"] > 0:
        summary_parts.append(
            f"{source_counts['llm_only']} detected ONLY by LLM "
            f"(not covered by static signatures)."
        )
    if novel:
        summary_parts.append(
            f"{len(novel)} technique(s) potentially new(s) identified."
        )
    summary_parts.append(f"Max severity: {max_severity}.")
    
    return {
        "behaviors_detected": merged,
        "total_behaviors": len(merged),
        "max_severity": max_severity,
        "detection_sources": source_counts,
        "novel_techniques": llm_result.get("novel_techniques", []),
        "attack_chain": llm_result.get("attack_chain_summary", ""),
        "behavior_summary": " ".join(summary_parts),
    }
