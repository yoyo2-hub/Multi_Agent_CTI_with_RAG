"""
==========================================
 TOOL 2 — Severity / Risk Engine
==========================================
Calculates the severity of each mapped technique.

Formula:
  Severity = 0.35×Impact + 0.25×Exploitability + 0.20×Prevalence + 0.20×Stealth

Scale: 1.0 to 5.0
  0–2   → Low
  2–3   → Medium
  3–4   → High
  4–5   → Critical

Hybrid: static base scores + contextual LLM adjustment.
"""

from langchain_core.tools import tool
from llm_helper import llm_analyze

#  BASE SCORES BY TACTIC
# Each ATT&CK tactic has a default risk profile.
# Format: (impact, exploitability, prevalence, stealth)

TACTIC_BASE_SCORES = {
    "Execution":            (4.0, 4.0, 4.5, 2.5),
    "Persistence":          (3.5, 3.5, 4.0, 3.5),
    "Privilege Escalation": (4.5, 3.0, 3.0, 3.0),
    "Defense Evasion":      (3.0, 3.5, 4.0, 4.5),
    "Credential Access":    (4.5, 3.5, 4.0, 3.5),
    "Discovery":            (2.0, 4.0, 4.5, 3.0),
    "Lateral Movement":     (4.0, 3.0, 3.5, 3.0),
    "Collection":           (3.5, 3.5, 3.5, 3.0),
    "Command And Control":  (3.5, 3.0, 4.0, 4.0),
    "Exfiltration":         (5.0, 3.0, 3.0, 3.5),
    "Impact":               (5.0, 3.5, 3.5, 2.0),
    "Initial Access":       (3.5, 4.0, 4.5, 2.5),
    "Resource Development": (2.0, 3.0, 3.0, 4.0),
    "Reconnaissance":       (1.5, 4.0, 4.5, 3.5),
}

# Formula weights
W_IMPACT       = 0.35
W_EXPLOIT      = 0.25
W_PREVALENCE   = 0.20
W_STEALTH      = 0.20


def _compute_score(impact: float, exploit: float, prevalence: float, stealth: float) -> float:
    """Applies the weighted formula."""
    score = (
        W_IMPACT * impact
        + W_EXPLOIT * exploit
        + W_PREVALENCE * prevalence
        + W_STEALTH * stealth
    )
    return round(min(5.0, max(0.0, score)), 2)


def _classify(score: float) -> str:
    """Converts a numerical score into a severity level."""
    if score >= 4.0:
        return "Critical"
    elif score >= 3.0:
        return "High"
    elif score >= 2.0:
        return "Medium"
    else:
        return "Low"


def _static_severity(technique: dict) -> dict:
    """Calculates severity from the base scores by tactic."""
    tactic = technique.get("tactic", "")
    base = TACTIC_BASE_SCORES.get(tactic, (3.0, 3.0, 3.0, 3.0))

    score = _compute_score(*base)
    return {
        "impact": base[0],
        "exploitability": base[1],
        "prevalence": base[2],
        "stealth": base[3],
        "score": score,
        "level": _classify(score),
    }

#  CONTEXTUAL LLM ADJUSTMENT

LLM_SEVERITY_PROMPT = """You are a cyber risk assessment expert.

Given these MITRE ATT&CK techniques found in a threat analysis,
adjust the severity scores based on the COMBINATION of techniques.

Consider:
- Technique chaining (e.g., credential dump + lateral movement = higher risk)
- Combined stealth (evasion + encrypted C2 = harder to detect)
- Overall campaign sophistication

For each technique, provide adjusted scores (1.0 to 5.0):
{
    "adjustments": [
        {
            "technique_id": "T1059",
            "impact": 4.0,
            "exploitability": 4.0,
            "prevalence": 4.5,
            "stealth": 3.0,
            "reasoning": "brief explanation"
        }
    ],
    "chain_bonus": 0.0-1.0,
    "overall_reasoning": "Why this combination is dangerous"
}

chain_bonus is an additional score (0 to 1.0) added to ALL techniques
when the combination suggests a sophisticated multi-stage attack."""


def _llm_severity_adjustment(techniques: list[dict]) -> dict:
    """Asks the LLM to adjust scores based on the overall context."""
    content = "Techniques found:\n" + "\n".join(
        f"- {t.get('id', '?')} {t.get('name', '?')} ({t.get('tactic', '?')})"
        for t in techniques
    )

    result = llm_analyze(LLM_SEVERITY_PROMPT, content)

    if result.get("llm_failed") or result.get("parse_error"):
        return {"adjustments": [], "chain_bonus": 0.0}
    return result

#  LANGCHAIN TOOL
@tool
def calculate_severity(techniques: list[dict]) -> dict:
    """
    Calculates the severity for each mapped ATT&CK technique.

    Formula: 0.35×Impact + 0.25×Exploitability + 0.20×Prevalence + 0.20×Stealth
    Contextual adjustment by LLM (chain bonus for multi-stage attacks).

    Args:
        techniques: List from map_to_mitre (each item has "id", "name", "tactic")

    Returns:
        {
            "scored_techniques": [{id, name, tactic, severity_score, severity_level, details}],
            "global_severity_score": float,
            "global_severity_level": str,
            "chain_bonus_applied": float
        }
    """
    if not techniques:
        return {"error": "No techniques provided"}

    #Static base scores
    scored = []
    for tech in techniques:
        severity = _static_severity(tech)
        scored.append({
            **tech,
            "severity_details": severity,
            "severity_score": severity["score"],
            "severity_level": severity["level"],
        })

    # LLM adjustment 
    llm_adj = _llm_severity_adjustment(techniques)
    # Cap chain_bonus to avoid LLM over-inflation
    chain_bonus = min(0.5, llm_adj.get("chain_bonus", 0.0))

    # Apply individual LLM adjustments
    adj_map = {a["technique_id"]: a for a in llm_adj.get("adjustments", [])}
    for item in scored:
        tech_id = item.get("id", "")

        # If the LLM provided adjusted scores, use them
        if tech_id in adj_map:
            adj = adj_map[tech_id]
            adjusted_score = _compute_score(
                adj.get("impact", item["severity_details"]["impact"]),
                adj.get("exploitability", item["severity_details"]["exploitability"]),
                adj.get("prevalence", item["severity_details"]["prevalence"]),
                adj.get("stealth", item["severity_details"]["stealth"]),
            )
            item["severity_score"] = adjusted_score
            item["severity_level"] = _classify(adjusted_score)
            item["llm_reasoning"] = adj.get("reasoning", "")

        # Apply chain bonus
        if chain_bonus > 0:
            item["severity_score"] = round(
                min(5.0, item["severity_score"] + chain_bonus), 2
            )
            item["severity_level"] = _classify(item["severity_score"])

    # Global score 
    if scored:
        global_score = round(
            max(s["severity_score"] for s in scored), 2
        )
    else:
        global_score = 0.0

    return {
        "scored_techniques": scored,
        "global_severity_score": global_score,
        "global_severity_level": _classify(global_score),
        "chain_bonus_applied": chain_bonus,
        "overall_reasoning": llm_adj.get("overall_reasoning", ""),
    }