from langchain_core.tools import tool
from llm_helper import llm_analyze
import json

# BASE SCORES BY TACTIC
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

W_IMPACT = 0.35
W_EXPLOIT = 0.25
W_PREVALENCE = 0.20
W_STEALTH = 0.20

def _compute_score(impact: float, exploit: float, prevalence: float, stealth: float) -> float:
    score = (W_IMPACT * impact + W_EXPLOIT * exploit + W_PREVALENCE * prevalence + W_STEALTH * stealth)
    return round(min(5.0, max(0.0, score)), 2)

def _classify(score: float) -> str:
    if score >= 4.0: return "Critical"
    elif score >= 3.0: return "High"
    elif score >= 2.0: return "Medium"
    else: return "Low"

def _static_severity(technique: dict) -> dict:
    tactic = technique.get("tactic", "")
    base = TACTIC_BASE_SCORES.get(tactic, (3.0, 3.0, 3.0, 3.0))
    score = _compute_score(*base)
    return {
        "impact": base[0], "exploitability": base[1],
        "prevalence": base[2], "stealth": base[3],
        "score": score, "level": _classify(score),
    }

LLM_SEVERITY_PROMPT = """Act as an Autonomous Cyber Risk Engine.
Analyze the provided MITRE techniques to identify logical attack paths.

REQUIRED JSON FORMAT:
{
  "adj": [{"id": "TXXXX", "imp": 1.0-5.0, "exp": 1.0-5.0, "pre": 1.0-5.0, "ste": 1.0-5.0, "res": "reason"}],
  "bonus": 0.0-1.0,
  "reason": "Explain the technical relationship"
}

RULES:
- NO STATIC EXAMPLES. 
- OUTPUT ONLY JSON."""

def _llm_severity_adjustment(techniques: list[dict]) -> dict:
    content = "Techniques found:\n" + "\n".join([f"- {t.get('id')} {t.get('name')}" for t in techniques])
    result = llm_analyze(LLM_SEVERITY_PROMPT, content)
    if result.get("llm_failed") or result.get("parse_error"):
        return {"adj": [], "bonus": 0.0, "reason": "LLM analysis failed"}
    return result

@tool
def calculate_severity(techniques: list[dict]) -> dict:
    """Calculates risk severity for MITRE techniques using a hybrid formula and LLM chaining logic."""
    if not techniques:
        return {"error": "No techniques provided"}

    # 1. Static Scoring
    scored = []
    for tech in techniques:
        sev = _static_severity(tech)
        scored.append({**tech, "severity_details": sev, "severity_score": sev["score"], "severity_level": sev["level"]})

    # 2. LLM Adjustment
    llm_adj = _llm_severity_adjustment(techniques)
    chain_bonus = min(0.5, llm_adj.get("bonus", 0.0))
    adj_map = {a["id"]: a for a in llm_adj.get("adj", [])}

    # 3. Apply Adjustments & Bonus
    for item in scored:
        tech_id = item.get("id", "")
        if tech_id in adj_map:
            a = adj_map[tech_id]
            item["severity_score"] = _compute_score(
                a.get("imp", item["severity_details"]["impact"]),
                a.get("exp", item["severity_details"]["exploitability"]),
                a.get("pre", item["severity_details"]["prevalence"]),
                a.get("ste", item["severity_details"]["stealth"])
            )
            item["llm_reasoning"] = a.get("res", "")

        if chain_bonus > 0:
            item["severity_score"] = round(min(5.0, item["severity_score"] + chain_bonus), 2)
        
        item["severity_level"] = _classify(item["severity_score"])

    global_score = round(max(s["severity_score"] for s in scored), 2) if scored else 0.0

    return {
        "scored_techniques": scored,
        "global_severity_score": global_score,
        "global_severity_level": _classify(global_score),
        "chain_bonus_applied": chain_bonus,
        "overall_reasoning": llm_adj.get("reason", "")
    }