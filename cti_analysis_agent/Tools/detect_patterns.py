'''TOOL 3 — Pattern Detection (HYBRID)
  Layer 1 (STATIC)     : Frequencies of known CTI words
  Layer 2 (STATISTICAL): Z-score, entropy, anomaly detection
  Layer 3 (LLM)        : Semantic classification of patterns
'''
import re
import math
from collections import Counter
from langchain_core.tools import tool
from llm_helper import llm_analyze
STOP_WORDS = {
    "the", "a", "an", "is", "it", "to", "in", "for", "on", "of",
    "and", "or", "this", "that", "with", "from", "by", "at", "as",
    "are", "was", "be", "has", "had", "have", "not", "but", "can",
    "will", "just", "we", "you", "he", "she", "they", "my", "your",
    "all", "been", "if", "so", "no", "do", "up", "out", "its",
    "than", "then", "also", "into", "over", "such", "about", "some",
    "would", "could", "should", "their", "there", "these", "those",
    "were", "what", "when", "where", "which", "who", "how", "each",
    "other", "more", "very", "only", "here", "after", "before",
    "de", "la", "le", "les", "et", "en", "un", "une", "des", "du",
    "est", "que", "qui", "dans", "pour", "pas", "sur", "avec", "ce",
    "il", "elle", "nous", "vous", "ils", "son", "ses", "aux", "par",
}
# Short tokens but CRITICAL in CTI — never filter these
CTI_SHORT_TOKENS = {
    "c2", "c&c", "ip", "vm", "av", "os", "id", "db", "xss", "sql",
    "rce", "lfi", "rfi", "poc", "apt", "rat", "bot", "dns", "tcp",
    "udp", "ssh", "rdp", "smb", "ftp", "vpn", "tor", "ioc", "ttps",
    "edr", "ids", "ips", "waf", "dll", "exe", "cmd", "ps1", "bat",
}
def _tokenize_smart(text: str) -> list[str]: 
    # Extract words, numbers, and compound tokens
    raw_tokens = re.findall(r"[a-zA-Z0-9&][\w&.-]*", text.lower())
    
    filtered = []
    for token in raw_tokens:
        if token in CTI_SHORT_TOKENS:
            filtered.append(token)
        elif token in STOP_WORDS:
            continue
        # Filter out very short tokens that are not in the CTI short list
        elif token.isdigit() and len(token) < 4:
            continue
        else:
            filtered.append(token)
    
    return filtered

#LAYER 1 : STATIC ANALYSIS (Frequencies)
CTI_TERMS_SEEDS = {
    "ransomware", "phishing", "exploit", "vulnerability", "cve",
    "botnet", "c2", "payload", "dropper", "loader", "stealer",
    "keylogger", "backdoor", "rootkit", "zero-day", "0day",
    "breach", "leak", "dump", "credentials", "brute", "ddos",
    "injection", "xss", "sqli", "rce", "privilege", "escalation",
    "lateral", "exfiltration", "encryption", "ransom", "bitcoin",
    "monero", "tor", "onion", "obfuscation", "persistence",
    "evasion", "sandbox", "rat", "apt", "campaign", "malware",
    "trojan", "worm", "spyware", "adware", "cryptominer",
}


def _static_frequency_analysis(tokens: list[str]) -> dict:
    """Layer 1: Count and identify known CTI terms."""
    word_counts = Counter(tokens)
    
    top_30 = word_counts.most_common(30)
    top_keywords = [
        {
            "word": word,
            "count": count,
            "is_known_cti_term": word in CTI_TERMS_SEEDS,
        }
        for word, count in top_30
    ]
    
    known_cti_found = sorted(
        [w for w in word_counts if w in CTI_TERMS_SEEDS],
        key=lambda w: word_counts[w],
        reverse=True,
    )
    
    return {
        "word_counts": word_counts,
        "top_keywords": top_keywords,
        "known_cti_terms": known_cti_found,
    }
#LAYER 2 : STATISTICAL ANALYSIS (Anomalies)
def _statistical_anomaly_detection(word_counts: Counter) -> dict:
    """
      Layer 2: Statistical anomaly detection.

      Methods:
      - Z-Score: identifies words whose frequency significantly deviates 
        from the mean (> 2 standard deviations)
      - Shannon entropy: measures vocabulary diversity.
        Low entropy = very repetitive messages (likely campaign)
        High entropy = diverse messages (likely noise)
      - Concentration ratio: % of total vocabulary in top 10 words
      """
    if not word_counts:
        return {"anomalies": [], "entropy": 0, "concentration_ratio": 0}
    
    counts = list(word_counts.values())
    total = sum(counts)
    n = len(counts)
    
    # Z-Score for each word
    mean = total / n
    variance = sum((c - mean) ** 2 for c in counts) / n
    std_dev = math.sqrt(variance) if variance > 0 else 1
    
    anomalies = []
    for word, count in word_counts.items():
        z_score = (count - mean) / std_dev
        # Threshold: z > 2.0 = statistically unusual
        if z_score > 2.0:
            anomalies.append({
                "word": word,
                "count": count,
                "z_score": round(z_score, 2),
                "interpretation": (
                    f"'{word}' apparaît {count}x "
                    f"(moyenne={mean:.1f}, z={z_score:.1f}) "
                    f"— fréquence anormalement élevée"
                ),
            })
    anomalies.sort(key=lambda a: a["z_score"], reverse=True)
    
    # Shannon entropy (to see how diverse or repetitive the vocabulary is/Low diversity may indicate a coordinated attack campaign)
    entropy = 0
    for count in counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    
    # Maximum theoretical entropy (all words equally frequent)
    max_entropy = math.log2(n) if n > 1 else 0
    # Diversity ratio: 0 = very concentrated, 1 = very diverse
    diversity_ratio = entropy / max_entropy if max_entropy > 0 else 0
    
    # Concentration ratio (top 10 words)
    top_10_sum = sum(count for _, count in word_counts.most_common(10))
    concentration = top_10_sum / total if total > 0 else 0
    
    return {
        "anomalies": anomalies[:10],  # Top 10 anomalies
        "entropy": round(entropy, 3),
        "max_entropy": round(max_entropy, 3),
        "diversity_ratio": round(diversity_ratio, 3),
        "concentration_ratio": round(concentration, 3),
        "stats": {
            "mean_frequency": round(mean, 2),
            "std_deviation": round(std_dev, 2),
            "unique_tokens": n,
            "total_tokens": total,
        },
        "interpretation": _interpret_stats(diversity_ratio, concentration),
    }
def _interpret_stats(diversity: float, concentration: float) -> str:
    """Generates human-readable interpretation of statistics."""
    parts = []
    
    if diversity < 0.3:
        parts.append(
            "Very concentrated vocabulary → likely targeted campaign "
            "or very similar messages (spam/botnet)"
        )
    elif diversity < 0.6:
        parts.append(
            "Moderately diverse vocabulary → possible themed messages "
            "related to the same actor or technique"
        )
    else:
        parts.append(
            "Very diverse vocabulary → varied messages, "
            "no obvious dominant campaign or theme"
        )
    
    if concentration > 0.5:
        parts.append(
            f"The top 10 most frequent words represent "
            f"{concentration:.0%} of the total → strong dominant theme"
        )
    
    return " | ".join(parts)
#  LAYER 3 : LLM CLASSIFICATION (Semantic)
LLM_PATTERN_PROMPT = """You are a literal-minded Cyber Threat Intelligence (CTI) Auditor. 

### CRITICAL NEUTRALITY MANDATE:
You must distinguish between routine IT work and actual cyber attacks. 
- Do NOT search for 'hidden' malicious meanings in standard corporate English.
- Words like 'view', 'scheduled', 'new', 'update', or 'internal' are NOT suspicious on their own.
- If the text describes a scheduled reboot, a patch, or an HR portal, it is NOT an attack.

### CLASSIFICATION CATEGORIES (Choose EXACTLY ONE):
1. BENIGN: Internal company news, holiday calendars, general greetings, or HR links.
2. ADMINISTRATIVE: Scheduled reboots, system patching, IT maintenance, or routine server tickets.
3. MALICIOUS: ONLY if there is explicit evidence of Command & Control (C2), Exploit payloads, Ransomware, or Unauthorized Data Leaks.

### YOUR TASKS:
1. CLASSIFY the primary theme using the categories above.
2. If BENIGN or ADMINISTRATIVE: Set 'is_malicious' to false, 'confidence' to 1.0, and 'predicted_next_steps' to ['None' or 'Routine Maintenance'].
3. If MALICIOUS: Identify specific patterns and predict the attacker's next steps.
STRICT JSON SCHEMA: You must use the exact keys 'keywords' and 'attack_pattern' inside the 'correlated_patterns' list. Do not use 'pattern' or 'description'.
Return ONLY valid JSON:
{
    "threat_classification": "BENIGN | ADMINISTRATIVE | RANSOMWARE | PHISHING | APT | etc.",
    "is_malicious": false,
    "confidence": 1.0,
    "emerging_terms": [],
    "correlated_patterns": [],
    "predicted_next_steps": ["Step 1", "Step 2"],
    "flagged_jargon": [],
    "semantic_summary": "Provide a literal explanation. If safe, state why (e.g., 'Routine system maintenance notice')."
}
"""


def _llm_pattern_analysis(
    top_keywords: list[dict],
    anomalies: list[dict],
    sample_messages: list[str],
) -> dict:
    """
    Layer 3: Semantic analysis using LLM of detected patterns.

    The LLM receives:
    - Most frequent keywords
    - Statistical anomalies
    - A sample of raw messages (for context)
    """
    # Construct the context for LLM
    context_parts = [
        "## Top Keywords (by frequency):",
        *[f"  - {kw['word']}: {kw['count']}x" for kw in top_keywords[:20]],
        "",
        "## Statistical Anomalies:",
        *[f"  - {a['interpretation']}" for a in anomalies[:5]],
        "",
        "## Sample Messages (first 3):",
        *[f"  ---\n  {msg[:300]}" for msg in sample_messages[:3]],
    ]
    
    context = "\n".join(context_parts)
    result = llm_analyze(LLM_PATTERN_PROMPT, context)
    if "llm_failed" in result or "parse_error" in result:
        # GPU memory might have failed → retry once or fallback
        result = {
            "threat_classification": "unknown",
            "confidence": 0.0,
            "emerging_terms": [],
            "correlated_patterns": [],
            "predicted_next_steps": [],
            "semantic_summary": "LLM analysis unavailable",
        }
    return result
#TOOL LANGCHAIN
@tool
def detect_patterns(messages: list[str]) -> dict:
    """
    Hybrid pattern analysis on a set of CTI messages.

    Layer 1 (Static)     : Known CTI term frequencies
    Layer 2 (Statistical): Z-score, entropy, anomalies
    Layer 3 (LLM)        : Semantic classification and emerging terms
    """
    if not messages:
        return {"error": "No messages provided for analysis."}
    
    # 1. Tokenization
    all_tokens = []
    for msg in messages:
        all_tokens.extend(_tokenize_smart(msg))
    
    # 2. Layer 1 : Static Frequency Analysis
    static = _static_frequency_analysis(all_tokens)
    
    # 3. Layer 2 : Statistical Anomalies
    stats = _statistical_anomaly_detection(static["word_counts"])
    
    # 4. Layer 3 : LLM Classification
    llm_analysis = _llm_pattern_analysis(
        top_keywords=static["top_keywords"],
        anomalies=stats["anomalies"],
        sample_messages=messages,
    )

    # --- 🛡️ THE SAFETY GATE (Corrected Logic) ---
    has_hard_evidence = len(static["known_cti_terms"]) > 0
    has_statistical_anomaly = len(stats["anomalies"]) > 0
    # "General Evidence" exists if either Layer 1 or Layer 2 caught something
    has_evidence = has_hard_evidence or has_statistical_anomaly
    
    classification = llm_analysis.get("threat_classification", "UNKNOWN")
    confidence = llm_analysis.get("confidence", 0.0)
    is_malicious = llm_analysis.get("is_malicious", False)

    # Only trust "MALICIOUS" if there is underlying evidence
    if not has_hard_evidence and classification == "MALICIOUS":
        if has_statistical_anomaly:
            # Stats say something is weird, but no known CTI words found
            classification = "POTENTIALLY SUSPICIOUS (Unconfirmed)"
            confidence *= 0.7 
        else:
            # Total hallucination check: no keywords AND no anomalies
            classification = "BENIGN / INFORMATIONAL (No Evidence)"
            confidence *= 0.5
            is_malicious = False
    
    # Force is_malicious to False if we have zero evidence overall
    final_is_malicious = is_malicious if has_evidence else False

    # 5. Merged Result (Synchronized with local variables)
    return {
        "total_messages": len(messages),
        "is_malicious": final_is_malicious,
        "unique_tokens": stats["stats"]["unique_tokens"],
        
        # Layer 1
        "top_keywords": static["top_keywords"],
        "known_cti_terms": static["known_cti_terms"],
        
        # Layer 2
        "statistical_anomalies": stats["anomalies"],
        "entropy": stats["entropy"],
        "diversity_ratio": stats["diversity_ratio"],
        "concentration_ratio": stats["concentration_ratio"],
        "stats_interpretation": stats["interpretation"],
        
        # Layer 3 (Using our Gate-filtered variables)
        "threat_classification": classification,
        "classification_confidence": round(confidence, 2),
        "emerging_terms": llm_analysis.get("emerging_terms", []),
        "correlated_patterns": llm_analysis.get("correlated_patterns", []),
        "predicted_next_steps": llm_analysis.get("predicted_next_steps", []),
        "flagged_jargon": llm_analysis.get("flagged_jargon", []),
        "semantic_summary": llm_analysis.get("semantic_summary", ""),
    }
