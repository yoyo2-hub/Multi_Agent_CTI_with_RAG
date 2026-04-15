from llm_helper import get_llm
import re
import json
from Tools import extract_entities
from Tools import detect_behaviors
from Tools import detect_patterns
from Tools import rag_search


def analyze_message(message: str) -> dict:
    """
    Entry point: analyzes a raw CTI message through all 4 tools directly.

    Args:
        message: Raw CTI message text (Telegram, web, report, etc.)

    Returns:
        Complete CTI analysis dict ready for the MITRE Mapping Agent.
    """
    print("[Step 1] Extracting entities...")
    entities = extract_entities.invoke({"message": message})

    print("[Step 2] Detecting behaviors...")
    behaviors_result = detect_behaviors.invoke({"message": message})

    print("[Step 3] Detecting patterns...")
    patterns_result = detect_patterns.invoke({"messages": [message]})

    print("[Step 4] Searching RAG database...")
    rag_raw = rag_search.invoke({"query": message[:300]})
    rag_result = json.loads(rag_raw) if isinstance(rag_raw, str) else rag_raw

    print("[✅] CTI Analysis complete.")
    return {
        "status": "success",

        # For the MITRE agent
        "entities": entities,
        "behaviors": behaviors_result.get("behaviors_detected", []),

        # Extra context passed to generate_report
        "rag_context": {
            "num_results": len(rag_result.get("results", [])),
            "results": rag_result.get("results", []),
        },
        "patterns": {
            "threat_classification": patterns_result.get("threat_classification", ""),
            "emerging_terms": patterns_result.get("emerging_terms", []),
            "semantic_summary": patterns_result.get("semantic_summary", ""),
            "predicted_next_steps": patterns_result.get("predicted_next_steps", []),
        },

        # Full results for debugging
        "behaviors_full": behaviors_result,
        "patterns_full": patterns_result,
    }