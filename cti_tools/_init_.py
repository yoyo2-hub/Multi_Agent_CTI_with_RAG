"""
CTI Tools
"""
from cti_tools.entity_extractor import extract_entities
from cti_tools.rag_retriver import rag_search
from cti_tools.pattern_detector import detect_patterns
from cti_tools.behavior_detector import detect_behaviors

CTI_TOOLS = [
    extract_entities,
    rag_search,
    detect_patterns,
    detect_behaviors,
]