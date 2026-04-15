from Tools import extract_entities
from Tools import rag_search
from Tools import detect_patterns
from Tools import detect_behaviors

# This list will be passed directly to the LangChain Agent
CTI_TOOLS = [
    extract_entities,
    rag_search,
    detect_patterns,
    detect_behaviors
]