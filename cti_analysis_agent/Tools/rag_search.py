import json
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.tools import tool

# Same config as the indexing
INDEX_PATH = "/kaggle/working/faiss_cti_index"
MODEL_NAME = "sentence-transformers/all-mpnet-base-v2"

# Lazy load resources
_vectorstore = None

def _get_vectorstore():
    global _vectorstore
    if _vectorstore is None:
        embeddings = HuggingFaceEmbeddings(
            model_name=MODEL_NAME,
            model_kwargs={'device': 'cpu'} # Use CPU for inference to save GPU
        )
        _vectorstore = FAISS.load_local(
            INDEX_PATH, 
            embeddings, 
            allow_dangerous_deserialization=True
        )
    return _vectorstore

@tool
def rag_search(query: str, k: int = 5) -> str:
    """Search the Telegram CTI database for cyber threat intelligence."""
    vs = _get_vectorstore()
    # similarity_search_with_score returns (Document, score)
    # Note: For L2 distance (default), LOWER score is BETTER.
    results_with_scores = vs.similarity_search_with_score(query, k=k)
    
    formatted_results = []
    for doc, score in results_with_scores:
        formatted_results.append({
            "score": round(float(score), 4),
            "content": doc.page_content[:500],
            "channel": doc.metadata.get("channel_name", "unknown"),
            "date": doc.metadata.get("date", "")
        })
        
    return json.dumps({"query": query, "results": formatted_results})