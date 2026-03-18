import os

# ── Paths to data ───────────────────────────────────
FAISS_INDEX_PATH = "/kaggle/input/datasets/chaymadallel/data-faiss/index.faiss"
JSONL_DATA_PATH  = "/kaggle/input/datasets/chaymadallel/dataa-1/darkgram_cti_final.jsonl"

# ── LLM & Embedding ──────────────────────────────────
EMBEDDING_MODEL = "sentence-transformers/all-mpnet-base-v2"

# ✅ Since your working test used this string, use it here too:
LLM_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"

TEMPERATURE = 0.1

# ── RAG & Hybrid Logic ──────────────────────────────
RAG_TOP_K = 5
WEIGHTS = {
    "static":      0.5,   
    "llm":         0.4,   
    "statistical": 0.2,   
}