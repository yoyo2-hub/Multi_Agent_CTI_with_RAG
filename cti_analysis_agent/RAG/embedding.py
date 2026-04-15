import json
import re
import pandas as pd
import faiss
import numpy as np
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter 
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS

# 1. SETTINGS
JSONL_PATH = 'data/darkgram_cti_final.jsonl'
EXPORT_PATH = "faiss_cti_index" # Directory for LangChain FAISS

# 2. YOUR ORIGINAL LOGIC (Optimized)
def extract_content(text):
    match = re.search(r'CONTENT:\s*(.+)$', text, re.DOTALL)
    return match.group(1).strip() if match else text.strip()

def load_and_prepare():
    print("📂 Loading and Filtering Data...")
    documents = []
    with open(JSONL_PATH, 'r', encoding='utf-8') as f:
        for line in f:
            obj = json.loads(line.strip())
            raw_text, metadata = obj.get('text', ''), obj.get('metadata', {})
            content = extract_content(raw_text)
            
            # Simple skip for empty or URL-only
            if not content or re.match(r'^https?://\S+$', content.strip()): continue
            
            # Clean Metadata (ensure strings/numbers only)
            clean_meta = {k: (v if v is not None else "") for k, v in metadata.items() 
                         if isinstance(v, (str, int, float, bool)) or v is None}
            
            documents.append(Document(page_content=content, metadata=clean_meta))
    
    # Smart Split (approx 300 tokens)
    splitter = RecursiveCharacterTextSplitter(chunk_size=700, chunk_overlap=70)
    return splitter.split_documents(documents)

# 3. RUN THE INDEXING
print("🚀 Starting Pipeline...")
docs = load_and_prepare()

embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-mpnet-base-v2",
    model_kwargs={'device': 'cuda'}, # Use the Kaggle GPU!
    encode_kwargs={'normalize_embeddings': True}
)

print(f"🧠 Embedding {len(docs)} chunks... (This will be fast on GPU)")
vectorstore = FAISS.from_documents(docs, embeddings)

# 4. SAVE (Creates the directory with .faiss and .pkl)
vectorstore.save_local(EXPORT_PATH)
print(f"✅ DONE! Index saved to {EXPORT_PATH}")