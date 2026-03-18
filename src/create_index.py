# 2_create_index.py
"""
Création de l'index FAISS avec all-mpnet-base-v2
"""

from pathlib import Path
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS

FAISS_INDEX_PATH = Path('faiss_cti_index')


# 2_create_index.py

def get_embedding_model():
    """
    all-mpnet-base-v2 :
    - 768 dimensions
    - 384 tokens max
    - Meilleure qualité théorique
    """
    return HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-mpnet-base-v2",
        model_kwargs={
            'device': 'cpu',
        },
        encode_kwargs={
            'normalize_embeddings': True,
            'batch_size': 64,    # Plus petit car modèle plus lourd
        }
    )


def create_index(documents):
    """Crée et sauvegarde l'index FAISS."""
    print(f"\n🔄 Création de l'index FAISS...")
    print(f"  Modèle : all-mpnet-base-v2 (768 dims)")
    print(f"  Documents : {len(documents)}")

    embeddings = get_embedding_model()

    vectorstore = FAISS.from_documents(
        documents=documents,
        embedding=embeddings,
    )

    # Sauvegarde
    vectorstore.save_local(str(FAISS_INDEX_PATH))
    print(f"  ✅ Sauvegardé : {FAISS_INDEX_PATH}/")

    return vectorstore


def load_index():
    """Charge un index existant."""
    if not FAISS_INDEX_PATH.exists():
        raise FileNotFoundError(

        )

    embeddings = get_embedding_model()

    vectorstore = FAISS.load_local(
        str(FAISS_INDEX_PATH),
        embeddings,
        allow_dangerous_deserialization=True,
    )
    print(
        f"✅ Index chargé : "
        f"{vectorstore.index.ntotal} vecteurs"
    )
    return vectorstore


if __name__ == "__main__":
    from load_documents import load_and_prepare

    docs = load_and_prepare()
    vectorstore = create_index(docs)
    print(f"  Vecteurs : {vectorstore.index.ntotal}")