# test_replies_final.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from create_index import load_index

vectorstore = load_index()

# Test 1 : Query vide
print("TEST 1 : Query vide")
try:
    r = vectorstore.similarity_search(
        query="",
        k=5,
        filter={"parent_post_id": "381"},
    )
    print(f"  Résultats : {len(r)}")
except Exception as e:
    print(f"  ERREUR : {e}")

# Test 2 : Query = contenu du post
print("\nTEST 2 : Query = contenu du post")
try:
    r = vectorstore.similarity_search(
        query="DARK METHOD CLOUD LOGS upload fresh logs",
        k=5,
        filter={"parent_post_id": "381"},
    )
    print(f"  Résultats : {len(r)}")
    for doc in r:
        print(f"  → {doc.page_content[:60]}...")
except Exception as e:
    print(f"  ERREUR : {e}")

# Test 3 : Query = contenu d'une reply connue
print("\nTEST 3 : Query = contenu reply")
try:
    r = vectorstore.similarity_search(
        query="How can I use it",
        k=5,
        filter={"parent_post_id": "381"},
    )
    print(f"  Résultats : {len(r)}")
    for doc in r:
        print(f"  → {doc.page_content[:60]}...")
except Exception as e:
    print(f"  ERREUR : {e}")

# Test 4 : Combien de replies pour 381 au total
print("\nTEST 4 : Toutes les replies doc_type=reply")
r = vectorstore.similarity_search(
    query="How can I use it",
    k=100,
    filter={"doc_type": "reply"},
)
count_381 = sum(
    1 for doc in r
    if doc.metadata.get("parent_post_id") == "381"
)
print(f"  Replies avec parent=381 trouvées : {count_381}")