from sentence_transformers import SentenceTransformer
model = SentenceTransformer('all-mpnet-base-v2')
vector = model.encode(["Sample CTI message"])
print(f"Vector Dimension: {vector.shape}") # Should be (768,)