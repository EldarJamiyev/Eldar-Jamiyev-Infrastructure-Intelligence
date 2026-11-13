---
name: vector-db
description: ChromaDB/Pinecone/Weaviate — collection design, hybrid search, metadata filters
metadata:
  type: skill
  triggers: ["chroma", "chromadb", "pinecone", "weaviate", "qdrant", "vector database", "vector store"]
---

# Vector Database Patterns

## ChromaDB (local)
```python
import chromadb
client = chromadb.PersistentClient(path="./chroma_db")
collection = client.get_or_create_collection(
    name="documents",
    metadata={"hnsw:space": "cosine"}
)

collection.add(
    documents=["doc text..."],
    embeddings=[[0.1, 0.2, ...]],
    metadatas=[{"source": "file.pdf", "page": 1}],
    ids=["doc-001"]
)

results = collection.query(
    query_embeddings=[query_embedding],
    n_results=5,
    where={"source": "file.pdf"}
)
```

## Pinecone (production)
```python
from pinecone import Pinecone
pc = Pinecone(api_key=os.environ["PINECONE_API_KEY"])
index = pc.Index("my-index")
index.upsert(vectors=[{"id": "v1", "values": embedding, "metadata": {"text": "..."}}])
results = index.query(vector=query_embedding, top_k=10, filter={"category": "tech"})
```

## Rules
- Dimension must match embedding model (text-embedding-3-small: 1536, nomic: 768)
- Always store original text in metadata
- Use cosine similarity for text, dot product for normalized vectors
- Batch upserts (100-1000) — never one-by-one
