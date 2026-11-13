---
name: rag-patterns
description: Retrieval Augmented Generation — chunking, embedding, vector store, reranking, hybrid search
metadata:
  type: skill
  triggers: ["rag", "retrieval", "embedding", "vector", "chunking", "semantic search", "knowledge base"]
---

# RAG Patterns

## Pipeline
1. **Ingest**: load docs → chunk → embed → store
2. **Retrieve**: embed query → vector search → rerank → top-k
3. **Generate**: context + query → LLM → response

## Chunking
```python
# LangChain v0.3+ import path:
from langchain_text_splitters import RecursiveCharacterTextSplitter
# LangChain v0.1 (old): from langchain.text_splitter import ...
splitter = RecursiveCharacterTextSplitter(
    chunk_size=512,
    chunk_overlap=50,
    separators=["\n\n", "\n", ".", " "]
)
```

## Hybrid search (better than pure vector)
```python
# BM25 (keyword) + vector → Reciprocal Rank Fusion
def hybrid_search(query, vector_results, bm25_results, alpha=0.5):
    scores = {}
    for rank, doc in enumerate(vector_results):
        scores[doc.id] = scores.get(doc.id, 0) + alpha / (rank + 60)
    for rank, doc in enumerate(bm25_results):
        scores[doc.id] = scores.get(doc.id, 0) + (1-alpha) / (rank + 60)
    return sorted(scores, key=scores.get, reverse=True)
```

## Reranking
```python
from sentence_transformers import CrossEncoder
reranker = CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2')
scores = reranker.predict([(query, doc.text) for doc in candidates])
reranked = [doc for _, doc in sorted(zip(scores, candidates), reverse=True)]
```

## Metadata
Always store: `source`, `page`, `created_at`, `doc_type` → enables pre-filter before vector search.
