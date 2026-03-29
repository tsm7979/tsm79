"""
TSM Layer - RAG (Retrieval-Augmented Generation)
Vector search and document retrieval for context enhancement.
"""

import numpy as np
from typing import List, Dict, Optional
from dataclasses import dataclass
import hashlib


@dataclass
class Document:
    """Document for RAG."""
    id: str
    content: str
    embedding: Optional[np.ndarray] = None
    metadata: Dict = None


class SimpleEmbedder:
    """Simple embedding using TF-IDF-like approach."""

    def __init__(self, vocab_size: int = 1000):
        self.vocab_size = vocab_size
        self.word_to_idx: Dict[str, int] = {}

    def embed(self, text: str) -> np.ndarray:
        """Create simple embedding for text."""
        words = text.lower().split()
        embedding = np.zeros(self.vocab_size)

        for word in words:
            if word not in self.word_to_idx:
                if len(self.word_to_idx) < self.vocab_size:
                    self.word_to_idx[word] = len(self.word_to_idx)

            if word in self.word_to_idx:
                idx = self.word_to_idx[word]
                embedding[idx] += 1

        # Normalize
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm

        return embedding


class VectorStore:
    """Simple vector store for document retrieval."""

    def __init__(self):
        self.documents: Dict[str, Document] = {}
        self.embedder = SimpleEmbedder()

    def add_document(self, content: str, metadata: Dict = None) -> str:
        """Add a document to the store."""
        doc_id = hashlib.sha256(content.encode()).hexdigest()[:12]
        embedding = self.embedder.embed(content)

        doc = Document(
            id=doc_id,
            content=content,
            embedding=embedding,
            metadata=metadata or {}
        )

        self.documents[doc_id] = doc
        return doc_id

    def search(self, query: str, top_k: int = 5) -> List[Document]:
        """Search for relevant documents."""
        query_embedding = self.embedder.embed(query)

        # Calculate cosine similarity
        scores = []
        for doc in self.documents.values():
            if doc.embedding is not None:
                similarity = np.dot(query_embedding, doc.embedding)
                scores.append((similarity, doc))

        # Sort by score
        scores.sort(key=lambda x: x[0], reverse=True)

        return [doc for _, doc in scores[:top_k]]

    def get_document(self, doc_id: str) -> Optional[Document]:
        """Get document by ID."""
        return self.documents.get(doc_id)

    def delete_document(self, doc_id: str) -> bool:
        """Delete a document."""
        if doc_id in self.documents:
            del self.documents[doc_id]
            return True
        return False


class RAG:
    """RAG system for context-enhanced LLM requests."""

    def __init__(self):
        self.vector_store = VectorStore()

    def add_context(self, content: str, metadata: Dict = None) -> str:
        """Add context document."""
        return self.vector_store.add_document(content, metadata)

    def enhance_prompt(self, prompt: str, top_k: int = 3) -> str:
        """Enhance prompt with relevant context."""
        relevant_docs = self.vector_store.search(prompt, top_k)

        if not relevant_docs:
            return prompt

        context_parts = ["Relevant context:"]
        for i, doc in enumerate(relevant_docs, 1):
            context_parts.append(f"{i}. {doc.content}")

        context = "\n".join(context_parts)
        enhanced_prompt = f"{context}\n\nUser query: {prompt}"

        return enhanced_prompt

    def get_relevant_context(self, query: str, top_k: int = 5) -> List[Dict]:
        """Get relevant context documents."""
        docs = self.vector_store.search(query, top_k)
        return [
            {
                'id': doc.id,
                'content': doc.content,
                'metadata': doc.metadata
            }
            for doc in docs
        ]


# Global RAG instance
_global_rag: Optional[RAG] = None


def get_rag() -> RAG:
    """Get the global RAG instance."""
    global _global_rag
    if _global_rag is None:
        _global_rag = RAG()
    return _global_rag
