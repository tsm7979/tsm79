"""
TSM Layer Memory
================

Memory and context management with RAG capabilities.
Provides vector storage, context retrieval, and conversation history.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import logging
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class MemoryEntry:
    """A single memory entry."""
    entry_id: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[List[float]] = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "entry_id": self.entry_id,
            "content": self.content,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }


class VectorStore:
    """
    Simple in-memory vector store for RAG.

    In production, this would be backed by:
    - Pinecone
    - Weaviate
    - Chroma
    - FAISS
    - Qdrant
    """

    def __init__(self, name: str = "default"):
        """Initialize vector store."""
        self.name = name
        self.entries: Dict[str, MemoryEntry] = {}
        logger.info(f"VectorStore '{name}' initialized")

    def add(
        self,
        content: str,
        metadata: Dict[str, Any] = None,
        embedding: List[float] = None
    ) -> str:
        """
        Add entry to vector store.

        Args:
            content: Text content
            metadata: Additional metadata
            embedding: Vector embedding (optional)

        Returns:
            Entry ID
        """
        # Generate ID from content hash
        entry_id = hashlib.sha256(content.encode()).hexdigest()[:16]

        entry = MemoryEntry(
            entry_id=entry_id,
            content=content,
            metadata=metadata or {},
            embedding=embedding
        )

        self.entries[entry_id] = entry
        logger.debug(f"Added entry {entry_id} to {self.name}")

        return entry_id

    def search(
        self,
        query: str,
        top_k: int = 5,
        filter_metadata: Dict[str, Any] = None
    ) -> List[MemoryEntry]:
        """
        Search vector store (simplified - keyword match for now).

        Args:
            query: Search query
            top_k: Number of results
            filter_metadata: Metadata filters

        Returns:
            List of matching entries
        """
        query_lower = query.lower()
        query_words = query_lower.split()

        # Simple keyword matching (would be vector similarity in production)
        matches = []
        for entry in self.entries.values():
            # Apply metadata filters
            if filter_metadata:
                if not all(
                    entry.metadata.get(k) == v
                    for k, v in filter_metadata.items()
                ):
                    continue

            # Keyword match - partial matching (supports "inject" matching "injection")
            content_lower = entry.content.lower()
            content_words = content_lower.split()
            
            # Check if any query word matches as substring in any content word
            match = False
            for query_word in query_words:
                for content_word in content_words:
                    if query_word in content_word or content_word in query_word:
                        match = True
                        break
                if match:
                    break
            
            if match:
                matches.append(entry)

        # Return top-k
        return matches[:top_k]

    def get(self, entry_id: str) -> Optional[MemoryEntry]:
        """Get entry by ID."""
        return self.entries.get(entry_id)

    def delete(self, entry_id: str) -> bool:
        """Delete entry."""
        if entry_id in self.entries:
            del self.entries[entry_id]
            return True
        return False

    def clear(self):
        """Clear all entries."""
        self.entries.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        return {
            "name": self.name,
            "total_entries": len(self.entries),
            "has_embeddings": sum(
                1 for e in self.entries.values() if e.embedding
            )
        }


class MemoryManager:
    """
    Manages conversation history and context retrieval.

    Provides:
    - Conversation history tracking
    - Context window management
    - RAG-based retrieval
    - Session management
    """

    def __init__(self, storage_path: str = "data/memory"):
        """
        Initialize memory manager.

        Args:
            storage_path: Path to persist memory data
        """
        self.storage_path = storage_path
        self.sessions: Dict[str, List[Dict]] = {}
        self.vector_store = VectorStore("main")
        logger.info(f"MemoryManager initialized at {storage_path}")

    def add_to_session(
        self,
        session_id: str,
        role: str,
        content: str,
        metadata: Dict[str, Any] = None
    ):
        """
        Add message to conversation session.

        Args:
            session_id: Session identifier
            role: Message role (user, assistant, system)
            content: Message content
            metadata: Additional metadata
        """
        if session_id not in self.sessions:
            self.sessions[session_id] = []

        message = {
            "role": role,
            "content": content,
            "metadata": metadata or {},
            "timestamp": datetime.utcnow().isoformat()
        }

        self.sessions[session_id].append(message)

        # Also add to vector store for RAG
        self.vector_store.add(
            content=content,
            metadata={
                "session_id": session_id,
                "role": role,
                **(metadata or {})
            }
        )

    def get_session_history(
        self,
        session_id: str,
        max_messages: int = 10
    ) -> List[Dict]:
        """
        Get conversation history for session.

        Args:
            session_id: Session identifier
            max_messages: Maximum messages to return

        Returns:
            List of messages (most recent first)
        """
        messages = self.sessions.get(session_id, [])
        return messages[-max_messages:]

    def get_context(
        self,
        query: str,
        session_id: str = None,
        max_results: int = 5
    ) -> List[str]:
        """
        Get relevant context for query using RAG.

        Args:
            query: Query text
            session_id: Optional session filter
            max_results: Maximum results

        Returns:
            List of relevant context strings
        """
        # Search vector store
        filter_meta = {"session_id": session_id} if session_id else None
        entries = self.vector_store.search(
            query=query,
            top_k=max_results,
            filter_metadata=filter_meta
        )

        return [entry.content for entry in entries]

    def clear_session(self, session_id: str):
        """Clear session history."""
        if session_id in self.sessions:
            del self.sessions[session_id]

    def get_stats(self) -> Dict[str, Any]:
        """Get memory manager statistics."""
        return {
            "total_sessions": len(self.sessions),
            "total_messages": sum(len(msgs) for msgs in self.sessions.values()),
            "vector_store": self.vector_store.get_stats()
        }


# Legacy aliases for backward compatibility
class ContextManager(MemoryManager):
    """Alias for MemoryManager."""
    async def store(
        self,
        input_text: str,
        result: Dict[str, Any],
        context: Dict[str, Any]
    ):
        """Store conversation context."""
        session_id = context.get("session_id", "default")
        self.add_to_session(
            session_id=session_id,
            role="user",
            content=input_text,
            metadata=context
        )
        if result.get("output"):
            self.add_to_session(
                session_id=session_id,
                role="assistant",
                content=str(result["output"]),
                metadata=result.get("metadata", {})
            )


class SemanticStore(VectorStore):
    """Alias for VectorStore."""
    async def store_embedding(self, text: str, metadata: Dict):
        """Store text embedding."""
        return self.add(content=text, metadata=metadata)

    async def retrieve(self, query: str, limit: int = 5):
        """Retrieve similar embeddings."""
        return self.search(query=query, top_k=limit)


# Global instances
memory_manager = MemoryManager()
context_manager = ContextManager()  # Legacy alias
semantic_store = SemanticStore()  # Legacy alias
