"""
Immutable Trace - Forensic Ledger for AI Evolution.

This module provides a cryptographically verifiable trace of all code changes
initiated by the AI ("Evolution" or "Self-Coding").
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from threading import Lock

logger = logging.getLogger(__name__)

class ImmutableTrace:
    """
    Manages the immutable ledger for code evolution events.
    Appends cryptographically hashed records to a local ledger.
    """

    _lock = Lock()

    def __init__(self, ledger_path: str = "data/trace_ledger.jsonl"):
        """
        Initialize the ImmutableTrace ledger.

        Args:
            ledger_path: Path to the local JSONL ledger file.
        """
        self.ledger_path = ledger_path
        self._ensure_ledger_dir()

    def _ensure_ledger_dir(self):
        """Ensure the ledger directory exists."""
        os.makedirs(os.path.dirname(self.ledger_path), exist_ok=True)

    def compute_hash(self, content: str) -> str:
        """
        Compute SHA-256 hash of the content.

        Args:
            content: The string content to hash.

        Returns:
            Hex string of the SHA-256 hash.
        """
        if content is None:
            return ""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def log_trace(
        self,
        action: str,
        before_content: Optional[str],
        after_content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Log a trace entry to the immutable ledger.

        Args:
            action: Description of the action (e.g., "generate_tool", "modify_tool").
            before_content: The code before modification (None for new creation).
            after_content: The code after modification/creation.
            metadata: Additional context for the event.

        Returns:
            The created log entry.
        """
        metadata = metadata or {}

        before_hash = self.compute_hash(before_content)
        after_hash = self.compute_hash(after_content)

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "before_hash": before_hash,
            "after_hash": after_hash,
            "metadata": metadata
        }

        json_entry = json.dumps(entry)

        with self._lock:
            try:
                with open(self.ledger_path, "a") as f:
                    f.write(json_entry + "\n")
                logger.info(f"Immutable trace logged: {action} ({after_hash[:8]})")
            except IOError as e:
                logger.critical(f"Failed to write to immutable ledger: {e}")

        return entry

# Global instance
immutable_trace = ImmutableTrace()
