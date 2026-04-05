"""
TSM Layer - Database Module
Handles database connections, schemas, and migrations.
"""

import sqlite3
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from contextlib import contextmanager
import time


class Database:
    """SQLite database manager for TSM Layer."""

    def __init__(self, db_path: str = "~/.tsm/tsm.db"):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self):
        """Initialize database schema."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    name TEXT,
                    organization_id TEXT,
                    role TEXT DEFAULT 'user',
                    created_at REAL NOT NULL,
                    last_login REAL,
                    is_active INTEGER DEFAULT 1
                )
            """)

            # Organizations table (for multi-tenancy)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS organizations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    tier TEXT DEFAULT 'free',
                    created_at REAL NOT NULL,
                    settings TEXT
                )
            """)

            # Requests table (audit log)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS requests (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    organization_id TEXT,
                    model TEXT,
                    prompt_hash TEXT,
                    response_hash TEXT,
                    has_pii INTEGER,
                    routing_decision TEXT,
                    cost REAL,
                    latency_ms REAL,
                    created_at REAL NOT NULL,
                    metadata TEXT
                )
            """)

            # API Keys table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    name TEXT,
                    permissions TEXT,
                    created_at REAL NOT NULL,
                    last_used REAL,
                    expires_at REAL,
                    is_active INTEGER DEFAULT 1
                )
            """)

            # Rate limits table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rate_limits (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    window_start REAL NOT NULL,
                    request_count INTEGER DEFAULT 0,
                    token_count INTEGER DEFAULT 0
                )
            """)

            # Policies table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS policies (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    rules TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL,
                    is_active INTEGER DEFAULT 1
                )
            """)

            # Cache metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cache_entries (
                    key_hash TEXT PRIMARY KEY,
                    model TEXT,
                    prompt_hash TEXT,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    hit_count INTEGER DEFAULT 0,
                    last_accessed REAL
                )
            """)

            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_requests_user ON requests(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_requests_org ON requests(organization_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_requests_created ON requests(created_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rate_limits_user ON rate_limits(user_id)")

            conn.commit()

    @contextmanager
    def get_connection(self):
        """Get database connection with context manager."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def execute(self, query: str, params: tuple = ()) -> Optional[List[Dict]]:
        """Execute a query and return results."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()

            if cursor.description:
                columns = [col[0] for col in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
            return None

    # User operations
    def create_user(self, user_id: str, email: str, name: str = None,
                   organization_id: str = None, role: str = "user") -> bool:
        """Create a new user."""
        query = """
            INSERT INTO users (id, email, name, organization_id, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        try:
            self.execute(query, (user_id, email, name, organization_id, role, time.time()))
            return True
        except:
            return False

    def get_user(self, user_id: str) -> Optional[Dict]:
        """Get user by ID."""
        query = "SELECT * FROM users WHERE id = ?"
        results = self.execute(query, (user_id,))
        return results[0] if results else None

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email."""
        query = "SELECT * FROM users WHERE email = ?"
        results = self.execute(query, (email,))
        return results[0] if results else None

    # Organization operations
    def create_organization(self, org_id: str, name: str, tier: str = "free") -> bool:
        """Create a new organization."""
        query = """
            INSERT INTO organizations (id, name, tier, created_at)
            VALUES (?, ?, ?, ?)
        """
        try:
            self.execute(query, (org_id, name, tier, time.time()))
            return True
        except:
            return False

    def get_organization(self, org_id: str) -> Optional[Dict]:
        """Get organization by ID."""
        query = "SELECT * FROM organizations WHERE id = ?"
        results = self.execute(query, (org_id,))
        return results[0] if results else None

    # Request logging
    def log_request(self, request_id: str, user_id: str, model: str,
                   has_pii: bool, routing_decision: str, cost: float = 0.0,
                   latency_ms: float = 0.0, metadata: Dict = None) -> bool:
        """Log an LLM request."""
        query = """
            INSERT INTO requests
            (id, user_id, model, has_pii, routing_decision, cost, latency_ms, created_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try:
            self.execute(query, (
                request_id, user_id, model, int(has_pii), routing_decision,
                cost, latency_ms, time.time(), json.dumps(metadata or {})
            ))
            return True
        except:
            return False

    def get_user_requests(self, user_id: str, limit: int = 100) -> List[Dict]:
        """Get recent requests for a user."""
        query = """
            SELECT * FROM requests
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        """
        return self.execute(query, (user_id, limit)) or []

    # API Key operations
    def create_api_key(self, key_id: str, user_id: str, key_hash: str,
                      name: str = None, permissions: List[str] = None) -> bool:
        """Create a new API key."""
        query = """
            INSERT INTO api_keys (id, user_id, key_hash, name, permissions, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        try:
            self.execute(query, (
                key_id, user_id, key_hash, name,
                json.dumps(permissions or []), time.time()
            ))
            return True
        except:
            return False

    def get_api_key(self, key_hash: str) -> Optional[Dict]:
        """Get API key by hash."""
        query = "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1"
        results = self.execute(query, (key_hash,))
        return results[0] if results else None

    # Analytics
    def get_usage_stats(self, user_id: str, days: int = 30) -> Dict:
        """Get usage statistics for a user."""
        cutoff = time.time() - (days * 86400)
        query = """
            SELECT
                COUNT(*) as total_requests,
                SUM(cost) as total_cost,
                AVG(latency_ms) as avg_latency,
                SUM(has_pii) as pii_requests
            FROM requests
            WHERE user_id = ? AND created_at > ?
        """
        results = self.execute(query, (user_id, cutoff))
        return results[0] if results else {}


# Global database instance
_global_db: Optional[Database] = None


def get_database() -> Database:
    """Get the global database instance."""
    global _global_db
    if _global_db is None:
        _global_db = Database()
    return _global_db
