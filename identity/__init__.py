"""
TSM Layer - Identity & Authentication
User authentication, session management, and API key validation.
"""

import hashlib
import secrets
import time
import jwt
from typing import Optional, Dict
from dataclasses import dataclass


@dataclass
class User:
    """User identity."""
    id: str
    email: str
    name: Optional[str]
    organization_id: Optional[str]
    role: str
    created_at: float


@dataclass
class Session:
    """User session."""
    user_id: str
    token: str
    created_at: float
    expires_at: float
    metadata: Dict


class IdentityManager:
    """Manages user authentication and sessions."""

    def __init__(self, jwt_secret: str = None):
        self.jwt_secret = jwt_secret or secrets.token_urlsafe(32)
        self.sessions: Dict[str, Session] = {}
        self.api_key_cache: Dict[str, User] = {}

    def generate_api_key(self) -> str:
        """Generate a secure API key."""
        return f"tsm_{secrets.token_urlsafe(32)}"

    def hash_api_key(self, api_key: str) -> str:
        """Hash an API key for storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()

    def create_session(self, user_id: str, ttl: int = 3600) -> str:
        """Create a new user session."""
        payload = {
            'user_id': user_id,
            'exp': time.time() + ttl,
            'iat': time.time()
        }
        token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')

        session = Session(
            user_id=user_id,
            token=token,
            created_at=time.time(),
            expires_at=time.time() + ttl,
            metadata={}
        )
        self.sessions[token] = session
        return token

    def validate_session(self, token: str) -> Optional[str]:
        """Validate a session token and return user_id."""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            return payload.get('user_id')
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def revoke_session(self, token: str) -> bool:
        """Revoke a session."""
        if token in self.sessions:
            del self.sessions[token]
            return True
        return False

    def authenticate_api_key(self, api_key: str) -> Optional[User]:
        """Authenticate using API key."""
        key_hash = self.hash_api_key(api_key)

        # Check cache first
        if key_hash in self.api_key_cache:
            return self.api_key_cache[key_hash]

        # Query database
        from database import get_database
        db = get_database()
        key_data = db.get_api_key(key_hash)

        if key_data and key_data.get('is_active'):
            # Get user
            user_data = db.get_user(key_data['user_id'])
            if user_data:
                user = User(
                    id=user_data['id'],
                    email=user_data['email'],
                    name=user_data.get('name'),
                    organization_id=user_data.get('organization_id'),
                    role=user_data.get('role', 'user'),
                    created_at=user_data['created_at']
                )
                self.api_key_cache[key_hash] = user
                return user

        return None

    def get_current_user(self, auth_header: Optional[str]) -> Optional[User]:
        """Get current user from auth header."""
        if not auth_header:
            return None

        # Bearer token
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            user_id = self.validate_session(token)
            if user_id:
                from database import get_database
                db = get_database()
                user_data = db.get_user(user_id)
                if user_data:
                    return User(
                        id=user_data['id'],
                        email=user_data['email'],
                        name=user_data.get('name'),
                        organization_id=user_data.get('organization_id'),
                        role=user_data.get('role', 'user'),
                        created_at=user_data['created_at']
                    )

        # API Key
        elif auth_header.startswith('tsm_'):
            return self.authenticate_api_key(auth_header)

        return None


# Global identity manager
_global_identity: Optional[IdentityManager] = None


def get_identity_manager() -> IdentityManager:
    """Get the global identity manager."""
    global _global_identity
    if _global_identity is None:
        _global_identity = IdentityManager()
    return _global_identity
