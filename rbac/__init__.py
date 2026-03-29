"""
TSM Layer - RBAC (Role-Based Access Control)
Fine-grained permission system for enterprise deployments.
"""

from typing import Set, Dict, List, Optional
from enum import Enum
from dataclasses import dataclass


class Permission(Enum):
    """System permissions."""
    # Core operations
    REQUEST_LLM = "request:llm"
    REQUEST_LOCAL = "request:local"
    REQUEST_CLOUD = "request:cloud"

    # Data operations
    VIEW_OWN_DATA = "data:view:own"
    VIEW_ALL_DATA = "data:view:all"
    EXPORT_DATA = "data:export"
    DELETE_DATA = "data:delete"

    # Policy management
    CREATE_POLICY = "policy:create"
    UPDATE_POLICY = "policy:update"
    DELETE_POLICY = "policy:delete"
    VIEW_POLICY = "policy:view"

    # User management
    CREATE_USER = "user:create"
    UPDATE_USER = "user:update"
    DELETE_USER = "user:delete"
    VIEW_USERS = "user:view"

    # Organization management
    MANAGE_ORG = "org:manage"
    VIEW_ORG_STATS = "org:stats"
    MANAGE_BILLING = "org:billing"

    # API key management
    CREATE_API_KEY = "apikey:create"
    REVOKE_API_KEY = "apikey:revoke"
    VIEW_API_KEYS = "apikey:view"

    # Audit and compliance
    VIEW_AUDIT_LOG = "audit:view"
    EXPORT_AUDIT = "audit:export"
    VIEW_TRUST_LEDGER = "trust:view"

    # Advanced features
    MANAGE_MODELS = "models:manage"
    MANAGE_ROUTES = "routes:manage"
    MANAGE_CACHE = "cache:manage"
    RUN_SIMULATIONS = "sim:run"

    # Admin operations
    SYSTEM_ADMIN = "system:admin"
    VIEW_METRICS = "metrics:view"
    MANAGE_INTEGRATIONS = "integrations:manage"


@dataclass
class Role:
    """Role definition with permissions."""
    name: str
    permissions: Set[Permission]
    description: str


# Predefined roles
ROLES: Dict[str, Role] = {
    "admin": Role(
        name="admin",
        permissions={
            Permission.REQUEST_LLM,
            Permission.REQUEST_LOCAL,
            Permission.REQUEST_CLOUD,
            Permission.VIEW_ALL_DATA,
            Permission.EXPORT_DATA,
            Permission.CREATE_POLICY,
            Permission.UPDATE_POLICY,
            Permission.DELETE_POLICY,
            Permission.VIEW_POLICY,
            Permission.CREATE_USER,
            Permission.UPDATE_USER,
            Permission.DELETE_USER,
            Permission.VIEW_USERS,
            Permission.MANAGE_ORG,
            Permission.VIEW_ORG_STATS,
            Permission.MANAGE_BILLING,
            Permission.CREATE_API_KEY,
            Permission.REVOKE_API_KEY,
            Permission.VIEW_API_KEYS,
            Permission.VIEW_AUDIT_LOG,
            Permission.EXPORT_AUDIT,
            Permission.VIEW_TRUST_LEDGER,
            Permission.MANAGE_MODELS,
            Permission.MANAGE_ROUTES,
            Permission.MANAGE_CACHE,
            Permission.RUN_SIMULATIONS,
            Permission.SYSTEM_ADMIN,
            Permission.VIEW_METRICS,
            Permission.MANAGE_INTEGRATIONS,
        },
        description="Full system access"
    ),

    "developer": Role(
        name="developer",
        permissions={
            Permission.REQUEST_LLM,
            Permission.REQUEST_LOCAL,
            Permission.REQUEST_CLOUD,
            Permission.VIEW_OWN_DATA,
            Permission.EXPORT_DATA,
            Permission.VIEW_POLICY,
            Permission.CREATE_API_KEY,
            Permission.VIEW_API_KEYS,
            Permission.VIEW_AUDIT_LOG,
            Permission.VIEW_METRICS,
            Permission.RUN_SIMULATIONS,
        },
        description="Developer access with API key management"
    ),

    "analyst": Role(
        name="analyst",
        permissions={
            Permission.REQUEST_LLM,
            Permission.REQUEST_CLOUD,
            Permission.VIEW_OWN_DATA,
            Permission.EXPORT_DATA,
            Permission.VIEW_POLICY,
            Permission.VIEW_AUDIT_LOG,
            Permission.VIEW_METRICS,
        },
        description="Data analysis and reporting access"
    ),

    "user": Role(
        name="user",
        permissions={
            Permission.REQUEST_LLM,
            Permission.VIEW_OWN_DATA,
            Permission.VIEW_POLICY,
        },
        description="Basic user access"
    ),

    "readonly": Role(
        name="readonly",
        permissions={
            Permission.VIEW_OWN_DATA,
            Permission.VIEW_POLICY,
            Permission.VIEW_AUDIT_LOG,
        },
        description="Read-only access for auditors"
    ),
}


class RBAC:
    """Role-Based Access Control manager."""

    def __init__(self):
        self.roles = ROLES.copy()
        self.user_roles: Dict[str, Set[str]] = {}  # user_id -> set of role names

    def assign_role(self, user_id: str, role_name: str) -> bool:
        """Assign a role to a user."""
        if role_name not in self.roles:
            return False

        if user_id not in self.user_roles:
            self.user_roles[user_id] = set()

        self.user_roles[user_id].add(role_name)
        return True

    def revoke_role(self, user_id: str, role_name: str) -> bool:
        """Revoke a role from a user."""
        if user_id in self.user_roles:
            self.user_roles[user_id].discard(role_name)
            return True
        return False

    def get_user_roles(self, user_id: str) -> List[str]:
        """Get all roles assigned to a user."""
        return list(self.user_roles.get(user_id, set()))

    def get_user_permissions(self, user_id: str) -> Set[Permission]:
        """Get all permissions for a user (union of all roles)."""
        permissions = set()
        for role_name in self.user_roles.get(user_id, set()):
            role = self.roles.get(role_name)
            if role:
                permissions.update(role.permissions)
        return permissions

    def has_permission(self, user_id: str, permission: Permission) -> bool:
        """Check if a user has a specific permission."""
        user_permissions = self.get_user_permissions(user_id)

        # System admin has all permissions
        if Permission.SYSTEM_ADMIN in user_permissions:
            return True

        return permission in user_permissions

    def require_permission(self, user_id: str, permission: Permission) -> bool:
        """Require a permission (raises exception if not authorized)."""
        if not self.has_permission(user_id, permission):
            raise PermissionError(
                f"User {user_id} does not have permission: {permission.value}"
            )
        return True

    def create_custom_role(self, role_name: str, permissions: Set[Permission],
                          description: str = "") -> bool:
        """Create a custom role."""
        if role_name in self.roles:
            return False

        self.roles[role_name] = Role(
            name=role_name,
            permissions=permissions,
            description=description
        )
        return True

    def list_roles(self) -> List[Dict]:
        """List all available roles."""
        return [
            {
                "name": role.name,
                "description": role.description,
                "permission_count": len(role.permissions)
            }
            for role in self.roles.values()
        ]

    def get_role_details(self, role_name: str) -> Optional[Dict]:
        """Get detailed information about a role."""
        role = self.roles.get(role_name)
        if role:
            return {
                "name": role.name,
                "description": role.description,
                "permissions": [p.value for p in role.permissions]
            }
        return None


# Global RBAC instance
_global_rbac: Optional[RBAC] = None


def get_rbac() -> RBAC:
    """Get the global RBAC instance."""
    global _global_rbac
    if _global_rbac is None:
        _global_rbac = RBAC()
    return _global_rbac


def check_permission(user_id: str, permission: Permission) -> bool:
    """Quick permission check."""
    rbac = get_rbac()
    return rbac.has_permission(user_id, permission)


def require_permission(user_id: str, permission: Permission):
    """Decorator/function to require a permission."""
    rbac = get_rbac()
    rbac.require_permission(user_id, permission)
