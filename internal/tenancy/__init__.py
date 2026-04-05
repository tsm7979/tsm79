"""
TSM Layer - Multi-Tenancy
Organization isolation and resource management for enterprise deployments.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
import time


@dataclass
class Organization:
    """Organization (tenant) representation."""
    id: str
    name: str
    tier: str  # free, pro, enterprise
    created_at: float
    settings: Dict
    resource_limits: Dict
    is_active: bool = True


class TenancyManager:
    """Manages multi-tenant isolation and resources."""

    def __init__(self):
        self.organizations: Dict[str, Organization] = {}
        self.user_org_mapping: Dict[str, str] = {}  # user_id -> org_id

    def create_organization(self, org_id: str, name: str, tier: str = "free") -> Organization:
        """Create a new organization."""
        # Default resource limits based on tier
        limits = self._get_tier_limits(tier)

        org = Organization(
            id=org_id,
            name=name,
            tier=tier,
            created_at=time.time(),
            settings={},
            resource_limits=limits
        )

        self.organizations[org_id] = org

        # Save to database
        from database import get_database
        db = get_database()
        db.create_organization(org_id, name, tier)

        return org

    def get_organization(self, org_id: str) -> Optional[Organization]:
        """Get organization by ID."""
        if org_id in self.organizations:
            return self.organizations[org_id]

        # Load from database
        from database import get_database
        db = get_database()
        org_data = db.get_organization(org_id)

        if org_data:
            org = Organization(
                id=org_data['id'],
                name=org_data['name'],
                tier=org_data['tier'],
                created_at=org_data['created_at'],
                settings={},
                resource_limits=self._get_tier_limits(org_data['tier'])
            )
            self.organizations[org_id] = org
            return org

        return None

    def assign_user_to_org(self, user_id: str, org_id: str) -> bool:
        """Assign a user to an organization."""
        if org_id not in self.organizations:
            return False

        self.user_org_mapping[user_id] = org_id
        return True

    def get_user_organization(self, user_id: str) -> Optional[Organization]:
        """Get the organization for a user."""
        org_id = self.user_org_mapping.get(user_id)
        if org_id:
            return self.get_organization(org_id)
        return None

    def _get_tier_limits(self, tier: str) -> Dict:
        """Get resource limits for a tier."""
        limits = {
            "free": {
                "max_users": 5,
                "max_requests_per_day": 1000,
                "max_tokens_per_day": 100_000,
                "max_storage_mb": 100,
                "max_api_keys": 2,
                "features": ["basic_llm", "local_models"]
            },
            "pro": {
                "max_users": 50,
                "max_requests_per_day": 10_000,
                "max_tokens_per_day": 1_000_000,
                "max_storage_mb": 1000,
                "max_api_keys": 10,
                "features": ["basic_llm", "local_models", "advanced_routing", "audit_logs"]
            },
            "enterprise": {
                "max_users": -1,  # unlimited
                "max_requests_per_day": -1,
                "max_tokens_per_day": -1,
                "max_storage_mb": -1,
                "max_api_keys": -1,
                "features": [
                    "basic_llm", "local_models", "advanced_routing",
                    "audit_logs", "sso", "rbac", "custom_policies",
                    "priority_support", "sla"
                ]
            }
        }
        return limits.get(tier, limits["free"])

    def check_resource_limit(self, org_id: str, resource: str, current_usage: int) -> bool:
        """Check if organization is within resource limits."""
        org = self.get_organization(org_id)
        if not org:
            return False

        limit = org.resource_limits.get(resource, 0)
        if limit == -1:  # unlimited
            return True

        return current_usage < limit

    def update_tier(self, org_id: str, new_tier: str) -> bool:
        """Upgrade/downgrade organization tier."""
        org = self.get_organization(org_id)
        if not org:
            return False

        org.tier = new_tier
        org.resource_limits = self._get_tier_limits(new_tier)

        # Update in database
        from database import get_database
        db = get_database()
        db.execute(
            "UPDATE organizations SET tier = ? WHERE id = ?",
            (new_tier, org_id)
        )

        return True

    def get_organization_users(self, org_id: str) -> List[str]:
        """Get all users in an organization."""
        return [user_id for user_id, oid in self.user_org_mapping.items() if oid == org_id]

    def get_organization_stats(self, org_id: str) -> Dict:
        """Get usage statistics for an organization."""
        from database import get_database
        db = get_database()

        # Get recent requests
        query = """
            SELECT
                COUNT(*) as total_requests,
                SUM(cost) as total_cost,
                AVG(latency_ms) as avg_latency
            FROM requests
            WHERE organization_id = ? AND created_at > ?
        """
        cutoff = time.time() - 86400  # Last 24 hours
        results = db.execute(query, (org_id, cutoff))

        stats = results[0] if results else {}
        users = self.get_organization_users(org_id)

        return {
            'organization_id': org_id,
            'user_count': len(users),
            'requests_24h': stats.get('total_requests', 0),
            'cost_24h': stats.get('total_cost', 0),
            'avg_latency_ms': stats.get('avg_latency', 0)
        }


# Global tenancy manager
_global_tenancy: Optional[TenancyManager] = None


def get_tenancy_manager() -> TenancyManager:
    """Get the global tenancy manager."""
    global _global_tenancy
    if _global_tenancy is None:
        _global_tenancy = TenancyManager()
    return _global_tenancy
