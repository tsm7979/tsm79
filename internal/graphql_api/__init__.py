"""
TSM Layer - GraphQL API
GraphQL interface for complex queries and mutations.
"""

from typing import Dict, List, Optional, Any


# GraphQL schema definition
SCHEMA = """
type Query {
    user(id: ID!): User
    organization(id: ID!): Organization
    requests(userId: ID!, limit: Int): [Request]
    metrics(userId: ID!, startTime: Float!, endTime: Float!): Metrics
    health: HealthStatus
}

type Mutation {
    createUser(email: String!, name: String, role: String): User
    createOrganization(name: String!, tier: String): Organization
    createAPIKey(userId: ID!, name: String, permissions: [String]): APIKey
    revokeAPIKey(keyId: ID!): Boolean
}

type User {
    id: ID!
    email: String!
    name: String
    organization: Organization
    role: String!
    createdAt: Float!
}

type Organization {
    id: ID!
    name: String!
    tier: String!
    users: [User]
    stats: OrganizationStats
}

type Request {
    id: ID!
    userId: ID!
    model: String!
    hasPii: Boolean!
    routingDecision: String!
    cost: Float!
    latencyMs: Float!
    createdAt: Float!
}

type Metrics {
    totalRequests: Int!
    successfulRequests: Int!
    failedRequests: Int!
    totalCost: Float!
    avgLatencyMs: Float!
    piiDetections: Int!
}

type OrganizationStats {
    userCount: Int!
    requests24h: Int!
    cost24h: Float!
}

type APIKey {
    id: ID!
    userId: ID!
    name: String
    permissions: [String]
    createdAt: Float!
}

type HealthStatus {
    status: String!
    uptimeSeconds: Float!
    checks: [HealthCheck]
}

type HealthCheck {
    component: String!
    status: String!
    message: String!
}
"""


class GraphQLResolver:
    """GraphQL query and mutation resolvers."""

    # Queries
    @staticmethod
    def resolve_user(id: str) -> Optional[Dict]:
        """Get user by ID."""
        from database import get_database
        db = get_database()
        return db.get_user(id)

    @staticmethod
    def resolve_organization(id: str) -> Optional[Dict]:
        """Get organization by ID."""
        from database import get_database
        db = get_database()
        return db.get_organization(id)

    @staticmethod
    def resolve_requests(user_id: str, limit: int = 100) -> List[Dict]:
        """Get user requests."""
        from database import get_database
        db = get_database()
        return db.get_user_requests(user_id, limit)

    @staticmethod
    def resolve_metrics(user_id: str, start_time: float, end_time: float) -> Dict:
        """Get user metrics."""
        from analytics import get_analytics
        analytics = get_analytics()
        metrics = analytics.get_user_metrics(user_id, start_time, end_time)

        return {
            'totalRequests': metrics.total_requests,
            'successfulRequests': metrics.successful_requests,
            'failedRequests': metrics.failed_requests,
            'totalCost': metrics.total_cost,
            'avgLatencyMs': metrics.avg_latency_ms,
            'piiDetections': metrics.pii_detections
        }

    @staticmethod
    async def resolve_health() -> Dict:
        """Get system health."""
        from monitoring import get_monitor
        monitor = get_monitor()
        return await monitor.check_health()

    # Mutations
    @staticmethod
    def resolve_create_user(email: str, name: str = None, role: str = "user") -> Dict:
        """Create a new user."""
        import uuid
        from database import get_database

        user_id = str(uuid.uuid4())
        db = get_database()
        db.create_user(user_id, email, name, role=role)

        return db.get_user(user_id)

    @staticmethod
    def resolve_create_organization(name: str, tier: str = "free") -> Dict:
        """Create a new organization."""
        import uuid
        from tenancy import get_tenancy_manager

        org_id = str(uuid.uuid4())
        tenancy = get_tenancy_manager()
        org = tenancy.create_organization(org_id, name, tier)

        return {
            'id': org.id,
            'name': org.name,
            'tier': org.tier
        }

    @staticmethod
    def resolve_create_api_key(user_id: str, name: str = None,
                               permissions: List[str] = None) -> Dict:
        """Create API key."""
        import uuid
        from identity import get_identity_manager
        from database import get_database

        identity = get_identity_manager()
        api_key = identity.generate_api_key()
        key_hash = identity.hash_api_key(api_key)
        key_id = str(uuid.uuid4())

        db = get_database()
        db.create_api_key(key_id, user_id, key_hash, name, permissions)

        return {
            'id': key_id,
            'userId': user_id,
            'name': name,
            'permissions': permissions or [],
            'key': api_key  # Return only once at creation
        }


# GraphQL handler (simplified - in production use graphene or strawberry)
class GraphQLAPI:
    """GraphQL API handler."""

    def __init__(self):
        self.schema = SCHEMA
        self.resolver = GraphQLResolver()

    async def execute(self, query: str, variables: Dict = None) -> Dict:
        """Execute GraphQL query."""
        # In production, use a proper GraphQL library
        # This is a simplified placeholder
        return {
            'data': None,
            'errors': ['GraphQL execution not fully implemented - use proper library']
        }


# Global GraphQL API
_global_graphql: Optional[GraphQLAPI] = None


def get_graphql_api() -> GraphQLAPI:
    """Get the global GraphQL API."""
    global _global_graphql
    if _global_graphql is None:
        _global_graphql = GraphQLAPI()
    return _global_graphql
