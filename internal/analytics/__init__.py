"""
TSM Layer - Analytics
Usage analytics, cost tracking, and reporting.
"""

import time
from typing import Dict, List, Optional
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class UsageMetrics:
    """Usage metrics for a time period."""
    total_requests: int
    successful_requests: int
    failed_requests: int
    total_tokens: int
    total_cost: float
    avg_latency_ms: float
    pii_detections: int
    local_routes: int
    cloud_routes: int


class Analytics:
    """Analytics engine for tracking usage and costs."""

    def __init__(self):
        self.metrics_buffer: List[Dict] = []

    def track_request(self, user_id: str, org_id: str, model: str,
                     tokens: int, cost: float, latency_ms: float,
                     has_pii: bool, routing: str, success: bool):
        """Track a single request."""
        metric = {
            'timestamp': time.time(),
            'user_id': user_id,
            'org_id': org_id,
            'model': model,
            'tokens': tokens,
            'cost': cost,
            'latency_ms': latency_ms,
            'has_pii': has_pii,
            'routing': routing,
            'success': success
        }
        self.metrics_buffer.append(metric)

        # Flush to database periodically
        if len(self.metrics_buffer) > 100:
            self._flush_metrics()

    def _flush_metrics(self):
        """Flush metrics buffer to database."""
        # In production, batch insert to database
        self.metrics_buffer = []

    def get_user_metrics(self, user_id: str, start_time: float,
                        end_time: float) -> UsageMetrics:
        """Get usage metrics for a user."""
        from database import get_database
        db = get_database()

        query = """
            SELECT
                COUNT(*) as total_requests,
                SUM(CASE WHEN metadata LIKE '%success\":true%' THEN 1 ELSE 0 END) as successful,
                SUM(cost) as total_cost,
                AVG(latency_ms) as avg_latency,
                SUM(has_pii) as pii_count,
                SUM(CASE WHEN routing_decision LIKE '%local%' THEN 1 ELSE 0 END) as local_routes,
                SUM(CASE WHEN routing_decision LIKE '%cloud%' THEN 1 ELSE 0 END) as cloud_routes
            FROM requests
            WHERE user_id = ? AND created_at >= ? AND created_at <= ?
        """

        results = db.execute(query, (user_id, start_time, end_time))
        data = results[0] if results else {}

        return UsageMetrics(
            total_requests=data.get('total_requests', 0),
            successful_requests=data.get('successful', 0),
            failed_requests=data.get('total_requests', 0) - data.get('successful', 0),
            total_tokens=0,  # Would need separate tracking
            total_cost=data.get('total_cost', 0.0),
            avg_latency_ms=data.get('avg_latency', 0.0),
            pii_detections=data.get('pii_count', 0),
            local_routes=data.get('local_routes', 0),
            cloud_routes=data.get('cloud_routes', 0)
        )

    def get_organization_metrics(self, org_id: str, start_time: float,
                                end_time: float) -> UsageMetrics:
        """Get usage metrics for an organization."""
        from database import get_database
        db = get_database()

        query = """
            SELECT
                COUNT(*) as total_requests,
                SUM(cost) as total_cost,
                AVG(latency_ms) as avg_latency,
                SUM(has_pii) as pii_count
            FROM requests
            WHERE organization_id = ? AND created_at >= ? AND created_at <= ?
        """

        results = db.execute(query, (org_id, start_time, end_time))
        data = results[0] if results else {}

        return UsageMetrics(
            total_requests=data.get('total_requests', 0),
            successful_requests=data.get('total_requests', 0),
            failed_requests=0,
            total_tokens=0,
            total_cost=data.get('total_cost', 0.0),
            avg_latency_ms=data.get('avg_latency', 0.0),
            pii_detections=data.get('pii_count', 0),
            local_routes=0,
            cloud_routes=0
        )

    def get_model_usage(self, start_time: float, end_time: float) -> Dict[str, int]:
        """Get usage breakdown by model."""
        from database import get_database
        db = get_database()

        query = """
            SELECT model, COUNT(*) as count
            FROM requests
            WHERE created_at >= ? AND created_at <= ?
            GROUP BY model
            ORDER BY count DESC
        """

        results = db.execute(query, (start_time, end_time))
        return {row['model']: row['count'] for row in (results or [])}

    def get_cost_breakdown(self, org_id: str, start_time: float,
                          end_time: float) -> Dict[str, float]:
        """Get cost breakdown by model for an organization."""
        from database import get_database
        db = get_database()

        query = """
            SELECT model, SUM(cost) as total_cost
            FROM requests
            WHERE organization_id = ? AND created_at >= ? AND created_at <= ?
            GROUP BY model
            ORDER BY total_cost DESC
        """

        results = db.execute(query, (org_id, start_time, end_time))
        return {row['model']: row['total_cost'] for row in (results or [])}


# Global analytics instance
_global_analytics: Optional[Analytics] = None


def get_analytics() -> Analytics:
    """Get the global analytics instance."""
    global _global_analytics
    if _global_analytics is None:
        _global_analytics = Analytics()
    return _global_analytics
