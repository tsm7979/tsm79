"""
TSM Layer - Load Balancer
Distributes requests across multiple backend instances.
"""

from typing import List, Optional
from dataclasses import dataclass
from enum import Enum
import random
import time


class LoadBalancingStrategy(Enum):
    """Load balancing strategies."""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    RANDOM = "random"


@dataclass
class Backend:
    """Backend server instance."""
    id: str
    host: str
    port: int
    weight: int = 1
    active_connections: int = 0
    is_healthy: bool = True
    last_health_check: float = 0


class LoadBalancer:
    """Load balancer for distributing requests."""

    def __init__(self, strategy: LoadBalancingStrategy = LoadBalancingStrategy.ROUND_ROBIN):
        self.strategy = strategy
        self.backends: List[Backend] = []
        self.current_index = 0

    def add_backend(self, backend_id: str, host: str, port: int, weight: int = 1):
        """Add a backend server."""
        backend = Backend(
            id=backend_id,
            host=host,
            port=port,
            weight=weight
        )
        self.backends.append(backend)

    def remove_backend(self, backend_id: str) -> bool:
        """Remove a backend server."""
        self.backends = [b for b in self.backends if b.id != backend_id]
        return True

    def get_backend(self) -> Optional[Backend]:
        """Select a backend based on strategy."""
        healthy_backends = [b for b in self.backends if b.is_healthy]

        if not healthy_backends:
            return None

        if self.strategy == LoadBalancingStrategy.ROUND_ROBIN:
            return self._round_robin(healthy_backends)

        elif self.strategy == LoadBalancingStrategy.LEAST_CONNECTIONS:
            return self._least_connections(healthy_backends)

        elif self.strategy == LoadBalancingStrategy.WEIGHTED_ROUND_ROBIN:
            return self._weighted_round_robin(healthy_backends)

        elif self.strategy == LoadBalancingStrategy.RANDOM:
            return random.choice(healthy_backends)

        return healthy_backends[0]

    def _round_robin(self, backends: List[Backend]) -> Backend:
        """Round-robin selection."""
        backend = backends[self.current_index % len(backends)]
        self.current_index += 1
        return backend

    def _least_connections(self, backends: List[Backend]) -> Backend:
        """Select backend with least active connections."""
        return min(backends, key=lambda b: b.active_connections)

    def _weighted_round_robin(self, backends: List[Backend]) -> Backend:
        """Weighted round-robin selection."""
        total_weight = sum(b.weight for b in backends)
        target = self.current_index % total_weight
        self.current_index += 1

        cumulative = 0
        for backend in backends:
            cumulative += backend.weight
            if target < cumulative:
                return backend

        return backends[-1]

    def mark_connection_start(self, backend_id: str):
        """Mark connection start."""
        for backend in self.backends:
            if backend.id == backend_id:
                backend.active_connections += 1
                break

    def mark_connection_end(self, backend_id: str):
        """Mark connection end."""
        for backend in self.backends:
            if backend.id == backend_id:
                backend.active_connections = max(0, backend.active_connections - 1)
                break

    def health_check(self, backend_id: str, is_healthy: bool):
        """Update backend health status."""
        for backend in self.backends:
            if backend.id == backend_id:
                backend.is_healthy = is_healthy
                backend.last_health_check = time.time()
                break

    def get_stats(self) -> dict:
        """Get load balancer statistics."""
        return {
            'total_backends': len(self.backends),
            'healthy_backends': sum(1 for b in self.backends if b.is_healthy),
            'strategy': self.strategy.value,
            'backends': [
                {
                    'id': b.id,
                    'host': b.host,
                    'port': b.port,
                    'active_connections': b.active_connections,
                    'is_healthy': b.is_healthy
                }
                for b in self.backends
            ]
        }


# Global load balancer
_global_lb: Optional[LoadBalancer] = None


def get_load_balancer() -> LoadBalancer:
    """Get the global load balancer."""
    global _global_lb
    if _global_lb is None:
        _global_lb = LoadBalancer()
    return _global_lb
