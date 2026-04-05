"""
TSM Layer - Monitoring & Observability
Health checks, metrics collection, and system status.
"""

import time
import psutil
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class HealthStatus(Enum):
    """System health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class HealthCheck:
    """Health check result."""
    component: str
    status: HealthStatus
    message: str
    latency_ms: float
    timestamp: float


@dataclass
class Metric:
    """System metric."""
    name: str
    value: float
    unit: str
    tags: Dict[str, str]
    timestamp: float


class Monitor:
    """System monitoring and health checks."""

    def __init__(self):
        self.metrics: List[Metric] = []
        self.health_checks: Dict[str, HealthCheck] = {}
        self.start_time = time.time()

    def record_metric(self, name: str, value: float, unit: str = "", tags: Dict = None):
        """Record a metric."""
        metric = Metric(
            name=name,
            value=value,
            unit=unit,
            tags=tags or {},
            timestamp=time.time()
        )
        self.metrics.append(metric)

        # Keep last 1000 metrics
        if len(self.metrics) > 1000:
            self.metrics = self.metrics[-1000:]

    async def check_health(self) -> Dict:
        """Run all health checks."""
        checks = []

        # Check database
        checks.append(await self._check_database())

        # Check system resources
        checks.append(self._check_system_resources())

        # Check cache
        checks.append(await self._check_cache())

        # Store results
        for check in checks:
            self.health_checks[check.component] = check

        # Overall status
        statuses = [c.status for c in checks]
        if all(s == HealthStatus.HEALTHY for s in statuses):
            overall = HealthStatus.HEALTHY
        elif any(s == HealthStatus.UNHEALTHY for s in statuses):
            overall = HealthStatus.UNHEALTHY
        else:
            overall = HealthStatus.DEGRADED

        return {
            'status': overall.value,
            'uptime_seconds': time.time() - self.start_time,
            'checks': [
                {
                    'component': c.component,
                    'status': c.status.value,
                    'message': c.message,
                    'latency_ms': c.latency_ms
                }
                for c in checks
            ]
        }

    async def _check_database(self) -> HealthCheck:
        """Check database connectivity."""
        start = time.time()
        try:
            from database import get_database
            db = get_database()
            # Simple query
            db.execute("SELECT 1")
            latency = (time.time() - start) * 1000

            if latency > 1000:
                status = HealthStatus.DEGRADED
                message = f"Database slow: {latency:.0f}ms"
            else:
                status = HealthStatus.HEALTHY
                message = "Database responsive"

        except Exception as e:
            latency = (time.time() - start) * 1000
            status = HealthStatus.UNHEALTHY
            message = f"Database error: {str(e)}"

        return HealthCheck(
            component="database",
            status=status,
            message=message,
            latency_ms=latency,
            timestamp=time.time()
        )

    def _check_system_resources(self) -> HealthCheck:
        """Check system CPU and memory."""
        start = time.time()
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()

            if cpu_percent > 90 or memory.percent > 90:
                status = HealthStatus.UNHEALTHY
                message = f"High resource usage: CPU {cpu_percent}%, Memory {memory.percent}%"
            elif cpu_percent > 70 or memory.percent > 70:
                status = HealthStatus.DEGRADED
                message = f"Elevated resource usage: CPU {cpu_percent}%, Memory {memory.percent}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Resources normal: CPU {cpu_percent}%, Memory {memory.percent}%"

            latency = (time.time() - start) * 1000

        except Exception as e:
            latency = (time.time() - start) * 1000
            status = HealthStatus.DEGRADED
            message = f"Could not check resources: {str(e)}"

        return HealthCheck(
            component="system_resources",
            status=status,
            message=message,
            latency_ms=latency,
            timestamp=time.time()
        )

    async def _check_cache(self) -> HealthCheck:
        """Check cache system."""
        start = time.time()
        try:
            from caching import get_cache
            cache = get_cache()
            stats = cache.get_stats()

            latency = (time.time() - start) * 1000
            status = HealthStatus.HEALTHY
            message = f"Cache operational: {stats.get('total_reads', 0)} reads"

        except Exception as e:
            latency = (time.time() - start) * 1000
            status = HealthStatus.DEGRADED
            message = f"Cache check failed: {str(e)}"

        return HealthCheck(
            component="cache",
            status=status,
            message=message,
            latency_ms=latency,
            timestamp=time.time()
        )

    def get_metrics(self, name: str = None, limit: int = 100) -> List[Dict]:
        """Get recorded metrics."""
        metrics = self.metrics
        if name:
            metrics = [m for m in metrics if m.name == name]

        return [asdict(m) for m in metrics[-limit:]]

    def get_system_stats(self) -> Dict:
        """Get current system statistics."""
        return {
            'cpu_percent': psutil.cpu_percent(interval=0.1),
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'percent': psutil.disk_usage('/').percent
            },
            'uptime_seconds': time.time() - self.start_time
        }


# Global monitor instance
_global_monitor: Optional[Monitor] = None


def get_monitor() -> Monitor:
    """Get the global monitor."""
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = Monitor()
    return _global_monitor
