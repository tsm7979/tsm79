"""
TSM Layer - Metrics Export
Export metrics to Prometheus, StatsD, InfluxDB, etc.
"""

from typing import Dict, List
from dataclasses import dataclass
import time


@dataclass
class MetricPoint:
    """Single metric data point."""
    name: str
    value: float
    tags: Dict[str, str]
    timestamp: float


class PrometheusExporter:
    """Export metrics in Prometheus format."""

    def __init__(self):
        self.metrics: List[MetricPoint] = []

    def record(self, name: str, value: float, tags: Dict = None):
        """Record a metric."""
        point = MetricPoint(
            name=name,
            value=value,
            tags=tags or {},
            timestamp=time.time()
        )
        self.metrics.append(point)

    def export(self) -> str:
        """Export in Prometheus format."""
        lines = []
        metric_groups: Dict[str, List[MetricPoint]] = {}

        # Group by metric name
        for metric in self.metrics:
            if metric.name not in metric_groups:
                metric_groups[metric.name] = []
            metric_groups[metric.name].append(metric)

        # Format for Prometheus
        for name, points in metric_groups.items():
            lines.append(f"# HELP {name} TSM Layer metric")
            lines.append(f"# TYPE {name} gauge")

            for point in points:
                tags_str = ",".join(f'{k}="{v}"' for k, v in point.tags.items())
                if tags_str:
                    lines.append(f"{name}{{{tags_str}}} {point.value}")
                else:
                    lines.append(f"{name} {point.value}")

        return "\n".join(lines)


class StatsDExporter:
    """Export metrics to StatsD."""

    def __init__(self, host: str = "localhost", port: int = 8125):
        self.host = host
        self.port = port

    def send_metric(self, name: str, value: float, metric_type: str = "g"):
        """Send metric to StatsD.

        metric_type:
        - g: gauge
        - c: counter
        - ms: timing
        """
        # In production, use actual UDP socket
        metric_str = f"{name}:{value}|{metric_type}"
        # socket.sendto(metric_str.encode(), (self.host, self.port))
        pass


class MetricsExporter:
    """Central metrics exporter."""

    def __init__(self):
        self.prometheus = PrometheusExporter()
        self.statsd = StatsDExporter()

    def record_request(self, model: str, latency_ms: float, cost: float,
                      success: bool, has_pii: bool):
        """Record request metrics."""
        tags = {
            'model': model,
            'status': 'success' if success else 'error',
            'has_pii': str(has_pii)
        }

        self.prometheus.record('tsm_requests_total', 1, tags)
        self.prometheus.record('tsm_request_latency_ms', latency_ms, tags)
        self.prometheus.record('tsm_request_cost', cost, tags)

        # StatsD
        self.statsd.send_metric('tsm.requests', 1, 'c')
        self.statsd.send_metric('tsm.latency', latency_ms, 'ms')

    def record_cache_hit(self, hit: bool):
        """Record cache hit/miss."""
        tags = {'result': 'hit' if hit else 'miss'}
        self.prometheus.record('tsm_cache_requests', 1, tags)
        self.statsd.send_metric(f'tsm.cache.{"hit" if hit else "miss"}', 1, 'c')

    def record_rate_limit(self, user_id: str, limited: bool):
        """Record rate limit check."""
        tags = {'user': user_id, 'limited': str(limited)}
        self.prometheus.record('tsm_ratelimit_checks', 1, tags)

    def get_prometheus_metrics(self) -> str:
        """Get metrics in Prometheus format."""
        return self.prometheus.export()


# Global exporter
_global_exporter: MetricsExporter = None


def get_metrics_exporter() -> MetricsExporter:
    """Get the global metrics exporter."""
    global _global_exporter
    if _global_exporter is None:
        _global_exporter = MetricsExporter()
    return _global_exporter
