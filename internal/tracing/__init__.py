"""
TSM Layer - Distributed Tracing
Trace-id propagation and request tracking across services.
"""

import uuid
import time
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field
from pathlib import Path
from contextlib import contextmanager


@dataclass
class Span:
    """Trace span representing a unit of work."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    name: str
    start_time: float
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    tags: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict] = field(default_factory=list)
    status: str = "ok"  # ok, error

    def finish(self):
        """Finish the span."""
        self.end_time = time.time()
        self.duration_ms = (self.end_time - self.start_time) * 1000

    def add_tag(self, key: str, value: Any):
        """Add a tag to the span."""
        self.tags[key] = value

    def add_log(self, message: str, level: str = "info"):
        """Add a log entry to the span."""
        self.logs.append({
            'timestamp': time.time(),
            'level': level,
            'message': message
        })

    def set_error(self, error: Exception):
        """Mark span as error."""
        self.status = "error"
        self.add_tag("error", True)
        self.add_tag("error.type", type(error).__name__)
        self.add_tag("error.message", str(error))


@dataclass
class Trace:
    """Complete trace with all spans."""
    trace_id: str
    spans: List[Span]
    start_time: float
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    metadata: Dict = field(default_factory=dict)

    def finish(self):
        """Finish the trace."""
        self.end_time = time.time()
        self.duration_ms = (self.end_time - self.start_time) * 1000


class Tracer:
    """Distributed tracer for TSM requests."""

    def __init__(self, trace_file: str = "~/.tsm/traces.jsonl"):
        self.trace_file = Path(trace_file).expanduser()
        self.trace_file.parent.mkdir(parents=True, exist_ok=True)
        self.active_traces: Dict[str, Trace] = {}
        self.active_spans: Dict[str, Span] = {}

    def start_trace(self, trace_id: str = None, metadata: Dict = None) -> str:
        """Start a new trace."""
        if trace_id is None:
            trace_id = f"tsm_{uuid.uuid4().hex[:12]}"

        trace = Trace(
            trace_id=trace_id,
            spans=[],
            start_time=time.time(),
            metadata=metadata or {}
        )
        self.active_traces[trace_id] = trace
        return trace_id

    def start_span(self, trace_id: str, name: str, parent_span_id: str = None) -> str:
        """Start a new span within a trace."""
        span_id = uuid.uuid4().hex[:8]
        span = Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            name=name,
            start_time=time.time()
        )

        self.active_spans[span_id] = span

        if trace_id in self.active_traces:
            self.active_traces[trace_id].spans.append(span)

        return span_id

    def finish_span(self, span_id: str):
        """Finish a span."""
        if span_id in self.active_spans:
            span = self.active_spans[span_id]
            span.finish()
            del self.active_spans[span_id]

    def finish_trace(self, trace_id: str):
        """Finish a trace and save it."""
        if trace_id in self.active_traces:
            trace = self.active_traces[trace_id]
            trace.finish()

            # Save to file
            self._save_trace(trace)

            del self.active_traces[trace_id]

    def _save_trace(self, trace: Trace):
        """Save trace to disk."""
        with open(self.trace_file, 'a') as f:
            trace_data = {
                'trace_id': trace.trace_id,
                'start_time': trace.start_time,
                'end_time': trace.end_time,
                'duration_ms': trace.duration_ms,
                'metadata': trace.metadata,
                'spans': [asdict(span) for span in trace.spans]
            }
            f.write(json.dumps(trace_data) + '\n')

    def get_span(self, span_id: str) -> Optional[Span]:
        """Get active span."""
        return self.active_spans.get(span_id)

    def add_span_tag(self, span_id: str, key: str, value: Any):
        """Add tag to span."""
        span = self.get_span(span_id)
        if span:
            span.add_tag(key, value)

    def add_span_log(self, span_id: str, message: str, level: str = "info"):
        """Add log to span."""
        span = self.get_span(span_id)
        if span:
            span.add_log(message, level)

    @contextmanager
    def trace(self, name: str, trace_id: str = None, parent_span_id: str = None):
        """Context manager for tracing."""
        if trace_id is None:
            trace_id = self.start_trace()
            created_trace = True
        else:
            created_trace = False

        span_id = self.start_span(trace_id, name, parent_span_id)

        try:
            yield span_id
            self.finish_span(span_id)
        except Exception as e:
            span = self.get_span(span_id)
            if span:
                span.set_error(e)
            self.finish_span(span_id)
            raise
        finally:
            if created_trace:
                self.finish_trace(trace_id)

    def load_trace(self, trace_id: str) -> Optional[Trace]:
        """Load a trace from disk."""
        if self.trace_file.exists():
            with open(self.trace_file, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    if data['trace_id'] == trace_id:
                        spans = [Span(**span) for span in data['spans']]
                        return Trace(
                            trace_id=data['trace_id'],
                            spans=spans,
                            start_time=data['start_time'],
                            end_time=data.get('end_time'),
                            duration_ms=data.get('duration_ms'),
                            metadata=data.get('metadata', {})
                        )
        return None


# Global tracer
_global_tracer: Optional[Tracer] = None


def get_tracer() -> Tracer:
    """Get the global tracer."""
    global _global_tracer
    if _global_tracer is None:
        _global_tracer = Tracer()
    return _global_tracer
