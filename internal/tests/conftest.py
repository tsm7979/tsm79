"""
Pytest configuration and shared fixtures for TSM Layer test suite.
Comprehensive fixtures for testing all modules.
"""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch
import json
import time

# Test data
SAMPLE_PROMPTS = {
    "clean": "What is the capital of France?",
    "pii_ssn": "My SSN is 123-45-6789",
    "pii_email": "Contact me at john.doe@example.com",
    "pii_multiple": "John Smith, SSN 123-45-6789, email: john@example.com, phone: 555-1234",
    "code": "def factorial(n): return 1 if n == 0 else n * factorial(n-1)",
    "long": "This is a very long prompt " * 100,
}

SAMPLE_RESPONSES = {
    "simple": "The capital of France is Paris.",
    "detailed": "Paris is the capital and most populous city of France.",
    "code_response": "Here's an explanation of the factorial function...",
}

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def temp_dir():
    """Create temporary directory for tests."""
    tmpdir = tempfile.mkdtemp()
    yield Path(tmpdir)
    shutil.rmtree(tmpdir)

@pytest.fixture
def sample_user():
    """Sample user data."""
    return {
        "id": "user_123",
        "email": "test@example.com",
        "name": "Test User",
        "organization_id": "org_456",
        "role": "developer"
    }

@pytest.fixture
def sample_organization():
    """Sample organization data."""
    return {
        "id": "org_456",
        "name": "Test Organization",
        "tier": "pro",
        "created_at": time.time()
    }

@pytest.fixture
def sample_api_key():
    """Sample API key."""
    return "tsm_test_api_key_123456789"

@pytest.fixture
def mock_llm_response():
    """Mock LLM API response."""
    return Mock(
        choices=[Mock(message=Mock(content="This is a test response."))],
        usage=Mock(total_tokens=50)
    )

@pytest.fixture
async def mock_async_llm():
    """Mock async LLM call."""
    async def _call(prompt, **kwargs):
        await asyncio.sleep(0.01)  # Simulate API delay
        return "Mock LLM response"
    return _call

@pytest.fixture
def clean_database(temp_dir):
    """Clean test database."""
    from database import Database
    db_path = temp_dir / "test.db"
    db = Database(str(db_path))
    yield db
    # Cleanup handled by temp_dir fixture

@pytest.fixture
def sample_request_data():
    """Sample request for testing."""
    return {
        "prompt": SAMPLE_PROMPTS["clean"],
        "model": "gpt-4",
        "max_tokens": 1000,
        "temperature": 0.7
    }

@pytest.fixture
def sample_pii_request():
    """Sample request with PII."""
    return {
        "prompt": SAMPLE_PROMPTS["pii_multiple"],
        "model": "gpt-4"
    }

@pytest.fixture
def mock_cache():
    """Mock cache system."""
    cache_data = {}
    
    class MockCache:
        def get(self, key):
            return cache_data.get(key)
        
        def set(self, key, value, ttl=3600):
            cache_data[key] = value
            return True
        
        def delete(self, key):
            if key in cache_data:
                del cache_data[key]
                return True
            return False
        
        def clear(self):
            cache_data.clear()
            return True
    
    return MockCache()

@pytest.fixture
def mock_queue():
    """Mock task queue."""
    tasks = []
    
    class MockQueue:
        def enqueue(self, task_name, payload, priority=0):
            task_id = f"task_{len(tasks)}"
            tasks.append({
                "id": task_id,
                "name": task_name,
                "payload": payload,
                "priority": priority
            })
            return task_id
        
        def get_task(self, task_id):
            for task in tasks:
                if task["id"] == task_id:
                    return task
            return None
    
    return MockQueue()

@pytest.fixture
def mock_tracer():
    """Mock distributed tracer."""
    traces = {}
    
    class MockTracer:
        def start_trace(self, trace_id=None):
            if trace_id is None:
                trace_id = f"trace_{len(traces)}"
            traces[trace_id] = {"spans": []}
            return trace_id
        
        def start_span(self, trace_id, name, parent_span_id=None):
            span_id = f"span_{len(traces[trace_id]['spans'])}"
            traces[trace_id]["spans"].append({
                "id": span_id,
                "name": name,
                "parent": parent_span_id
            })
            return span_id
        
        def finish_span(self, span_id):
            pass
        
        def finish_trace(self, trace_id):
            pass
    
    return MockTracer()

@pytest.fixture
def mock_metrics():
    """Mock metrics collector."""
    metrics = []
    
    class MockMetrics:
        def record(self, name, value, tags=None):
            metrics.append({
                "name": name,
                "value": value,
                "tags": tags or {},
                "timestamp": time.time()
            })
        
        def get_metrics(self):
            return metrics
    
    return MockMetrics()

@pytest.fixture
def sample_policy():
    """Sample security policy."""
    return {
        "id": "policy_1",
        "name": "Default Security Policy",
        "rules": [
            {"type": "block_pii", "enabled": True},
            {"type": "require_auth", "enabled": True},
            {"type": "rate_limit", "limit": 100}
        ]
    }

@pytest.fixture
def mock_rbac():
    """Mock RBAC system."""
    user_roles = {}
    
    class MockRBAC:
        def assign_role(self, user_id, role):
            if user_id not in user_roles:
                user_roles[user_id] = set()
            user_roles[user_id].add(role)
            return True
        
        def has_permission(self, user_id, permission):
            # Simplified permission check
            roles = user_roles.get(user_id, set())
            if "admin" in roles:
                return True
            return permission in ["basic_access"]
    
    return MockRBAC()

@pytest.fixture
async def mock_webhook_server():
    """Mock webhook endpoint."""
    received_events = []
    
    async def handler(event):
        received_events.append(event)
        return {"status": "ok"}
    
    handler.events = received_events
    return handler

@pytest.fixture
def performance_timer():
    """Performance timing utility."""
    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None
        
        def start(self):
            self.start_time = time.perf_counter()
        
        def stop(self):
            self.end_time = time.perf_counter()
            return self.elapsed()
        
        def elapsed(self):
            if self.start_time and self.end_time:
                return (self.end_time - self.start_time) * 1000  # ms
            return None
    
    return Timer()

# Pytest markers
def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line("markers", "slow: marks tests as slow")
    config.addinivalue_line("markers", "integration: integration tests")
    config.addinivalue_line("markers", "unit: unit tests")
    config.addinivalue_line("markers", "e2e: end-to-end tests")
    config.addinivalue_line("markers", "performance: performance tests")

