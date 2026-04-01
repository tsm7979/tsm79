# TSM Layer v2.0 - Complete Restructure Plan
## Professional-Grade Production Code

**Date**: April 1, 2026
**Objective**: Rebuild TSM Layer to exceed the quality standards of the reference codebase
**Reference**: Claude Code v2.1.88 quality analysis

---

## Problems with Current Implementation

### 1. **Code Quality Issues**
- ❌ No proper error handling (bare except, no error codes)
- ❌ No type validation (missing Pydantic models)
- ❌ Placeholder implementations everywhere
- ❌ No structured logging
- ❌ Tests only check imports, not functionality
- ❌ No documentation
- ❌ Flat file structure (everything in root)

### 2. **Architecture Issues**
- ❌ No clear separation of concerns
- ❌ Mixed business logic with infrastructure
- ❌ No dependency injection
- ❌ Tight coupling between layers
- ❌ No interfaces/protocols

### 3. **Production Readiness Issues**
- ❌ No configuration management
- ❌ No graceful degradation
- ❌ No circuit breakers (stub only)
- ❌ No proper caching (simple dict)
- ❌ No metrics/monitoring
- ❌ No security best practices

---

## New Professional Structure

```
tsm/
├── src/                          # All source code
│   ├── core/                     # Core business logic
│   │   ├── firewall/            # PII detection & sanitization
│   │   │   ├── __init__.py
│   │   │   ├── detector.py      # Pattern detection
│   │   │   ├── sanitizer.py     # Data sanitization
│   │   │   ├── patterns.py      # Regex patterns
│   │   │   └── types.py         # Pydantic models
│   │   ├── router/              # Intelligent routing
│   │   │   ├── __init__.py
│   │   │   ├── orchestrator.py  # Routing logic
│   │   │   ├── strategy.py      # Routing strategies
│   │   │   └── types.py         # Pydantic models
│   │   ├── policy/              # Policy enforcement
│   │   │   ├── __init__.py
│   │   │   ├── engine.py        # Policy evaluation
│   │   │   ├── rules.py         # Rule definitions
│   │   │   └── types.py
│   │   └── execution/           # Action execution
│   │       ├── __init__.py
│   │       ├── executor.py      # Execution engine
│   │       ├── actions.py       # Action definitions
│   │       └── types.py
│   │
│   ├── services/                 # Service layer
│   │   ├── gateway/             # Request gateway
│   │   │   ├── __init__.py
│   │   │   ├── pipeline.py      # Request pipeline
│   │   │   └── middleware.py    # Middleware chain
│   │   ├── models/              # LLM model providers
│   │   │   ├── __init__.py
│   │   │   ├── base.py          # Base provider
│   │   │   ├── openai.py        # OpenAI provider
│   │   │   ├── anthropic.py     # Anthropic provider
│   │   │   └── local.py         # Local model provider
│   │   ├── cache/               # Caching service
│   │   │   ├── __init__.py
│   │   │   ├── lru.py           # LRU cache with limits
│   │   │   └── types.py
│   │   └── database/            # Database service
│   │       ├── __init__.py
│   │       ├── models.py        # SQLAlchemy models
│   │       └── repository.py    # Data access layer
│   │
│   ├── infrastructure/           # Infrastructure layer
│   │   ├── logging/             # Structured logging
│   │   │   ├── __init__.py
│   │   │   ├── logger.py        # Logger setup
│   │   │   └── formatters.py    # Log formatters
│   │   ├── monitoring/          # Metrics & monitoring
│   │   │   ├── __init__.py
│   │   │   ├── metrics.py       # Metrics collection
│   │   │   └── health.py        # Health checks
│   │   ├── config/              # Configuration
│   │   │   ├── __init__.py
│   │   │   ├── settings.py      # Pydantic settings
│   │   │   └── validation.py    # Config validation
│   │   └── errors/              # Error handling
│   │       ├── __init__.py
│   │       ├── exceptions.py    # Custom exceptions
│   │       ├── codes.py         # Error codes
│   │       └── handlers.py      # Error handlers
│   │
│   ├── utils/                    # Utility functions
│   │   ├── validation/          # Validation utils
│   │   ├── security/            # Security utils
│   │   ├── text/                # Text processing
│   │   └── patterns/            # Regex patterns
│   │
│   ├── cli/                      # CLI application
│   │   ├── __init__.py
│   │   ├── app.py               # Main CLI app
│   │   ├── commands/            # CLI commands
│   │   │   ├── run.py
│   │   │   ├── audit.py
│   │   │   └── config.py
│   │   └── ui/                  # UI components
│   │       ├── output.py        # Output formatting
│   │       └── colors.py        # Color schemes
│   │
│   └── types/                    # Shared type definitions
│       ├── __init__.py
│       ├── common.py            # Common types
│       ├── messages.py          # Message types
│       └── results.py           # Result types
│
├── tests/                        # All tests
│   ├── unit/                    # Unit tests
│   │   ├── core/
│   │   ├── services/
│   │   └── utils/
│   ├── integration/             # Integration tests
│   │   ├── test_pipeline.py
│   │   ├── test_firewall.py
│   │   └── test_routing.py
│   ├── e2e/                     # End-to-end tests
│   │   └── test_cli.py
│   └── fixtures/                # Test fixtures
│       └── conftest.py
│
├── docs/                         # Documentation
│   ├── architecture.md          # Architecture docs
│   ├── api/                     # API documentation
│   ├── guides/                  # User guides
│   └── examples/                # Code examples
│
├── config/                       # Configuration files
│   ├── default.yaml             # Default config
│   ├── production.yaml          # Production config
│   └── development.yaml         # Development config
│
├── scripts/                      # Utility scripts
│   ├── setup.py                 # Setup script
│   └── test_all.sh              # Test runner
│
├── pyproject.toml               # Project configuration
├── setup.py                     # Package setup
├── requirements.txt             # Dependencies
├── requirements-dev.txt         # Dev dependencies
├── pytest.ini                   # Pytest configuration
├── .gitignore                   # Git ignore
└── README.md                    # Project README
```

---

## Implementation Phases

### Phase 1: Foundation (Core Infrastructure)
**Deliverables**:
1. ✅ Proper project structure
2. ✅ Type system with Pydantic models
3. ✅ Error handling infrastructure
4. ✅ Logging system
5. ✅ Configuration management

**Quality Standards**:
- All functions have type hints
- All inputs validated with Pydantic
- All errors have error codes
- All operations logged
- Zero placeholders

### Phase 2: Core Business Logic
**Deliverables**:
1. ✅ Firewall with proper PII detection
2. ✅ Router with intelligent strategies
3. ✅ Policy engine with rule evaluation
4. ✅ Execution engine with action handlers

**Quality Standards**:
- 100% test coverage on critical paths
- All edge cases handled
- Graceful degradation everywhere
- Performance benchmarks met

### Phase 3: Service Layer
**Deliverables**:
1. ✅ Gateway pipeline with middleware
2. ✅ Model providers with retries
3. ✅ LRU cache with memory limits
4. ✅ Database with proper ORM

**Quality Standards**:
- Circuit breakers implemented
- Timeouts on all I/O
- Connection pooling
- Transaction support

### Phase 4: CLI & Testing
**Deliverables**:
1. ✅ Production-ready CLI
2. ✅ Comprehensive test suite (90%+ coverage)
3. ✅ Integration tests
4. ✅ E2E tests

**Quality Standards**:
- All tests passing
- Performance tests included
- Load tests for production scenarios
- Security tests for PII detection

### Phase 5: Documentation & Polish
**Deliverables**:
1. ✅ Architecture documentation
2. ✅ API documentation
3. ✅ User guides
4. ✅ Code examples

**Quality Standards**:
- Every public API documented
- Examples for every feature
- Troubleshooting guides
- Migration guides

---

## Key Improvements from Reference Analysis

### 1. Type Safety
**Before**: No validation, bare dictionaries
**After**: Pydantic models everywhere, branded types for IDs

```python
# Before
def process_request(data: dict) -> dict:
    return {"result": "ok"}

# After
class ProcessRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10000)
    context: Dict[str, Any] = Field(default_factory=dict)
    options: RequestOptions = Field(default_factory=RequestOptions)

class ProcessResponse(BaseModel):
    result: str
    trace_id: TraceID
    metadata: ResponseMetadata

@validate_call
def process_request(req: ProcessRequest) -> ProcessResponse:
    ...
```

### 2. Error Handling
**Before**: Bare except, no error codes
**After**: Classified errors, user-friendly messages

```python
# Before
try:
    result = call_api()
except:
    return "error"

# After
class ErrorCode(str, Enum):
    API_TIMEOUT = "api_timeout"
    RATE_LIMIT = "rate_limit"
    NETWORK_ERROR = "network_error"
    # ... 20+ more

try:
    result = await call_api_with_retry()
except APITimeoutError as e:
    raise TSMError(
        code=ErrorCode.API_TIMEOUT,
        message="The AI service took too long to respond",
        suggestion="Try again in a few seconds",
        details={"timeout": e.timeout, "endpoint": e.endpoint}
    ) from e
```

### 3. Validation Layers
**Before**: No validation
**After**: Multi-layer validation (schema → business → security)

```python
# Schema validation
class SanitizeRequest(BaseModel):
    text: str
    patterns: List[PIIPattern]

    @validator('text')
    def text_not_empty(cls, v):
        if not v.strip():
            raise ValueError('Text cannot be empty')
        return v

# Business validation
def validate_business_rules(req: SanitizeRequest) -> None:
    if len(req.text) > 1_000_000:
        raise BusinessError("Text too long for processing")

# Security validation
def validate_security(req: SanitizeRequest) -> None:
    if contains_potential_injection(req.text):
        raise SecurityError("Potential injection detected")
```

### 4. Performance
**Before**: Simple dict cache, no limits
**After**: LRU cache with memory limits

```python
from functools import lru_cache
from cachetools import LRUCache, TTLCache

class SmartCache:
    def __init__(self, max_size_mb: int = 100):
        # LRU for LLM responses (size-aware)
        self._llm_cache = LRUCache(maxsize=1000)
        # TTL for temporary data
        self._temp_cache = TTLCache(maxsize=500, ttl=300)
        # Memory monitoring
        self._max_bytes = max_size_mb * 1024 * 1024

    def get(self, key: str) -> Optional[Any]:
        # Check memory usage before returning
        if self._get_cache_size() > self._max_bytes:
            self._evict_oldest()
        return self._llm_cache.get(key)
```

### 5. Logging
**Before**: print() statements
**After**: Structured logging with context

```python
import structlog

logger = structlog.get_logger(__name__)

# Contextual logging
logger.info(
    "pii_detected",
    trace_id=trace_id,
    pii_types=["ssn", "email"],
    sanitized_count=2,
    routing_decision="local"
)

# Error logging with full context
logger.error(
    "api_call_failed",
    error_code="api_timeout",
    provider="openai",
    model="gpt-4",
    retry_attempt=3,
    exc_info=True
)
```

---

## Success Criteria

### Code Quality Metrics
- ✅ **100%** type coverage (all functions have type hints)
- ✅ **90%+** test coverage (line coverage)
- ✅ **100%** critical path coverage
- ✅ **Zero** TODOs or FIXMEs in production code
- ✅ **Zero** bare except blocks
- ✅ **Zero** print() debugging
- ✅ **All** public APIs documented

### Functional Requirements
- ✅ **100%** PII detection accuracy (all test cases pass)
- ✅ **100%** stability (10+ consecutive runs without errors)
- ✅ **Sub-second** response times for CLI
- ✅ **Graceful degradation** when services unavailable
- ✅ **Zero crashes** on invalid input

### Production Readiness
- ✅ Proper error codes for monitoring
- ✅ Structured logging for analytics
- ✅ Health check endpoints
- ✅ Metrics exporters (Prometheus format)
- ✅ Configuration via environment variables
- ✅ Security best practices (secrets detection, input sanitization)

---

## Next Steps

1. **Create new project structure** (this plan)
2. **Implement foundation** (types, errors, logging, config)
3. **Implement core** (firewall, router, policy, execution)
4. **Implement services** (gateway, models, cache, database)
5. **Build CLI** (commands, UI, output)
6. **Write tests** (unit, integration, e2e)
7. **Add documentation** (architecture, API, guides)
8. **Production validation** (load tests, security audit)

---

## Estimated Timeline

- **Phase 1 (Foundation)**: 2-3 hours
- **Phase 2 (Core)**: 3-4 hours
- **Phase 3 (Services)**: 2-3 hours
- **Phase 4 (CLI & Testing)**: 2-3 hours
- **Phase 5 (Documentation)**: 1-2 hours

**Total**: 10-15 hours for production-ready code

---

**This is what 200% ready means**: Code that's better than the reference, not just "working".**
